param(
    [string]$RepoRoot = ".",
    [switch]$FailOnLegacyInclude
)

$ErrorActionPreference = "Stop"

function Normalize-PathForCheck {
    param([string]$Path)
    if (-not $Path) {
        return ""
    }
    return $Path.Replace('\', '/')
}

function Get-LayerFromFilePath {
    param([string]$Path)
    $n = Normalize-PathForCheck $Path
    if ($n -match '^(include|src)/(foundation|infrastructure|domain|application|interface|bootstrap)/') {
        return $Matches[2]
    }
    return ""
}

function Get-RelativePathCompat {
    param(
        [string]$BasePath,
        [string]$TargetPath
    )
    try {
        return [System.IO.Path]::GetRelativePath($BasePath, $TargetPath)
    }
    catch {
        $base = [System.Uri]((Resolve-Path $BasePath).Path.TrimEnd('\') + "\")
        $target = [System.Uri]((Resolve-Path $TargetPath).Path)
        $relativeUri = $base.MakeRelativeUri($target)
        return [System.Uri]::UnescapeDataString($relativeUri.ToString()).Replace('/', '\')
    }
}

function Get-LayerFromIncludePath {
    param([string]$IncludePath)
    $n = Normalize-PathForCheck $IncludePath
    if ($n -match '^(foundation|infrastructure|domain|application|interface|bootstrap)/') {
        return $Matches[1]
    }
    if ($n -match '^(?:\./|\.\./)+(foundation|infrastructure|domain|application|interface|bootstrap)/') {
        return $Matches[1]
    }
    if ($n -match '^include/(foundation|infrastructure|domain|application|interface|bootstrap)/') {
        return $Matches[1]
    }
    return ""
}

function Is-LegacyInclude {
    param([string]$IncludePath)
    $n = Normalize-PathForCheck $IncludePath
    return $n -match '^(AMBase|AMManager|AMCLI|AMClient)/'
}

function Get-IncludeEntries {
    param([string]$FilePath)
    $entries = @()
    $lines = Get-Content $FilePath
    for ($i = 0; $i -lt $lines.Count; $i++) {
        $line = $lines[$i]
        if ($line -match '^\s*#\s*include\s*"([^"]+)"') {
            $entries += [pscustomobject]@{
                Line = $i + 1
                IncludePath = $Matches[1]
            }
        }
    }
    return $entries
}

$repoFull = (Resolve-Path $RepoRoot).Path
Set-Location $repoFull

$allowedDeps = @{
    foundation     = @("foundation")
    infrastructure = @("foundation", "infrastructure")
    domain         = @("foundation", "domain")
    application    = @("foundation", "domain", "application")
    interface      = @("foundation", "domain", "application", "interface")
    bootstrap      = @("foundation", "infrastructure", "domain", "application", "interface", "bootstrap")
}

$targetFiles = Get-ChildItem -Recurse -File include, src -ErrorAction SilentlyContinue |
    Where-Object { $_.Extension -in @(".h", ".hpp", ".hh", ".hxx", ".c", ".cc", ".cpp", ".cxx") }

$layeredFiles = @()
foreach ($file in $targetFiles) {
    $relative = Normalize-PathForCheck (Get-RelativePathCompat -BasePath $repoFull -TargetPath $file.FullName)
    $layer = Get-LayerFromFilePath $relative
    if (-not [string]::IsNullOrEmpty($layer)) {
        $layeredFiles += [pscustomobject]@{
            FilePath = $file.FullName
            Relative = $relative
            Layer = $layer
        }
    }
}

$violations = @()
$legacyWarnings = @()

foreach ($entry in $layeredFiles) {
    $includes = Get-IncludeEntries $entry.FilePath
    foreach ($inc in $includes) {
        $toLayer = Get-LayerFromIncludePath $inc.IncludePath
        if (-not [string]::IsNullOrEmpty($toLayer)) {
            $allowed = $allowedDeps[$entry.Layer]
            if ($allowed -notcontains $toLayer) {
                $violations += [pscustomobject]@{
                    File = $entry.Relative
                    Line = $inc.Line
                    FromLayer = $entry.Layer
                    IncludePath = $inc.IncludePath
                    ToLayer = $toLayer
                    Reason = "forbidden dependency direction"
                }
            }
            continue
        }

        if (Is-LegacyInclude $inc.IncludePath) {
            $legacyWarnings += [pscustomobject]@{
                File = $entry.Relative
                Line = $inc.Line
                FromLayer = $entry.Layer
                IncludePath = $inc.IncludePath
            }
            if ($FailOnLegacyInclude) {
                $violations += [pscustomobject]@{
                    File = $entry.Relative
                    Line = $inc.Line
                    FromLayer = $entry.Layer
                    IncludePath = $inc.IncludePath
                    ToLayer = "legacy"
                    Reason = "legacy include not allowed in strict mode"
                }
            }
        }
    }
}

Write-Host "Layer checker root: $repoFull"
Write-Host ("Layered files scanned: {0}" -f $layeredFiles.Count)

if ($legacyWarnings.Count -gt 0) {
    Write-Host ("Legacy include warnings: {0}" -f $legacyWarnings.Count) -ForegroundColor Yellow
    foreach ($w in $legacyWarnings | Sort-Object File, Line) {
        Write-Host ("  WARN {0}:{1} [{2}] -> {3}" -f $w.File, $w.Line, $w.FromLayer, $w.IncludePath) -ForegroundColor Yellow
    }
}

if ($violations.Count -gt 0) {
    Write-Host ("Layer violations: {0}" -f $violations.Count) -ForegroundColor Red
    foreach ($v in $violations | Sort-Object File, Line) {
        Write-Host ("  ERROR {0}:{1} [{2}] include '{3}' -> {4} ({5})" -f $v.File, $v.Line, $v.FromLayer, $v.IncludePath, $v.ToLayer, $v.Reason) -ForegroundColor Red
    }
    exit 1
}

Write-Host "Layer check passed." -ForegroundColor Green
exit 0
