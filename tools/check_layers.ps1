param(
    [string]$RepoRoot = ".",
    [switch]$FailOnLegacyInclude,
    [switch]$FailOnFilesystemCompatInActivePath,
    [switch]$SkipLayerDirectionCheck
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
    if ($n -match '^src/(foundation|infrastructure|domain|application|interface|bootstrap)/') {
        return $Matches[1]
    }
    return ""
}

function Is-FilesystemActivePath {
    param([string]$RelativePath)
    $n = Normalize-PathForCheck $RelativePath
    if ($n -eq "main.cpp") {
        return $true
    }
    return $n -match '^src/(application|interface|bootstrap)/'
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
    infrastructure = @("foundation", "infrastructure", "domain", "application")
    domain         = @("foundation", "domain")
    application    = @("foundation", "domain", "application")
    interface      = @("foundation", "domain", "application", "interface")
    bootstrap      = @("foundation", "infrastructure", "domain", "application", "interface", "bootstrap")
}

$targetFiles = Get-ChildItem -Recurse -File src -ErrorAction SilentlyContinue |
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
$filesystemCompatForbiddenIncludes = @(
    "domain/filesystem/FileSystemManager.hpp",
    "domain/filesystem/deprecated/FileSystemManager.hpp",
    "domain/filesystem/deprecated/FileSystemManagerLegacy.hpp",
    "domain/filesystem/dep/FileSystemManager.dep.hpp",
    "application/filesystem/FileSystemWorkflows.hpp",
    "application/filesystem/dep/FileSystemWorkflows.dep.hpp"
)

foreach ($entry in $layeredFiles) {
    $isDeprecatedLayerFile = $entry.Relative -match '\.dep\.(h|hpp|hh|hxx|c|cc|cpp|cxx)$|\.h\.dep$|\.hpp\.dep$|\.c\.dep$|\.cc\.dep$|\.cpp\.dep$|\.cxx\.dep$'
    $includes = Get-IncludeEntries $entry.FilePath
    foreach ($inc in $includes) {
        $includeNorm = Normalize-PathForCheck $inc.IncludePath
        $toLayer = Get-LayerFromIncludePath $inc.IncludePath
        $isInterfaceControllerBridge = ($entry.Layer -eq "interface" `
                -and $toLayer -eq "infrastructure" `
                -and $includeNorm -eq "infrastructure/controller/ClientControlTokenAdapter.hpp")
        if (-not [string]::IsNullOrEmpty($toLayer)) {
            if ((-not $SkipLayerDirectionCheck) -and (-not $isDeprecatedLayerFile) -and (-not $isInterfaceControllerBridge)) {
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
            }
            if (-not $FailOnFilesystemCompatInActivePath) {
                continue
            }
        }
        if ($FailOnFilesystemCompatInActivePath -and (Is-FilesystemActivePath $entry.Relative)) {
            $isBridgeException = ($entry.Relative -eq "src/application/filesystem/dep/FileSystemWorkflows.hpp" `
                    -and $includeNorm -eq "application/filesystem/dep/FileSystemWorkflows.dep.hpp")
            if (($filesystemCompatForbiddenIncludes -contains $includeNorm) -and -not $isBridgeException) {
                $violations += [pscustomobject]@{
                    File = $entry.Relative
                    Line = $inc.Line
                    FromLayer = $entry.Layer
                    IncludePath = $inc.IncludePath
                    ToLayer = "filesystem-compat"
                    Reason = "filesystem compatibility include not allowed in active path"
                }
            }
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

    if ($FailOnFilesystemCompatInActivePath -and (Is-FilesystemActivePath $entry.Relative)) {
        $lines = Get-Content $entry.FilePath
        for ($idx = 0; $idx -lt $lines.Count; $idx++) {
            $lineText = $lines[$idx]
            if ($lineText -match '\bAMDomain::filesystem::AMFileSystem\b|\bAMFileSystem::Instance\s*\(') {
                $violations += [pscustomobject]@{
                    File = $entry.Relative
                    Line = $idx + 1
                    FromLayer = $entry.Layer
                    IncludePath = "AMFileSystem"
                    ToLayer = "filesystem-compat"
                    Reason = "legacy filesystem type usage not allowed in active path"
                }
            }
        }
    }
}

Write-Host "Layer checker root: $repoFull"
Write-Host ("Layered files scanned: {0}" -f $layeredFiles.Count)
Write-Host ("Layer direction check skipped: {0}" -f $SkipLayerDirectionCheck.IsPresent)
Write-Host ("Filesystem active-path compatibility guard enabled: {0}" -f $FailOnFilesystemCompatInActivePath.IsPresent)

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
