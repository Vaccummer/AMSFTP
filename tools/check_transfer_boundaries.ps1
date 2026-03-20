param(
    [string]$RepoRoot = "."
)

$ErrorActionPreference = "Stop"

function Normalize-PathForCheck {
    param([string]$Path)
    if (-not $Path) {
        return ""
    }
    return $Path.Replace('\', '/')
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

$repoFull = (Resolve-Path $RepoRoot).Path
Set-Location $repoFull

$targetFiles = Get-ChildItem -Recurse -File include/application/transfer, src/application/transfer -ErrorAction SilentlyContinue |
    Where-Object { $_.Extension -in @(".h", ".hpp", ".c", ".cc", ".cpp", ".cxx") }

$forbiddenRules = @(
    @{ Name = "Prompt manager coupling"; Pattern = '\bAMPromptManager\b' },
    @{ Name = "Interactive prompt callback name"; Pattern = '\bprompt_yes_no\b' },
    @{ Name = "Interactive print callback name"; Pattern = '\bprint_line\b|\bprint_error\b' },
    @{ Name = "Presentation bridge type"; Pattern = '\bTransferPresentationPort\b' },
    @{ Name = "Hidden global interrupt provider"; Pattern = 'TaskControlToken::Instance\s*\(' },
    @{ Name = "Legacy interrupt resolver helper"; Pattern = '\bResolveInterruptToken_\b' }
)

$violations = @()
foreach ($file in $targetFiles) {
    $relative = Normalize-PathForCheck (Get-RelativePathCompat -BasePath $repoFull -TargetPath $file.FullName)
    $lines = Get-Content $file.FullName
    for ($i = 0; $i -lt $lines.Count; $i++) {
        $line = $lines[$i]
        foreach ($rule in $forbiddenRules) {
            if ($line -match $rule.Pattern) {
                $violations += [pscustomobject]@{
                    File = $relative
                    Line = $i + 1
                    Rule = $rule.Name
                    Content = $line.Trim()
                }
            }
        }
    }
}

Write-Host "Transfer boundary checker root: $repoFull"
Write-Host ("Transfer app-core files scanned: {0}" -f $targetFiles.Count)

if ($violations.Count -gt 0) {
    Write-Host ("Transfer boundary violations: {0}" -f $violations.Count) -ForegroundColor Red
    foreach ($v in $violations | Sort-Object File, Line) {
        Write-Host ("  ERROR {0}:{1} {2} -> {3}" -f $v.File, $v.Line, $v.Rule, $v.Content) -ForegroundColor Red
    }
    exit 1
}

Write-Host "Transfer boundary check passed." -ForegroundColor Green
exit 0
