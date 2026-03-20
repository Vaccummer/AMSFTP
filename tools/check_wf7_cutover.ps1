param(
    [string]$RepoRoot = ".",
    [switch]$IncludeSingletonCompat,
    [switch]$IncludeManagerCompat,
    [switch]$IncludeFilesystemRefactorGuard
)

$ErrorActionPreference = "Stop"

$repoFull = (Resolve-Path $RepoRoot).Path
Set-Location $repoFull

$searchScopes = @("main.cpp", "src", "include")
$codeGlobs = @(
    "-g", "*.h",
    "-g", "*.hpp",
    "-g", "*.hh",
    "-g", "*.hxx",
    "-g", "*.c",
    "-g", "*.cc",
    "-g", "*.cpp",
    "-g", "*.cxx"
)

# WF-7 cutover rules:
# 1) legacy include prefixes AMBase, AMCLI, AMClient are always forbidden.
# 2) AMManager/Prompt.hpp is forbidden (migrated to interface/Prompt.hpp).
# 3) singleton compatibility wrappers are optional strict checks:
#    AMManager/{Config,Logger,SignalMonitor}.hpp
# 4) full AMManager compatibility removal can be enabled explicitly:
#    -IncludeManagerCompat (forbids AMManager/*).
# 5) filesystem active-path refactor guard can be enabled explicitly:
#    -IncludeFilesystemRefactorGuard.
$prefixRules = @(
    "AMBase",
    "AMCLI",
    "AMClient"
)
if ($IncludeManagerCompat) {
    $prefixRules += "AMManager"
}

$headerRules = @(
    "AMManager/Prompt.hpp"
)
if ($IncludeSingletonCompat -and -not $IncludeManagerCompat) {
    $headerRules += @(
        "AMManager/Config.hpp",
        "AMManager/Logger.hpp",
        "AMManager/SignalMonitor.hpp"
    )
}
$headerRules = $headerRules | Sort-Object -Unique

$violations = @()
foreach ($prefix in $prefixRules) {
    $pattern = '#\s*include\s*[\"<]' + [regex]::Escape($prefix) + '[/\\][^\">]+[\">]'
    $matches = rg -n $pattern @codeGlobs @searchScopes
    foreach ($line in $matches) {
        $violations += [pscustomobject]@{
            Rule  = "$prefix/*"
            Match = $line
        }
    }
}

foreach ($header in $headerRules) {
    $pattern = '#\s*include\s*[\"<]' + [regex]::Escape($header) + '[\">]'
    $matches = rg -n $pattern @codeGlobs @searchScopes
    foreach ($line in $matches) {
        $violations += [pscustomobject]@{
            Rule  = $header
            Match = $line
        }
    }
}

Write-Host "WF-7 cutover check root: $repoFull"
Write-Host ("Prefix rules: {0}" -f $prefixRules.Count)
Write-Host ("Header rules: {0}" -f $headerRules.Count)
Write-Host ("Total enforced rules: {0}" -f ($prefixRules.Count + $headerRules.Count))
Write-Host ("Filesystem refactor guard enabled: {0}" -f ($IncludeFilesystemRefactorGuard.IsPresent))

$filesystemGuardFailed = $false
if ($IncludeFilesystemRefactorGuard) {
    $guardScript = Join-Path $PSScriptRoot "check_filesystem_refactor_guards.ps1"
    if (-not (Test-Path $guardScript)) {
        Write-Host ("WF-7 filesystem guard script missing: {0}" -f $guardScript) -ForegroundColor Red
        $filesystemGuardFailed = $true
    }
    else {
        & $guardScript -RepoRoot $repoFull
        if ($LASTEXITCODE -ne 0) {
            $filesystemGuardFailed = $true
        }
    }
}

if ($violations.Count -gt 0 -or $filesystemGuardFailed) {
    Write-Host ("WF-7 cutover violations: {0}" -f $violations.Count) -ForegroundColor Red
    foreach ($v in $violations | Sort-Object Rule, Match) {
        Write-Host ("  ERROR {0} -> {1}" -f $v.Rule, $v.Match) -ForegroundColor Red
    }
    if ($filesystemGuardFailed) {
        Write-Host "  ERROR filesystem refactor guard failed" -ForegroundColor Red
    }
    exit 1
}

Write-Host "WF-7 cutover check passed." -ForegroundColor Green
exit 0
