param(
    [string]$RepoRoot = ".",
    [switch]$IncludeSingletonCompat
)

$ErrorActionPreference = "Stop"

function Normalize-HeaderPath {
    param([string]$Path)
    return (($Path -replace '^include[\\/]', '') -replace '\\', '/')
}

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

# WF-7 cutover set:
# 1) all AMBase headers are bridged and should no longer be directly included.
# 2) all AMCLI headers are bridged and should no longer be directly included.
# 3) all AMClient headers are bridged and should no longer be directly included.
# 4) AMManager/Prompt.hpp is bridged and should no longer be directly included.
# 5) singleton compatibility wrappers are optional strict checks:
#    AMManager/{Config,Logger,SignalMonitor}.hpp
$targetHeaders = @()
if (Test-Path "include/AMBase") {
    $targetHeaders += Get-ChildItem -File -Recurse "include/AMBase" |
        ForEach-Object {
            Normalize-HeaderPath $_.FullName.Substring($repoFull.Length + 1)
        }
}
$targetHeaders += @(
    "AMManager/Prompt.hpp"
)
if (Test-Path "include/AMCLI") {
    $targetHeaders += Get-ChildItem -File -Recurse "include/AMCLI" |
        ForEach-Object {
            Normalize-HeaderPath $_.FullName.Substring($repoFull.Length + 1)
        }
}
if (Test-Path "include/AMClient") {
    $targetHeaders += Get-ChildItem -File -Recurse "include/AMClient" |
        ForEach-Object {
            Normalize-HeaderPath $_.FullName.Substring($repoFull.Length + 1)
        }
}
if ($IncludeSingletonCompat) {
    $targetHeaders += @(
        "AMManager/Config.hpp",
        "AMManager/Logger.hpp",
        "AMManager/SignalMonitor.hpp"
    )
}
$targetHeaders = $targetHeaders | Sort-Object -Unique

$violations = @()
foreach ($header in $targetHeaders) {
    $pattern = '#\s*include\s*[\"<]' + [regex]::Escape($header) + '[\">]'
    $matches = rg -n $pattern @codeGlobs @searchScopes
    foreach ($line in $matches) {
        $violations += [pscustomobject]@{
            Header = $header
            Match  = $line
        }
    }
}

Write-Host "WF-7 cutover check root: $repoFull"
Write-Host ("Headers in enforced cutover set: {0}" -f $targetHeaders.Count)

if ($violations.Count -gt 0) {
    Write-Host ("WF-7 cutover violations: {0}" -f $violations.Count) -ForegroundColor Red
    foreach ($v in $violations | Sort-Object Header, Match) {
        Write-Host ("  ERROR {0} -> {1}" -f $v.Header, $v.Match) -ForegroundColor Red
    }
    exit 1
}

Write-Host "WF-7 cutover check passed." -ForegroundColor Green
exit 0
