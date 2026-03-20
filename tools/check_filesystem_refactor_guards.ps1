param(
    [string]$RepoRoot = "."
)

$ErrorActionPreference = "Stop"

$repoFull = (Resolve-Path $RepoRoot).Path
Set-Location $repoFull

$searchScopes = @(
    "main.cpp",
    "src/application",
    "src/interface",
    "src/bootstrap"
)

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

$forbiddenHeaders = @(
    "domain/filesystem/FileSystemManager.hpp",
    "domain/filesystem/deprecated/FileSystemManager.hpp",
    "domain/filesystem/deprecated/FileSystemManagerLegacy.hpp",
    "domain/filesystem/dep/FileSystemManager.dep.hpp",
    "application/filesystem/FileSystemWorkflows.hpp",
    "application/filesystem/dep/FileSystemWorkflows.dep.hpp"
)

$violations = @()

function Normalize-PathLike {
    param([string]$Path)
    if (-not $Path) {
        return ""
    }
    return $Path.Replace('\', '/')
}

function Get-MatchFilePath {
    param([string]$MatchLine)
    if (-not $MatchLine) {
        return ""
    }
    $m = [regex]::Match($MatchLine, '^(?<file>[^:]+):\d+:')
    if (-not $m.Success) {
        return ""
    }
    return Normalize-PathLike $m.Groups["file"].Value
}

function Is-AllowedCompatibilityBridge {
    param(
        [string]$RuleItem,
        [string]$MatchLine
    )
    $filePath = Get-MatchFilePath $MatchLine
    if (-not $filePath) {
        return $false
    }

    if ($RuleItem -eq "application/filesystem/dep/FileSystemWorkflows.dep.hpp" `
            -and $filePath -eq "src/application/filesystem/dep/FileSystemWorkflows.hpp") {
        return $true
    }
    return $false
}

foreach ($header in $forbiddenHeaders) {
    $pattern = '#\s*include\s*[\"<]' + [regex]::Escape($header) + '[\">]'
    $matches = rg -n $pattern @codeGlobs @searchScopes
    foreach ($line in $matches) {
        if (Is-AllowedCompatibilityBridge -RuleItem $header -MatchLine $line) {
            continue
        }
        $violations += [pscustomobject]@{
            Rule  = "forbidden include"
            Item  = $header
            Match = $line
        }
    }
}

# Guard against directly reintroducing legacy filesystem singleton/runtime type
# into active application/interface/bootstrap code paths.
$symbolPattern = '\bAMDomain::filesystem::AMFileSystem\b|\bAMFileSystem\b'
$symbolMatches = rg -n $symbolPattern @codeGlobs @searchScopes
foreach ($line in $symbolMatches) {
    $violations += [pscustomobject]@{
        Rule  = "forbidden legacy type usage"
        Item  = "AMFileSystem"
        Match = $line
    }
}

Write-Host "Filesystem refactor guard root: $repoFull"
Write-Host ("Scopes checked: {0}" -f $searchScopes.Count)
Write-Host ("Header rules: {0}" -f $forbiddenHeaders.Count)
Write-Host "Symbol rules: 1"

if ($violations.Count -gt 0) {
    Write-Host ("Filesystem refactor guard violations: {0}" -f $violations.Count) -ForegroundColor Red
    foreach ($v in $violations | Sort-Object Rule, Item, Match) {
        Write-Host ("  ERROR {0} [{1}] -> {2}" -f $v.Rule, $v.Item, $v.Match) -ForegroundColor Red
    }
    exit 1
}

Write-Host "Filesystem refactor guard passed." -ForegroundColor Green
exit 0
