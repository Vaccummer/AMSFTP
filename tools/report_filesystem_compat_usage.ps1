param(
    [string]$RepoRoot = ".",
    [switch]$AsMarkdown,
    [switch]$AsJson
)

$ErrorActionPreference = "Stop"

$repoFull = (Resolve-Path $RepoRoot).Path
Set-Location $repoFull

if ($AsMarkdown -and $AsJson) {
    Write-Error "Use either -AsMarkdown or -AsJson, not both."
    exit 2
}

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

$rules = @(
    @{
        Name = "include:domain/filesystem/FileSystemManager.hpp"
        Pattern = '#\s*include\s*[\"<]domain/filesystem/FileSystemManager\.hpp[\">]'
    },
    @{
        Name = "include:domain/filesystem/deprecated/FileSystemManager.hpp"
        Pattern = '#\s*include\s*[\"<]domain/filesystem/deprecated/FileSystemManager\.hpp[\">]'
    },
    @{
        Name = "include:domain/filesystem/deprecated/FileSystemManagerLegacy.hpp"
        Pattern = '#\s*include\s*[\"<]domain/filesystem/deprecated/FileSystemManagerLegacy\.hpp[\">]'
    },
    @{
        Name = "include:domain/filesystem/dep/FileSystemManager.dep.hpp"
        Pattern = '#\s*include\s*[\"<]domain/filesystem/dep/FileSystemManager\.dep\.hpp[\">]'
    },
    @{
        Name = "include:application/filesystem/FileSystemWorkflows.hpp"
        Pattern = '#\s*include\s*[\"<]application/filesystem/FileSystemWorkflows\.hpp[\">]'
    },
    @{
        Name = "include:application/filesystem/dep/FileSystemWorkflows.dep.hpp"
        Pattern = '#\s*include\s*[\"<]application/filesystem/dep/FileSystemWorkflows\.dep\.hpp[\">]'
    },
    @{
        Name = "symbol:AMDomain::filesystem::AMFileSystem or AMFileSystem::Instance"
        Pattern = '\bAMDomain::filesystem::AMFileSystem\b|\bAMFileSystem::Instance\s*\('
    }
)

$rows = @()
foreach ($rule in $rules) {
    $matches = rg -n $rule.Pattern @codeGlobs @searchScopes
    foreach ($line in $matches) {
        $parsed = [regex]::Match($line, '^(?<file>[^:]+):(?<line>\d+):(?<text>.*)$')
        if (-not $parsed.Success) {
            continue
        }
        $rows += [pscustomobject]@{
            Rule = $rule.Name
            File = ($parsed.Groups["file"].Value -replace '\\', '/')
            Line = [int]$parsed.Groups["line"].Value
            Text = $parsed.Groups["text"].Value
        }
    }
}

$ruleSummary = @()
foreach ($rule in $rules) {
    $count = ($rows | Where-Object { $_.Rule -eq $rule.Name }).Count
    $ruleSummary += [pscustomobject]@{
        Rule = $rule.Name
        Count = $count
    }
}
$ruleSummary = $ruleSummary | Sort-Object -Property @{ Expression = "Count"; Descending = $true }, Rule

$fileSummary = $rows |
    Group-Object File |
    ForEach-Object {
        [pscustomobject]@{
            File = $_.Name
            Count = $_.Count
        }
    } |
    Sort-Object -Property @{ Expression = "Count"; Descending = $true }, File

if ($AsMarkdown) {
    Write-Output "| Rule | Count |"
    Write-Output "|---|---:|"
    foreach ($r in $ruleSummary) {
        Write-Output ("| `{0}` | {1} |" -f $r.Rule, $r.Count)
    }
    Write-Output ""
    Write-Output "| File | Count |"
    Write-Output "|---|---:|"
    foreach ($f in ($fileSummary | Select-Object -First 30)) {
        Write-Output ("| `{0}` | {1} |" -f $f.File, $f.Count)
    }
    exit 0
}

if ($AsJson) {
    $payload = [ordered]@{
        root = $repoFull
        rules = @($ruleSummary | ForEach-Object {
                [ordered]@{
                    rule = $_.Rule
                    count = $_.Count
                }
            })
        files = @($fileSummary | Select-Object -First 30 | ForEach-Object {
                [ordered]@{
                    file = $_.File
                    count = $_.Count
                }
            })
    }
    $payload | ConvertTo-Json -Depth 8
    exit 0
}

Write-Output ("Filesystem compatibility usage report root: {0}" -f $repoFull)
Write-Output "Rule totals:"
foreach ($r in $ruleSummary) {
    Write-Output ("  {0,4}  {1}" -f $r.Count, $r.Rule)
}
Write-Output ""
Write-Output "Top files:"
foreach ($f in ($fileSummary | Select-Object -First 20)) {
    Write-Output ("  {0,4}  {1}" -f $f.Count, $f.File)
}
