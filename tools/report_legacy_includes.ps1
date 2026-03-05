param(
    [string]$RepoRoot = ".",
    [switch]$AsMarkdown
)

$ErrorActionPreference = "Stop"

$repoFull = (Resolve-Path $RepoRoot).Path
Set-Location $repoFull

$legacyPrefixes = @("AMBase", "AMManager", "AMCLI", "AMClient")
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

$pattern = '#\s*include\s*[\"<](AMBase|AMManager|AMCLI|AMClient)[/\\][^\">]+[\">]'
$matches = rg -n $pattern @codeGlobs @searchScopes

$headerCounts = @{}
foreach ($line in $matches) {
    $parsed = [regex]::Match($line, '^[^:]+:\d+:(?<text>.*)$')
    if (-not $parsed.Success) {
        continue
    }

    $text = $parsed.Groups["text"].Value
    $includeMatch = [regex]::Match($text, '#\s*include\s*[\"<](?<header>[^\">]+)[\">]')
    if (-not $includeMatch.Success) {
        continue
    }

    $header = ($includeMatch.Groups["header"].Value -replace '\\', '/')
    if (-not $headerCounts.ContainsKey($header)) {
        $headerCounts[$header] = 0
    }
    $headerCounts[$header] += 1
}

$rows = @()
foreach ($header in ($headerCounts.Keys | Sort-Object)) {
    $prefix = ($header -split '/')[0]
    $rows += [pscustomobject]@{
        Header = $header
        Prefix = $prefix
        Count  = $headerCounts[$header]
    }
}

$rows = $rows | Sort-Object -Property @{Expression = "Count"; Descending = $true }, Header
$prefixSummary = @()
foreach ($prefix in $legacyPrefixes) {
    $sum = ($rows | Where-Object { $_.Prefix -eq $prefix } |
        Measure-Object -Property Count -Sum).Sum
    if ($null -eq $sum) {
        $sum = 0
    }
    $prefixSummary += [pscustomobject]@{
        Prefix = $prefix
        Count  = $sum
    }
}

if ($AsMarkdown) {
    Write-Output "| Header | Prefix | Include Count |"
    Write-Output "|---|---|---:|"
    foreach ($row in $rows) {
        Write-Output ("| `{0}` | `{1}` | {2} |" -f $row.Header, $row.Prefix, $row.Count)
    }
    Write-Output ""
    Write-Output "| Prefix | Total Include Count |"
    Write-Output "|---|---:|"
    foreach ($item in $prefixSummary) {
        Write-Output ("| `{0}` | {1} |" -f $item.Prefix, $item.Count)
    }
    exit 0
}

Write-Output ("Legacy include report root: {0}" -f $repoFull)
Write-Output "Top 20 headers by include count:"
$rows | Select-Object -First 20 | ForEach-Object {
    Write-Output ("  {0,3}  {1}" -f $_.Count, $_.Header)
}
Write-Output ""
Write-Output "Prefix totals:"
$prefixSummary | ForEach-Object {
    Write-Output ("  {0,-10} {1}" -f $_.Prefix, $_.Count)
}
