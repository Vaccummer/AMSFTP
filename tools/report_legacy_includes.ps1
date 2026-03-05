param(
    [string]$RepoRoot = ".",
    [switch]$AsMarkdown
)

$ErrorActionPreference = "Stop"

function Normalize-PathForRegex {
    param([string]$Path)
    return (($Path -replace '^include[\\/]', '') -replace '\\', '/')
}

$repoFull = (Resolve-Path $RepoRoot).Path
Set-Location $repoFull

$legacyRoots = @(
    "include/AMBase",
    "include/AMManager",
    "include/AMCLI",
    "include/AMClient"
)

$headers = @()
foreach ($root in $legacyRoots) {
    if (Test-Path $root) {
        $headers += Get-ChildItem -File -Recurse $root | ForEach-Object {
            Normalize-PathForRegex $_.FullName.Substring($repoFull.Length + 1)
        }
    }
}
$headers = $headers | Sort-Object -Unique

$searchScopes = @("main.cpp", "src", "include")
$rows = @()
foreach ($header in $headers) {
    $pattern = '#\s*include\s*[\"<]' + [regex]::Escape($header) + '[\">]'
    $count = (rg -n $pattern @searchScopes | Measure-Object).Count
    $prefix = ($header -split '/')[0]
    $rows += [pscustomobject]@{
        Header = $header
        Prefix = $prefix
        Count  = $count
    }
}

$rows = $rows | Sort-Object -Property @{Expression = "Count"; Descending = $true }, Header
$prefixSummary = $rows |
    Group-Object Prefix |
    Sort-Object Name |
    ForEach-Object {
        [pscustomobject]@{
            Prefix = $_.Name
            Count  = ($_.Group | Measure-Object -Property Count -Sum).Sum
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
