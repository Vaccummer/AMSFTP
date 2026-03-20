param(
    [string]$CurrentPath = "md/refactor/filesystem_stage6_guardrail_snapshot.json",
    [string]$BaselinePath = "md/refactor/filesystem_stage6_guardrail_baseline.json",
    [switch]$UpdateBaseline
)

$ErrorActionPreference = "Stop"

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot "..\\..")
$currentFile = Join-Path $repoRoot $CurrentPath
$baselineFile = Join-Path $repoRoot $BaselinePath

if (-not (Test-Path $currentFile)) {
    Write-Host ("Current snapshot not found: {0}" -f $currentFile) -ForegroundColor Red
    exit 1
}

if ($UpdateBaseline) {
    $baselineDir = Split-Path -Parent $baselineFile
    if (-not (Test-Path $baselineDir)) {
        New-Item -ItemType Directory -Path $baselineDir -Force | Out-Null
    }
    Copy-Item -Path $currentFile -Destination $baselineFile -Force
    Write-Host ("Baseline updated: {0}" -f $baselineFile) -ForegroundColor Green
    exit 0
}

if (-not (Test-Path $baselineFile)) {
    Write-Host ("Baseline snapshot not found: {0}" -f $baselineFile) -ForegroundColor Red
    Write-Host "Run with -UpdateBaseline to initialize baseline." -ForegroundColor Yellow
    exit 1
}

$current = Get-Content $currentFile -Raw | ConvertFrom-Json
$baseline = Get-Content $baselineFile -Raw | ConvertFrom-Json

$violations = @()

if ($current.execution -ne "pass") {
    $violations += "current snapshot execution is '$($current.execution)'"
}

if (-not $current.compat_summary -or -not $current.compat_summary.rules) {
    $violations += "current snapshot missing compat_summary.rules"
}
if (-not $baseline.compat_summary -or -not $baseline.compat_summary.rules) {
    $violations += "baseline snapshot missing compat_summary.rules"
}

$currentRules = @{}
$baselineRules = @{}

if ($current.compat_summary -and $current.compat_summary.rules) {
    foreach ($r in $current.compat_summary.rules) {
        $currentRules[$r.rule] = [int]$r.count
    }
}
if ($baseline.compat_summary -and $baseline.compat_summary.rules) {
    foreach ($r in $baseline.compat_summary.rules) {
        $baselineRules[$r.rule] = [int]$r.count
    }
}

foreach ($rule in $baselineRules.Keys) {
    $baseCount = $baselineRules[$rule]
    $currCount = 0
    if ($currentRules.ContainsKey($rule)) {
        $currCount = $currentRules[$rule]
    }
    if ($currCount -gt $baseCount) {
        $violations += ("rule count regression: '{0}' baseline={1}, current={2}" -f $rule, $baseCount, $currCount)
    }
}

foreach ($rule in $currentRules.Keys) {
    if (-not $baselineRules.ContainsKey($rule) -and $currentRules[$rule] -gt 0) {
        $violations += ("new positive-count rule detected: '{0}' current={1}" -f $rule, $currentRules[$rule])
    }
}

Write-Host ("Filesystem Stage6 delta check current : {0}" -f $currentFile)
Write-Host ("Filesystem Stage6 delta check baseline: {0}" -f $baselineFile)

if ($violations.Count -gt 0) {
    Write-Host ("Delta check violations: {0}" -f $violations.Count) -ForegroundColor Red
    foreach ($v in $violations) {
        Write-Host ("  ERROR {0}" -f $v) -ForegroundColor Red
    }
    exit 1
}

Write-Host "Delta check passed." -ForegroundColor Green
exit 0
