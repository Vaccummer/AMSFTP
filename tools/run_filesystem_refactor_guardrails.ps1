param(
    [string]$RepoRoot = ".",
    [switch]$CheckDelta,
    [switch]$UpdateDeltaBaseline
)

$ErrorActionPreference = "Stop"

$repoFull = (Resolve-Path $RepoRoot).Path
$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path

function Invoke-GuardStep {
    param(
        [string]$Name,
        [scriptblock]$Action
    )
    Write-Host ("[RUN ] {0}" -f $Name)
    & $Action
    if ($LASTEXITCODE -ne 0) {
        Write-Host ("[FAIL] {0}" -f $Name) -ForegroundColor Red
        return $false
    }
    Write-Host ("[PASS] {0}" -f $Name) -ForegroundColor Green
    return $true
}

Write-Host ("Filesystem refactor guardrail suite root: {0}" -f $repoFull)
Write-Host ("Delta check enabled: {0}" -f $CheckDelta.IsPresent)
Write-Host ("Delta baseline update: {0}" -f $UpdateDeltaBaseline.IsPresent)

$ok = $true

$ok = (Invoke-GuardStep -Name "check_filesystem_refactor_guards" -Action {
        & (Join-Path $scriptRoot "check_filesystem_refactor_guards.ps1") -RepoRoot $repoFull
    }) -and $ok

$ok = (Invoke-GuardStep -Name "check_wf7_cutover + filesystem guard" -Action {
        & (Join-Path $scriptRoot "check_wf7_cutover.ps1") -RepoRoot $repoFull -IncludeFilesystemRefactorGuard
    }) -and $ok

$ok = (Invoke-GuardStep -Name "check_layers scoped filesystem-compat" -Action {
        & (Join-Path $scriptRoot "check_layers.ps1") -RepoRoot $repoFull -SkipLayerDirectionCheck -FailOnFilesystemCompatInActivePath
    }) -and $ok

Write-Host "[INFO] filesystem compatibility residue report"
& (Join-Path $scriptRoot "report_filesystem_compat_usage.ps1") -RepoRoot $repoFull
if ($LASTEXITCODE -ne 0) {
    Write-Host "[WARN] report_filesystem_compat_usage returned non-zero" -ForegroundColor Yellow
}

if ($CheckDelta) {
    $ok = (Invoke-GuardStep -Name "refresh_filesystem_stage6_snapshot" -Action {
            & (Join-Path $scriptRoot "refactor/filesystem_stage6_guardrail_smoke.ps1") -RunChecks
        }) -and $ok

    $deltaParams = @{}
    if ($UpdateDeltaBaseline) {
        $deltaParams.UpdateBaseline = $true
    }
    $ok = (Invoke-GuardStep -Name "check_filesystem_stage6_snapshot_delta" -Action {
            & (Join-Path $scriptRoot "refactor/check_filesystem_stage6_snapshot_delta.ps1") @deltaParams
        }) -and $ok
}

if (-not $ok) {
    Write-Host "Filesystem refactor guardrail suite failed." -ForegroundColor Red
    exit 1
}

Write-Host "Filesystem refactor guardrail suite passed." -ForegroundColor Green
exit 0
