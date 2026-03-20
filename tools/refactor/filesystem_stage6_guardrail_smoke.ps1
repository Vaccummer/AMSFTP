param(
    [string]$OutputPath = "md/refactor/filesystem_stage6_guardrail_snapshot.json",
    [string]$ReportPath = "md/refactor/filesystem_stage6_guardrail_report.md",
    [switch]$RunChecks
)

$ErrorActionPreference = "Stop"

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot "..\\..")
$outputFile = Join-Path $repoRoot $OutputPath
$reportFile = Join-Path $repoRoot $ReportPath
$timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:sszzz"

# Execute one guard command and capture exit/output snapshot.
function Invoke-GuardCommand {
    param(
        [string]$Name,
        [scriptblock]$Action
    )
    $watch = [System.Diagnostics.Stopwatch]::StartNew()
    $lines = @()
    & $Action *>&1 | ForEach-Object { $lines += $_.ToString() }
    $watch.Stop()
    $code = $LASTEXITCODE
    return [ordered]@{
        name = $Name
        exit_code = $code
        status = $(if ($code -eq 0) { "pass" } else { "fail" })
        duration_ms = $watch.ElapsedMilliseconds
        output_head = @($lines | Select-Object -First 12)
    }
}

function Get-CompatSummary {
    param([string]$RepoRootPath)
    $jsonText = & (Join-Path $RepoRootPath "tools/report_filesystem_compat_usage.ps1") -RepoRoot $RepoRootPath -AsJson
    if ($LASTEXITCODE -ne 0) {
        return $null
    }
    $obj = $jsonText | ConvertFrom-Json
    if (-not $obj) {
        return $null
    }
    return [ordered]@{
        root = $obj.root
        rules = @($obj.rules | ForEach-Object {
                [ordered]@{
                    rule = $_.rule
                    count = [int]$_.count
                }
            })
        files = @($obj.files | ForEach-Object {
                [ordered]@{
                    file = $_.file
                    count = [int]$_.count
                }
            })
    }
}

function Write-Stage6Report {
    param(
        [hashtable]$Snapshot,
        [string]$Path
    )

    $results = @()
    if ($Snapshot.Contains("results")) {
        $results = @($Snapshot["results"])
    }

    $total = $results.Count
    $failed = ($results | Where-Object { $_.status -ne "pass" }).Count
    $passed = $total - $failed

    $lines = @()
    $lines += "# Filesystem Stage6 Guardrail Report ($($Snapshot.generated_at))"
    $lines += ""
    $lines += "## Summary"
    $lines += "- execution: $($Snapshot.execution)"
    $lines += "- total checks: $total"
    $lines += "- passed: $passed"
    $lines += "- failed: $failed"
    $lines += ""
    $lines += "## Check Results"
    foreach ($r in $results) {
        $lines += "- $($r.name) : $($r.status) (exit $($r.exit_code), $($r.duration_ms) ms)"
    }
    $lines += ""
    $lines += "## Output Head"
    $hasOutput = $false
    foreach ($r in $results) {
        if (($r.output_head | Measure-Object).Count -le 0) {
            continue
        }
        $hasOutput = $true
        $lines += "### $($r.name)"
        $lines += '```text'
        foreach ($line in $r.output_head) {
            $lines += $line
        }
        $lines += '```'
        $lines += ""
    }
    if (-not $hasOutput) {
        $lines += "- no output captured"
    }

    $reportDir = Split-Path -Parent $Path
    if (-not (Test-Path $reportDir)) {
        New-Item -ItemType Directory -Path $reportDir -Force | Out-Null
    }
    $lines | Set-Content -Path $Path -Encoding UTF8
}

$snapshot = [ordered]@{
    stage = "filesystem-stage6"
    generated_at = $timestamp
    mode = "guardrail-smoke"
    execution = "not-run"
    checks = @(
        [ordered]@{
            name = "check_filesystem_refactor_guards"
            command = "tools/check_filesystem_refactor_guards.ps1"
            expected = "pass"
        },
        [ordered]@{
            name = "check_wf7_cutover_with_filesystem_guard"
            command = "tools/check_wf7_cutover.ps1 -IncludeFilesystemRefactorGuard"
            expected = "pass"
        },
        [ordered]@{
            name = "check_layers_scoped_filesystem_guard"
            command = "tools/check_layers.ps1 -SkipLayerDirectionCheck -FailOnFilesystemCompatInActivePath"
            expected = "pass"
        },
        [ordered]@{
            name = "run_filesystem_refactor_guardrails"
            command = "tools/run_filesystem_refactor_guardrails.ps1"
            expected = "pass"
        },
        [ordered]@{
            name = "report_filesystem_compat_usage"
            command = "tools/report_filesystem_compat_usage.ps1"
            expected = "pass"
        }
    )
}

if ($RunChecks) {
    $results = @()
    $results += Invoke-GuardCommand -Name "check_filesystem_refactor_guards" -Action {
        & (Join-Path $repoRoot "tools/check_filesystem_refactor_guards.ps1")
    }
    $results += Invoke-GuardCommand -Name "check_wf7_cutover_with_filesystem_guard" -Action {
        & (Join-Path $repoRoot "tools/check_wf7_cutover.ps1") -IncludeFilesystemRefactorGuard
    }
    $results += Invoke-GuardCommand -Name "check_layers_scoped_filesystem_guard" -Action {
        & (Join-Path $repoRoot "tools/check_layers.ps1") -SkipLayerDirectionCheck -FailOnFilesystemCompatInActivePath
    }
    $results += Invoke-GuardCommand -Name "run_filesystem_refactor_guardrails" -Action {
        & (Join-Path $repoRoot "tools/run_filesystem_refactor_guardrails.ps1")
    }
    $results += Invoke-GuardCommand -Name "report_filesystem_compat_usage" -Action {
        & (Join-Path $repoRoot "tools/report_filesystem_compat_usage.ps1")
    }

    $allPass = (($results | Where-Object { $_.status -ne "pass" }).Count -eq 0)
    $snapshot.execution = $(if ($allPass) { "pass" } else { "failed" })
    $snapshot["results"] = $results
    $compatSummary = Get-CompatSummary -RepoRootPath $repoRoot
    if ($null -ne $compatSummary) {
        $snapshot["compat_summary"] = $compatSummary
    }
}

$outputDir = Split-Path -Parent $outputFile
if (-not (Test-Path $outputDir)) {
    New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
}

$snapshot | ConvertTo-Json -Depth 10 | Set-Content -Path $outputFile -Encoding UTF8
Write-Output ("Filesystem stage6 smoke snapshot written to {0}" -f $outputFile)

if ($RunChecks) {
    Write-Stage6Report -Snapshot $snapshot -Path $reportFile
    Write-Output ("Filesystem stage6 smoke report written to {0}" -f $reportFile)
}
