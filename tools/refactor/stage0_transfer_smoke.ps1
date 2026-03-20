param(
    [string]$OutputPath = "md/refactor/amworkmanager_stage0_snapshot.json",
    [string]$BinaryPath = ""
)

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot "..\\..")
$outputFile = Join-Path $repoRoot $OutputPath
$timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:sszzz"

$snapshot = [ordered]@{
    stage = "stage0"
    generated_at = $timestamp
    mode = "baseline-contract"
    execution = "not-run"
    binary = $BinaryPath
    cases = [ordered]@{
        load_tasks = [ordered]@{
            file_to_file = "expect_single_task_or_path_already_exists"
            file_to_dir = "expect_basename_append_when_destination_is_directory"
            dir_to_dir = "expect_recursive_relative_mapping"
            resume = "expect_dst_file_exists_and_size_le_src"
            interrupt = "expect_ec_terminate"
            timeout = "expect_ec_operation_timeout"
        }
        scheduler = [ordered]@{
            submit = "expect_pending_status"
            pause = "expect_paused_status"
            resume = "expect_requeued_or_conducting_status"
            terminate = "expect_ec_terminate"
            graceful_terminate_timeout = "expect_ec_operation_timeout"
        }
        transfer_matrix = @(
            "local-local",
            "local-ftp",
            "local-sftp",
            "ftp-sftp",
            "sftp-transit"
        )
    }
}

if (-not [string]::IsNullOrWhiteSpace($BinaryPath) -and (Test-Path $BinaryPath)) {
    $snapshot.execution = "binary-present-manual-run-required"
}

$snapshot | ConvertTo-Json -Depth 8 | Set-Content -Path $outputFile -Encoding UTF8
Write-Output "Stage0 snapshot written to $outputFile"
