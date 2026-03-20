# tools

Repository utility scripts for migration checks and compatibility reports.

## Layer and Legacy Checks

1. `check_layers.ps1`
- Layer-direction checker for `src/`.
- Legacy include strict mode: `-FailOnLegacyInclude`.
- Filesystem active-path compatibility strict mode:
  `-FailOnFilesystemCompatInActivePath`.
- Scoped filesystem-only mode:
  `-SkipLayerDirectionCheck -FailOnFilesystemCompatInActivePath`.

Example:
```powershell
D:\Powershell\7\pwsh.exe -NoProfile -File tools/check_layers.ps1 -SkipLayerDirectionCheck -FailOnFilesystemCompatInActivePath
```

2. `check_wf7_cutover.ps1`
- WF-7 legacy include cutover checker.
- Optional strict flags:
  - `-IncludeSingletonCompat`
  - `-IncludeManagerCompat`
  - `-IncludeFilesystemRefactorGuard` (runs `check_filesystem_refactor_guards.ps1`)

Example:
```powershell
D:\Powershell\7\pwsh.exe -NoProfile -File tools/check_wf7_cutover.ps1 -IncludeFilesystemRefactorGuard
```

3. `report_legacy_includes.ps1`
- Aggregated report for legacy include prefixes (`AMBase`, `AMManager`, `AMCLI`, `AMClient`).
- Supports `-AsMarkdown`.

## Filesystem Refactor Guardrails

1. `check_filesystem_refactor_guards.ps1`
- Enforces no reintroduction of filesystem compatibility headers/types in active paths:
  - `main.cpp`
  - `src/{application,interface,bootstrap}`
- Keeps explicit compatibility bridge exception:
  `src/application/filesystem/dep/FileSystemWorkflows.hpp` ->
  `application/filesystem/dep/FileSystemWorkflows.dep.hpp`.

Example:
```powershell
D:\Powershell\7\pwsh.exe -NoProfile -File tools/check_filesystem_refactor_guards.ps1
```

2. `report_filesystem_compat_usage.ps1`
- Reports filesystem compatibility residue by rule/file:
  - legacy filesystem manager headers
  - deprecated filesystem workflow headers
  - legacy `AMFileSystem` symbol usage
- Supports `-AsMarkdown`.
- Supports `-AsJson` for machine-readable summaries.

Example:
```powershell
D:\Powershell\7\pwsh.exe -NoProfile -File tools/report_filesystem_compat_usage.ps1
```

3. `run_filesystem_refactor_guardrails.ps1`
- Stage-6 orchestration entrypoint that runs:
  - `check_filesystem_refactor_guards.ps1`
  - `check_wf7_cutover.ps1 -IncludeFilesystemRefactorGuard`
  - `check_layers.ps1 -SkipLayerDirectionCheck -FailOnFilesystemCompatInActivePath`
  - `report_filesystem_compat_usage.ps1`
- Fails if any strict guard step fails.
- Optional delta mode:
  - `-CheckDelta` refreshes Stage-6 snapshot (`filesystem_stage6_guardrail_smoke.ps1 -RunChecks`)
    then runs `tools/refactor/check_filesystem_stage6_snapshot_delta.ps1`
  - `-UpdateDeltaBaseline` (with `-CheckDelta`) refreshes baseline

Example:
```powershell
D:\Powershell\7\pwsh.exe -NoProfile -File tools/run_filesystem_refactor_guardrails.ps1
```

4. `tools/refactor/filesystem_stage6_guardrail_smoke.ps1`
- Refactor-style smoke snapshot runner for Stage-6 guardrails.
- Writes JSON snapshot to:
  `md/refactor/filesystem_stage6_guardrail_snapshot.json`.
- Writes Markdown report to:
  `md/refactor/filesystem_stage6_guardrail_report.md`.
- `-RunChecks` executes guardrail commands before writing snapshot.

Example:
```powershell
D:\Powershell\7\pwsh.exe -NoProfile -File tools/refactor/filesystem_stage6_guardrail_smoke.ps1 -RunChecks
```

5. `tools/refactor/check_filesystem_stage6_snapshot_delta.ps1`
- Compares current Stage-6 snapshot to baseline and fails on rule-count regressions.
- Baseline init/update:
  `-UpdateBaseline` (default baseline path:
  `md/refactor/filesystem_stage6_guardrail_baseline.json`).

Example:
```powershell
D:\Powershell\7\pwsh.exe -NoProfile -File tools/refactor/check_filesystem_stage6_snapshot_delta.ps1
```
