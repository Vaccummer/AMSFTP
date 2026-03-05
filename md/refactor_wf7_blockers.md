# Workflow-7 Blockers Inventory

Date: 2026-03-05

## Purpose

Track why certain legacy headers cannot be cut over yet, and identify owner
workflow handoffs required to unblock WF-7 caller migration/removal.

## Blockers

| Legacy Scope | Current State | Blocking Reason | Unblock Owner | WF-7 Impact |
|---|---|---|---|---|
| `AMManager/Client.hpp` | legacy | no `include/domain/Client.hpp` contract published | WF-3 | cannot migrate include path or remove legacy header |
| `AMManager/Host.hpp` | legacy | no `include/domain/Host.hpp` contract published | WF-3 | same |
| `AMManager/Var.hpp` | legacy | no `include/domain/Var.hpp` contract published | WF-3 | same |
| `AMManager/Transfer.hpp` | legacy | no `include/domain/Transfer.hpp` contract published | WF-3 | same |
| `AMManager/FileSystem.hpp` | legacy | no `include/domain/FileSystem.hpp` contract published | WF-3 | same |
| `AMManager/{Config,Logger,SignalMonitor}.hpp` | bridged | still used by singleton compatibility runtime paths (`AM*::Instance()`) | WF-6 | strict cutover cannot pass until singleton removal is complete |

## Already Unblocked and Guarded

- `AMBase/*` is bridged to `foundation/*` and has zero first-party legacy include usage.
- `AMCLI/*` is bridged to `interface/*` and has zero first-party legacy include usage.
- `AMClient/*` is bridged to `infrastructure/client/*` and has zero first-party legacy include usage.
- `AMManager/Prompt.hpp` is bridged to `interface/Prompt.hpp` and has zero
  first-party legacy include usage.
- `AMManager/Config.hpp`, `AMManager/Logger.hpp`,
  `AMManager/SignalMonitor.hpp` are bridged to `infrastructure/*`; caller
  migration is still in progress.
- Regression guard is available via:
  - `tools/check_wf7_cutover.ps1`
  - CMake target: `check_wf7_cutover`
  - strict mode / target: `check_wf7_cutover.ps1 -IncludeSingletonCompat` /
    `check_wf7_cutover_strict`

## Exit Conditions (Per Blocker Group)

1. Replacement layered header contracts exist.
2. First-party callsites can migrate to layered include paths.
3. Legacy usage report shows stable downward trend after migration batches.
4. Forwarders are removed only after `migrated` gate criteria are met.
