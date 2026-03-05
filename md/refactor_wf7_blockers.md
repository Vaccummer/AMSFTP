# Workflow-7 Blockers Inventory

Date: 2026-03-04

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
| `AMManager/Prompt.hpp` | legacy | no `include/interface/Prompt*` contract published | WF-5 | prompt include migration blocked |
| `AMCLI/*` | legacy | `include/interface/` currently only has `README.md` (no replacement headers) | WF-5 | all CLI include migration blocked |
| `AMClient/Base.hpp` | legacy | no domain/infrastructure split headers published | WF-2/WF-3 | adapter/port migration blocked |
| `AMClient/IOCore.hpp` | legacy | no `include/infrastructure/IOCore.hpp` replacement published | WF-2 | migration blocked |
| `AMClient/FTP.hpp` | legacy | no layered FTP adapter header published | WF-2 | migration blocked |
| `AMClient/Local.hpp` | legacy | no layered Local adapter header published | WF-2 | migration blocked |
| `AMClient/SFTP.hpp` | legacy | no layered SFTP adapter header published | WF-2 | migration blocked |

## Already Unblocked and Guarded

- `AMBase/*` is bridged to `foundation/*` and has zero first-party legacy include usage.
- `AMManager/Config.hpp`, `AMManager/Logger.hpp`,
  `AMManager/SignalMonitor.hpp` are bridged to `infrastructure/*` and also at
  zero first-party legacy include usage.
- Regression guard is available via:
  - `tools/check_wf7_cutover.ps1`
  - CMake target: `check_wf7_cutover`

## Exit Conditions (Per Blocker Group)

1. Replacement layered header contracts exist.
2. First-party callsites can migrate to layered include paths.
3. Legacy usage report shows stable downward trend after migration batches.
4. Forwarders are removed only after `migrated` gate criteria are met.
