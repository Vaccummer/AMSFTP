# Workflow-7 Cutover Schedule

## Purpose

Define a predictable, non-breaking path from legacy include roots
(`AMBase`, `AMManager`, `AMCLI`, `AMClient`) to layered include roots.

## Cutover Sequence

1. Baseline and map all public legacy headers.
2. Introduce/maintain compatibility forwarders for migrated contracts.
3. Migrate caller includes in small batches (high fan-out last per module).
4. Enforce stricter checks on layered files.
5. Remove legacy headers only after usage reaches zero and rollback is ready.

## Batch Plan

### Batch WF7-A (Now): Tracker + Contract Baseline

- Deliverables:
  - `md/refactor_wf7_context_package.md`
  - `md/refactor_wf7_compatibility_matrix.md`
  - `md/refactor_wf7_cutover_schedule.md`
- Exit criteria:
  - all legacy public headers mapped with owner workflow and priority.

### Batch WF7-B: Shim-First Compatibility

- Scope:
  - for every layered header introduced by WF-1..WF-6, keep legacy entrypoint
    compiling via compatibility forwarding/shim strategy.
- Exit criteria:
  - no caller breakage from include-path changes in active workflows.

Current status (2026-03-04):

- Completed:
  - `AMBase/*` forwarder bridge to `foundation/*`
  - `AMManager/Config.hpp` -> `infrastructure/Config.hpp`
  - `AMManager/Logger.hpp` -> `infrastructure/Logger.hpp`
  - `AMManager/SignalMonitor.hpp` -> `infrastructure/SignalMonitor.hpp`
- Pending:
  - `AMClient/FTP.hpp` and `AMClient/Local.hpp` still lack layered target
    headers, so they remain `legacy` until WF-2 publishes replacements.

### Batch WF7-C: Caller Migration

- Scope:
  - switch internal callers from legacy includes to layered includes.
- Order:
  - `P2` low fan-out headers first,
  - `P1` medium fan-out second,
  - `P0` high fan-out last with smaller PR/change batches.
- Exit criteria:
  - include usage trend reduced and tracked in matrix updates.

Tracking command:

- `pwsh -NoProfile -ExecutionPolicy Bypass -File tools/report_legacy_includes.ps1 -RepoRoot .`
- `cmake --build <build-dir> --target report_legacy_includes`
- `pwsh -NoProfile -ExecutionPolicy Bypass -File tools/check_wf7_cutover.ps1 -RepoRoot .`
- `cmake --build <build-dir> --target check_wf7_cutover`
- `pwsh -NoProfile -ExecutionPolicy Bypass -File tools/check_wf7_cutover.ps1 -RepoRoot . -IncludeSingletonCompat`
- `cmake --build <build-dir> --target check_wf7_cutover_strict`

Note:

- default check excludes `AMManager/{Config,Logger,SignalMonitor}.hpp` because
  these singleton compatibility wrappers are gated on WF-6 completion.
- strict check includes those headers and is the target state after WF-6.

### Batch WF7-D: Strictness Ramp

- Scope:
  - run strict include policy checks for layered files and enforce remediation.
- Exit criteria:
  - no strict-mode violations from legacy includes in layered roots.

### Batch WF7-E: Legacy Surface Removal/Minimization

- Scope:
  - remove unused compatibility headers,
  - retain only intentional compatibility surface with documented rationale.
- Exit criteria:
  - layered structure is canonical,
  - legacy roots removed or minimized intentionally.

## Removal Gate Checklist (Per Header)

- [ ] replacement layered include path exists and is documented
- [ ] all first-party include sites migrated
- [ ] dependent modules validated by owning workflow
- [ ] rollback strategy documented
- [ ] matrix status moved from `bridged` to `migrated`

## Rollback Rules

- If a cutover batch breaks compile/runtime behavior:
  - immediately restore the last known-good include entrypoint,
  - keep compatibility forwarder active,
  - split failing migration batch into smaller units before retry.
- Never combine forwarder removal with large behavioral refactors.

## Coordination Protocol

- WF-1/WF-2/WF-3/WF-5 notify WF-7 when introducing layered public headers.
- WF-7 updates matrix status and migration notes in the same window.
- WF-6 bootstrap changes that alter top-level contracts require WF-7 review for
  include compatibility impact.

## Related WF-7 Docs

- `md/refactor_wf7_context_package.md`
- `md/refactor_wf7_compatibility_matrix.md`
- `md/refactor_wf7_forwarder_conventions.md`
- `md/refactor_wf7_legacy_include_snapshot.md`
- `md/refactor_wf7_blockers.md`
