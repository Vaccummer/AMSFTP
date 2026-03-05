# Workflow-0 Status Tracker

This tracker is the baseline for the layered migration and should be updated in
every refactor workflow.

## Legend

- `legacy`: old structure, not migrated
- `bridged`: partially migrated, compatibility adapters/forwarders in place
- `migrated`: fully moved to layered path and contracts

## Guardrail Deliverables

- [x] Layer policy document: `include/LAYERS.md`
- [x] Automated include-direction checker: `tools/check_layers.ps1`
- [x] CMake check target: `check_layers`
- [x] Layer placeholder roots created in `include/`

## WF-7 Compatibility Deliverables

- [x] WF-7 context package: `md/refactor_wf7_context_package.md`
- [x] WF-7 compatibility matrix: `md/refactor_wf7_compatibility_matrix.md`
- [x] WF-7 cutover schedule: `md/refactor_wf7_cutover_schedule.md`
- [x] WF-7 forwarder conventions: `md/refactor_wf7_forwarder_conventions.md`
- [x] WF-7 include snapshot baseline: `md/refactor_wf7_legacy_include_snapshot.md`
- [x] WF-7 blocker inventory: `md/refactor_wf7_blockers.md`
- [x] WF-7 cutover regression checker: `tools/check_wf7_cutover.ps1`

## Module Migration Status

| Module Scope | Current Status | Target Layer | Owner Workflow | Notes |
|---|---|---|---|---|
| `include/AMBase/*` | bridged | foundation | WF-1/WF-7 | Strict compatibility forwarders (`pragma once` + canonical `foundation/*` include only) |
| `include/AMManager/*` | bridged | domain + infrastructure + interface | WF-2/WF-3/WF-5/WF-7 | `Config/Logger/SignalMonitor` compatibility wrappers over `infrastructure/*`; `Prompt.hpp` compatibility forwarder to `interface/Prompt.hpp`; remaining business headers still legacy |
| `include/AMCLI/*` | bridged | interface | WF-5/WF-7 | Strict compatibility forwarders to `include/interface/*` canonical headers |
| `include/AMClient/*` | legacy | infrastructure + domain ports | WF-2/WF-3/WF-7 | Adapter + domain boundary cleanup, compatibility tracked by WF-7 |
| `src/base/*` | bridged | foundation | WF-1 | Utility implementations remain in legacy path but include `foundation/*` APIs |
| `src/manager/*` | legacy | domain + infrastructure | WF-2/WF-3 | Refactor by business vs adapter concerns |
| `src/cli/*` | bridged | interface | WF-5 | CLI implementation has been relocated to `src/interface/*`; path retained as compatibility/transition scope |
| `src/application/*` | legacy | application | WF-4 | Keep orchestration-only behavior |
| `include/foundation/*` | migrated | foundation | WF-1 | Canonical shared base; no `AMBase/*` includes; singleton accessor now transitional/deprecated |
| `include/infrastructure/*` | bridged | infrastructure | WF-2 | `Config/Logger/SignalMonitor` adapters migrated; infra API switched to explicit non-singleton classes with binding APIs; logger/signal constructors are publicly constructible for DI; config friend coupling to host removed |
| `include/domain/*` | bridged | domain | WF-3 | Placeholder root created in WF-0 |
| `include/application/*` | bridged | application | WF-4 | Placeholder root created in WF-0 |
| `include/interface/*` | bridged | interface | WF-5 | Canonical CLI contract headers published; header-level `AMManager/*` includes removed; interface runtime/prompt guard sources are manager-header clean; manager-coupled compatibility implementations are isolated in `src/manager/*Compat.cpp` and other legacy implementation paths |
| `include/bootstrap/*` | bridged | bootstrap | WF-6 | Placeholder root created in WF-0 |

## Enforcement Notes

- Checker currently validates files under layered roots only:
  - `include/foundation|infrastructure|domain|application|interface|bootstrap`
  - `src/foundation|infrastructure|domain|application|interface|bootstrap`
- Legacy includes from layered files are warnings by default.
- Use strict mode to fail on legacy includes:
  - `tools/check_layers.ps1 -RepoRoot . -FailOnLegacyInclude`

## WF-1 Status Note

Done:

- `foundation/*` is the canonical shared base include surface.
- `AMBase/*` headers are strict forwarders to `foundation/*`.
- Foundation include graph no longer references `AMBase/*`.
- `TaskControlToken::Instance()` is transitional/deprecated; explicit
  `TaskControlToken::CreateShared()` is available.

Remaining:

- Global token usage remains in upper legacy layers and needs WF-6 ownership
  cutover to remove singleton access paths.
- `src/base/*` path relocation to `src/foundation/*` is pending dedicated
  migration cleanup.

## Next Update Rules

1. Any workflow that migrates files must update this table.
2. If compatibility shims are introduced, mark status as `bridged`.
3. Move to `migrated` only after callers are switched and legacy dependency is removed.
4. WF-7 must keep `md/refactor_wf7_compatibility_matrix.md` and
   `md/refactor_wf7_cutover_schedule.md` in sync with migration batches.
