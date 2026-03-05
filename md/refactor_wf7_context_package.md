# Workflow-7 Context Package (Compatibility and Cutover)

## Problem Statement

WF-7 must keep the repository buildable and behavior-stable while WF-1..WF-6
move APIs into layered roots (`foundation`, `infrastructure`, `domain`,
`application`, `interface`, `bootstrap`).

Primary risk: breaking include paths and transitive dependencies too early,
especially for widely included legacy headers.

## Explicit Non-Goals

- Do not redesign domain/application behavior in WF-7.
- Do not force immediate include-path rewrites across the whole tree.
- Do not remove legacy headers until replacement headers and callers are stable.

## Owned Paths (WF-7)

- `include/AMBase/*`
- `include/AMManager/*`
- `include/AMCLI/*`
- `include/AMClient/*`
- CMake include exposure and migration notes for header visibility
- Migration tracker docs under `md/` for compatibility/cutover status

## No-Touch Paths (Except Coordination Edits)

- Business logic refactors owned by WF-1..WF-6 in `src/*` and layered headers
- New architecture/service wiring owned by WF-6 bootstrap work
- Feature changes unrelated to include-compatibility/cutover

## Current Dependency Map (WF-7 Prioritization)

Observed legacy include hotspots (reference count in source tree):

- `AMBase/DataClass.hpp`: 26
- `AMManager/Config.hpp`: 17
- `AMManager/Prompt.hpp`: 15
- `AMManager/Client.hpp`: 11
- `AMManager/Host.hpp`: 10
- `AMBase/tools/json.hpp`: 9
- `AMBase/tools/time.hpp`: 9
- `AMBase/Path.hpp`: 8
- `AMBase/Enum.hpp`: 8
- `AMManager/Var.hpp`: 8
- `AMClient/IOCore.hpp`: 7

Implication: cutover should start with shim-first handling for these headers,
then migrate call sites in controlled batches.

## Public Contract Change Policy (WF-7)

- Existing include paths under legacy roots remain valid until explicit removal.
- Any new layered API introduced by WF-1..WF-6 should get a corresponding WF-7
  compatibility mapping entry before legacy header removal.
- Legacy header removal requires:
  - replacement include path documented,
  - all first-party callers migrated,
  - rollback path documented for one release window.

## Migration Method

Shim-first, then caller migration, then removal:

1. Add/maintain compatibility forwarders in legacy roots.
2. Migrate callers toward layered includes in low-risk batches.
3. Enforce strict checks for layered files (`check_layers` strict mode).
4. Remove legacy forwarders only when usage reaches zero and contracts are
   stable.

## Compatibility Impact and Rollback Plan

- Impact:
  - short-term dual include surface (legacy + layered) is intentional.
  - compile surface may grow temporarily; behavior should remain unchanged.
- Rollback:
  - if a cutover batch regresses, restore legacy include path in affected
    callers and keep forwarders active.
  - do not remove forwarder headers in same change set as major caller rewrites.

## Done Criteria

- WF-7 matrix exists and is updated with each migration batch.
- Every legacy public header is mapped to target layer ownership.
- Cutover schedule and removal gates are documented.
- Legacy include count trends downward per batch.
- Final state: legacy roots removed or intentionally minimized with rationale.

## Verification Checklist

- [ ] Compatibility matrix updated (`md/refactor_wf7_compatibility_matrix.md`)
- [ ] Cutover schedule updated (`md/refactor_wf7_cutover_schedule.md`)
- [ ] Forwarder conventions updated (`md/refactor_wf7_forwarder_conventions.md`)
- [ ] Workflow-0 tracker updated with latest WF-7 state
- [ ] Legacy include usage snapshot refreshed (`tools/report_legacy_includes.ps1`)
- [ ] WF-7 cutover regression check passed (`tools/check_wf7_cutover.ps1`)
- [ ] No accidental singleton/global reintroduction in migration changes
- [ ] Layer checker still passes in default mode
- [ ] Strict mode evaluated for layered files before legacy removals
