# AMSFTP Layered Refactor Master Plan

## Objective

Refactor the whole project to:

1. Use the target layer structure.
2. Remove singleton-style/global access and fully adopt AppHandle + SessionHandle ownership.

Target include layers:

- include/foundation: shared primitives, common types, error codes, utilities
- include/infrastructure: adapters (config IO, logging sinks, signal/platform wrappers)
- include/domain: business/domain services and models
- include/application: use-cases and command orchestration
- include/interface: CLI-facing contracts, rendering/input abstractions
- include/bootstrap: wiring/composition root interfaces

## Current Baseline (Important)

- Composition root seeds already exist:
  - include/bootstrap/AppHandle.hpp
  - include/bootstrap/SessionHandle.hpp
  - main.cpp
- Application workflow modules already exist under include/application and src/application.
- Legacy trees (AMBase, AMManager, AMCLI) are still heavily referenced and should be migrated incrementally with compatibility shims.

## Architecture Rules (Must Enforce First)

Dependency direction:

- foundation <- domain <- application <- interface <- bootstrap
- infrastructure may depend on foundation and implement ports from domain/application
- domain must not depend on infrastructure concrete implementations

Hard rules:

- No new singleton/global service access.
- No hidden service lookup; dependencies are constructor/parameter injected.
- Session mutable state must stay in SessionHandle.
- Process lifetime services must stay in AppHandle.

## Whole Refactor Plan

### Phase 0: Guardrails and Safety Net

Goals:

- Freeze architectural boundaries before moving files.
- Prevent accidental reverse dependencies.

Tasks:

- Add layer dependency policy doc.
- Add include-direction validation script/check.
- Add migration status tracker per module: legacy, bridged, migrated.

Done criteria:

- Policy is documented.
- Automated dependency checks can fail CI/local checks when violated.

### Phase 1: Foundation Extraction

Goals:

- Build a stable, reusable base in include/foundation.

Tasks:

- Move shared primitives/types/utilities from AMBase into foundation.
- Keep temporary forwarding compatibility headers in AMBase.
- Normalize error/result/control-token usage into foundation APIs.

Done criteria:

- Core shared headers are available from foundation.
- Legacy AMBase headers mostly forward to foundation.

### Phase 2: Infrastructure Isolation

Goals:

- Move platform and external adapters into include/infrastructure.

Tasks:

- Extract config persistence and schema IO adapters.
- Extract logging sinks/adapters.
- Extract signal/platform wrappers.
- Keep concrete external integration out of domain/application.

Done criteria:

- Config/log/signal concrete implementations live in infrastructure.
- Upper layers consume interfaces, not concrete adapter internals.

### Phase 3: Domain Core Extraction

Goals:

- Keep business models and rules in include/domain.

Tasks:

- Extract host/client/var/transfer/filesystem domain models/services.
- Remove UI/CLI formatting and direct persistence calls from domain classes.
- Define domain ports/interfaces required by domain services.

Done criteria:

- Domain code is business-focused and independent from CLI/adapters.

### Phase 4: Application Use-Case Consolidation

Goals:

- Keep orchestration-only logic in include/application.

Tasks:

- Refine existing workflow modules to pure use-case orchestration.
- Ensure use-cases receive explicit dependencies + session context.
- Remove manager-to-manager ad-hoc orchestration leakage.

Done criteria:

- Use-cases are stable contracts between interface and domain/infrastructure ports.

### Phase 5: Interface Layer Migration

Goals:

- Move CLI contracts/render/input/completion to include/interface.

Tasks:

- Migrate InteractiveLoop, PromptRender, CLI binding/parsing abstractions.
- Interface calls application use-cases only.
- Remove direct infrastructure coupling from CLI layer.

Done criteria:

- CLI/prompt modules compile and run through application contracts.

### Phase 6: Bootstrap Finalization and Singleton Removal

Goals:

- Make bootstrap the only composition root.

Tasks:

- Finalize AppHandle process-wide ownership graph.
- Finalize SessionHandle per-run/per-loop context ownership.
- Eliminate all remaining singleton/global service paths.
- Remove compatibility overloads after migration stabilizes.

Done criteria:

- No singleton usage in first-party code.
- All service wiring is explicit in bootstrap.

### Phase 7: Compatibility Cutover and Cleanup

Goals:

- Complete migration and remove legacy surface safely.

Tasks:

- Remove transitional forwarding headers gradually.
- Update include paths and CMake exposure.
- Decommission unused legacy modules/folders.

Done criteria:

- New layered structure is canonical.
- Legacy AMBase/AMManager/AMCLI compatibility shims are removed or minimized intentionally.

## Parallel Workflow Design (Acceleration Plan)

Use low-coupling workstreams with strict ownership and interface contracts.

### WF-0 Architecture Guardrails

Goal:

- Lock dependency rules and migration protocol.

Context package:

- include/LAYERS.md
- include/bootstrap/AppHandle.hpp
- include/bootstrap/SessionHandle.hpp

Owns:

- Policy docs
- Dependency check scripts/rules

Delivers:

- Enforced layering constraints and migration checklist.

### WF-1 Foundation Extraction

Goal:

- Build include/foundation as the shared base.

Context package:

- include/AMBase/DataClass.hpp
- include/AMBase/Enum.hpp
- include/AMBase/tools/*

Owns:

- include/foundation/*
- AMBase compatibility forwarders

Delivers:

- Stable foundation interfaces used by all other workflows.

### WF-2 Infrastructure Adapters

Goal:

- Move concrete adapters to infrastructure.

Context package:

- include/AMManager/Config.hpp
- include/AMManager/Logger.hpp
- include/AMManager/SignalMonitor.hpp
- src/manager/config/*
- src/manager/Logger.cpp
- src/manager/signal.cpp

Owns:

- include/infrastructure/*
- src/infrastructure/* (or migrated equivalents)

Delivers:

- Config/log/signal adapter modules behind explicit interfaces.

### WF-3 Domain Core

Goal:

- Isolate business models/services from manager monolith behavior.

Context package:

- include/AMManager/Client.hpp
- include/AMManager/FileSystem.hpp
- include/AMManager/Host.hpp
- include/AMManager/Var.hpp
- include/AMManager/Transfer.hpp

Owns:

- include/domain/*
- src/domain/* (or migrated equivalents)

Delivers:

- Domain services/models with zero CLI-rendering dependency.

### WF-4 Application Orchestration

Goal:

- Keep application as use-case orchestration layer.

Context package:

- include/application/*
- src/application/*
- src/cli/CLIArg.cpp

Owns:

- include/application/*
- src/application/*

Delivers:

- Stable use-case APIs for CLI/interface integration.

### WF-5 Interface (CLI, Prompt, Completion)

Goal:

- Move CLI-specific behavior into interface layer.

Context package:

- include/AMCLI/InteractiveLoop.hpp
- include/AMCLI/PromptRender.hpp
- src/cli/InteractiveLoop.cpp
- src/cli/PromptRender.cpp
- src/cli/*

Owns:

- include/interface/*
- src/interface/* (or migrated equivalents)

Delivers:

- CLI contracts/render/input abstractions using application use-cases.

### WF-6 Bootstrap and Session Model Completion

Goal:

- Complete AppHandle + SessionHandle ownership model and remove singleton usage.

Context package:

- main.cpp
- include/bootstrap/AppHandle.hpp
- include/bootstrap/SessionHandle.hpp
- dispatch path in src/cli/CLIBind.cpp

Owns:

- include/bootstrap/*
- bootstrap wiring entrypoints

Delivers:

- Single composition root, explicit dependency graph, session-scoped execution context.

### WF-7 Compatibility and Cutover

Goal:

- Keep migration non-breaking while parallel streams land.

Context package:

- include/AMBase/*
- include/AMManager/*
- include/AMCLI/*
- CMake include directories and targets

Owns:

- Compatibility forwarders
- Cutover/deprecation schedule

Delivers:

- Predictable migration path and final cleanup plan.

## Parallel Execution Sequence

1. Start WF-0 immediately (blocking policy baseline).
2. Run WF-1, WF-2, WF-7 in parallel.
3. Start WF-3 after foundation contracts stabilize.
4. Run WF-4 and WF-5 in parallel after domain interfaces are available.
5. Run WF-6 when application/interface contracts are stable.
6. Finish with WF-7 cutover and legacy cleanup.

## Workflow Context Requirements (Each Stream Must Include)

For every workflow handoff, include:

1. Problem statement and explicit non-goals.
2. Owned paths and no-touch paths.
3. Current dependency map for owned files.
4. Public contract changes (headers/signatures/interfaces).
5. Migration method (shim-first or direct move).
6. Compatibility impact and rollback plan.
7. Done criteria and verification checklist.

## Integration Contracts (Cross-Workflow)

- SessionHandle owns per-run mutable context only.
- AppHandle owns process-lifetime services only.
- Interface depends on application contracts, not infrastructure concrete types.
- Domain does not include CLI/render/config/log concrete headers.
- All use-cases receive dependencies explicitly.

## Milestones and Exit Criteria

Milestone A:

- Foundation + infrastructure contracts stable.

Milestone B:

- Domain/application contracts stable.

Milestone C:

- Interface migrated to use-case APIs only.

Milestone D:

- Bootstrap-only wiring path active, no singleton/global paths.

Milestone E:

- Legacy compatibility removed or intentionally minimized with documented rationale.
