# WF-2 Infrastructure Adapters (Shim-First)

## 1) Problem Statement / Non-goals

- Problem: move concrete `Config` / `Logger` / `SignalMonitor` adapter modules
  into the infrastructure layer without breaking active legacy callsites.
- Non-goals in this step:
  - Full callsite migration from `AMManager/*` to `infrastructure/*`.
  - AppHandle/SessionHandle wiring completion.

## 2) Owned / No-touch Paths

- Owned (WF-2):
  - `include/infrastructure/{Config,Logger,SignalMonitor}.hpp`
  - `src/infrastructure/Logger.cpp`
  - `src/infrastructure/signal.cpp`
  - `src/infrastructure/config/{io_base,style_data}.cpp`
  - `include/AMManager/{Config,Logger,SignalMonitor}.hpp` (compatibility
    wrappers only)
- No-touch (except compatibility include continuity):
  - Domain/application/interface behavior code.
  - Bootstrap wiring behavior.

## 3) Dependency Map (Current)

- `Config` adapter depends on:
  - cfgffi (`RustTomlRead.h`) and file/time/json helper utilities.
- `Logger` adapter depends on:
  - explicitly bound config adapter (`AMInfraConfigManager*`) for settings,
    write queue, and project root resolution.
- `SignalMonitor` adapter depends on:
  - process signal APIs and an explicitly bound task-control token
    (`std::shared_ptr<TaskControlToken>`).

## 4) Public Contract Changes

- New canonical header locations:
  - `infrastructure/Config.hpp`
  - `infrastructure/Logger.hpp`
  - `infrastructure/SignalMonitor.hpp`
- Infrastructure classes are now non-singleton types:
  - `AMInfraConfigStorage`
  - `AMInfraConfigManager`
  - `AMInfraLogManager`
  - `AMInfraCliSignalMonitor`
- Infrastructure logger/signal classes are directly constructible for DI.
- Explicit dependency binding APIs:
  - `AMInfraLogManager::BindConfigManager(...)`
  - `AMInfraCliSignalMonitor::BindTaskControlToken(...)`
- Legacy public headers remain stable and now forward:
  - `AMManager/Config.hpp` exposes compatibility `AMConfigManager::Instance()`
    wrapper over `AMInfraConfigManager`.
  - `AMManager/Logger.hpp` exposes compatibility `AMLogManager::Instance()`
    wrapper over `AMInfraLogManager`.
  - `AMManager/SignalMonitor.hpp` exposes compatibility
    `AMCliSignalMonitor::Instance()` wrapper over `AMInfraCliSignalMonitor`
    with explicit compatibility token setter methods (no deprecated
    global-token accessor usage inside wrapper).

## 5) Migration Method

- Method: shim-first.
- Move concrete declarations/definitions to infrastructure paths first.
- Keep legacy include paths intact via forwarding headers.

## 6) Compatibility Impact / Rollback

- Compatibility impact:
  - Existing singleton callsites remain valid through `AMManager/*` wrappers.
  - Infrastructure API itself no longer exposes singleton entrypoints.
  - Legacy signal wrapper requires explicit compatibility token binding when
    kill/interrupt propagation to task token is needed.
- Rollback:
  - Revert file moves and restore original include/source paths.

## 7) Done Criteria / Verification

- Adapter declarations exist under `include/infrastructure`.
- Adapter implementations exist under `src/infrastructure`.
- Singleton APIs removed from infrastructure headers and sources.
- Legacy manager headers provide compatibility wrappers for singleton callsites.
- Signal adapter no longer calls the global task-token singleton directly.
- Compatibility signal wrapper no longer re-binds deprecated global token API.
- Non-Windows signal includes use POSIX signal headers (`<csignal>`,
  `<signal.h>`).
- Cross-layer coupling cleanup: removed `friend class AMHostManager` from
  infrastructure config adapter.
- CMake source globs no longer include stale `src/manager/config/*.cpp`.
- Layer checker passes in default mode.
