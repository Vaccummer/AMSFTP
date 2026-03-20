# WF-6 Bootstrap and Session Model Completion (Current Pass)

## 1) Problem Statement / Non-goals

- Problem: finalize bootstrap-owned wiring for process/session lifetimes and
  remove singleton task-token/run-context access from the CLI dispatch path.
- Non-goals in this pass:
  - Full singleton elimination across legacy manager/domain implementations.
  - Command-tree and interactive event registry singleton removal.

## 2) Owned / No-touch Paths

- Owned (WF-6):
  - `include/bootstrap/{AppHandle,SessionHandle}.hpp`
  - `main.cpp`
  - `include/interface/cli/CLIArg.hpp`
  - `src/interface/{CLIArg,InteractiveLoop}.cpp`
  - `src/bootstrap/CliManagersBootstrap.cpp`
- No-touch:
  - Domain/application behavior semantics.
  - Legacy manager internal singleton implementations outside bootstrap path.

## 3) Dependency Map (Current)

- `AppHandle` owns process-lifetime manager wiring and runtime adapter binding.
- `SessionHandle` owns mutable per-run execution context and task-control token.
- `CliManagers::Init(...)` now requires explicit token injection.
- CLI dispatch/interactive path reads token from `CliRunContext`.

## 4) Public Contract Changes

- Added:
  - `AMBootstrap::AppHandle`
  - `AMBootstrap::SessionHandle`
- Updated:
  - `CliManagers::Init(const amf &task_control_token)`
  - `CliRunContext` now carries `task_control_token` and no longer exposes
    `CliRunContext::Instance()`.

## 5) Migration Method

- Method: shim-first within bootstrap path.
- Removed singleton-compat bootstrap includes in `main.cpp` for
  `Config/Logger/SignalMonitor` and switched to explicit infrastructure
  instances there.
- Kept legacy singleton acquisition for host/client/transfer/filesystem/var in
  `main.cpp` for now.

## 6) Compatibility Impact / Rollback

- Compatibility impact:
  - Command execution now receives task token from session context.
  - Bootstrap runtime binding lifecycle is explicit and guard-scoped.
- Rollback:
  - Restore direct wiring in `main.cpp` and revert `CliRunContext`/`CliManagers`
    contract updates.

## 7) Done Criteria / Verification

- `main.cpp` now wires via `AppHandle` + `SessionHandle`.
- `CliRunContext::Instance()` removed.
- `TaskControlToken::Instance()` removed from:
  - `src/interface/cli/CLIArg.cpp`
  - `src/interface/cli/InteractiveLoop.cpp`
  - `src/bootstrap/CliManagersBootstrap.cpp`
- Runtime bindings are reset automatically through bootstrap guard at process
  exit paths.
- `SessionHandle::ResetRunContext()` resets task-token runtime state.
- `DispatchCliCommands(...)` now fails fast when session token is missing.
- Strict cutover check (`check_wf7_cutover.ps1 -IncludeSingletonCompat`) is
  reduced from 19 to 15 violations; remaining violations are outside WF-6-owned
  bootstrap/interface files.
