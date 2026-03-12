# WF-5 Interface Migration (Shim-First)

## 1) Problem Statement / Non-goals

- Problem: make `include/interface/*` the canonical CLI contract surface while
  preserving existing `AMCLI/*` callsites.
- Non-goals in this step:
  - prompt manager split (`AMManager/Prompt.hpp` -> `interface/*`)

## 2) Owned / No-touch Paths

- Owned (WF-5):
  - `include/interface/{CLIArg,CLIBind,CommandPreprocess,CommandTree,InteractiveLoop,TokenTypeAnalyzer}.hpp`
  - `include/interface/prompt/Prompt.hpp`
  - `include/interface/adapters/ApplicationAdapters.hpp`
  - `include/interface/completion/{Engine,Proxy,Searcher,SearcherCommon}.hpp`
  - `src/interface/{CLIArg,CLIBind,CommandPreprocess,command_tree,InteractiveLoop,PromptGuards,TokenTypeAnalyzer}.cpp`
  - `src/interface/completion/{engine_skeleton,engine_worker,proxy}.cpp`
  - `src/interface/completion/search/{command_searcher,internal_searcher,path_searcher}.cpp`
  - migrated equivalents:
    - `src/manager/ApplicationAdaptersCompat.cpp`
    - `src/manager/CliManagersCompat.cpp`
  - `include/AMCLI/*` compatibility forwarders
  - `include/AMManager/Prompt.hpp` compatibility forwarder
  - CLI-facing include callsites in `main.cpp`, `src/interface/*`,
    `src/manager/prompt/{api,cli}.cpp`
- No-touch:
  - application/domain/infrastructure behavior changes
  - bootstrap ownership graph semantics

## 3) Dependency Map (Current)

- Canonical CLI contracts now live in `include/interface/*`.
- Legacy `include/AMCLI/*` headers forward to `include/interface/*`.
- `include/interface/*` headers no longer directly include `AMManager/*`.
- Legacy manager binding implementation is moved to compatibility sources under
  `src/manager/*Compat.cpp`.
- CLI implementation resides in `src/interface/*` and `src/manager/prompt/*`
  (migrated-equivalent paths for this batch) and now includes
  `interface/*` contracts.

## 4) Public Contract Changes

- Added canonical interface headers for CLI loop, parsing, command tree,
  binding, token analysis, prompt, and completion APIs.
- Added interface-layer workflow adapters:
  - Host/profile/config save
  - Client session/connect
  - Transfer execute
  - Task/job orchestration
  - Variable and client-path helper gateways
- Kept legacy include compatibility:
  - `AMCLI/*` now contains forwarding headers only.
  - `AMManager/Prompt.hpp` now forwards to `interface/prompt/Prompt.hpp`.

## 5) Migration Method

- Method: shim-first.
- Step 1: publish canonical `interface/*` headers.
- Step 2: convert `AMCLI/*` to compatibility forwarders.
- Step 3: switch first-party include callsites to `interface/*`.
- Step 4: relocate CLI implementation sources from `src/cli/*` to
  `src/interface/*`.

## 6) Compatibility Impact / Rollback

- Compatibility impact:
  - old include paths (`AMCLI/*`) remain valid via forwarders.
  - first-party code now uses interface-layer include paths directly.
- Rollback:
  - restore `AMCLI/*` header bodies and revert include callsite replacements.

## 7) Done Criteria / Verification

- `include/interface/*` contains the canonical CLI contract set.
- `include/AMCLI/*` is a pure compatibility forwarding surface.
- First-party include usage for `AMManager/Prompt.hpp` is zero.
- First-party include usage for `AMCLI/*` is zero.
- `src/interface/cli/CLIArg.cpp` no longer includes
  `AMManager/{Config,Host,Logger,SignalMonitor,Transfer,Var,Client}` and now
  routes multiple command paths through `application/*` workflows via
  `interface/ApplicationAdapters`.
- `src/interface/{TokenTypeAnalyzer,searcher/internal_searcher,searcher/path_searcher,completer/engine_skeleton}.cpp`
  no longer include `AMManager/*`; they now consume
  `AMInterface::ApplicationAdapters::Runtime` query/format adapters.
- `src/interface/{CommandPreprocess,completer/engine_worker}.cpp` now consume
  `domain/var/VarModel.hpp` directly instead of `AMManager/Var.hpp`.
- `src/interface/cli/CLIArg.cpp` no longer includes `AMManager/FileSystem.hpp`; local
  filesystem command paths are now routed through
  `AMInterface::ApplicationAdapters::FileCommandGateway`.
- Direct `AMManager/*` include usage under `src/interface/*` is now zero.
- `src/interface/prompt/PromptGuards.cpp` no longer includes
  `AMManager/SignalMonitor.hpp`; prompt-hook signal toggles now route through
  `AMInterface::ApplicationAdapters::Runtime`.
- `CliManagers` no longer acquires manager singletons inside `src/interface/*`.
  Singleton lookup is now in `main.cpp` (bootstrap wiring), and
  `CliManagers` consumes explicit references.
- `AMInterface::ApplicationAdapters::Runtime::{SilenceSignalHook,ResumeSignalHook}`
  now use bound runtime dependencies instead of singleton access.
- Legacy include report confirms `AMCLI` prefix count is zero.
- `tools/check_wf7_cutover.ps1` violations are reduced to 20, with remaining
  legacy include hotspots outside interface (`main.cpp`, `src/manager/*`).
