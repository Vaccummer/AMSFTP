# Workflow-7 Compatibility Matrix

This matrix tracks legacy header compatibility ownership and cutover status.

Reference count note:

- Table `Ref Count` values are baseline fan-out reference points collected at
  WF7-A planning time.
- Current live include usage should be measured with
  `tools/report_legacy_includes.ps1`.

## Status Legend

- `legacy`: header remains primary include path.
- `bridged`: legacy header kept as compatibility shim/forwarder.
- `migrated`: layered include path is canonical; legacy header removable.

## Priority Legend

- `P0`: high fan-out (`>= 10` references), migrate with extra caution.
- `P1`: medium fan-out (`4..9` references).
- `P2`: low fan-out (`<= 3` references).

## AMBase -> foundation (WF-1 with WF-7 compatibility tracking)

| Legacy Header | Ref Count | Priority | Target Layer | Owner | Status | Notes |
|---|---:|---|---|---|---|---|
| `AMBase/DataClass.hpp` | 26 | P0 | `foundation` | WF-1 + WF-7 | bridged | Forwarder active -> `foundation/DataClass.hpp` |
| `AMBase/Enum.hpp` | 8 | P1 | `foundation` | WF-1 + WF-7 | bridged | Forwarder active -> `foundation/Enum.hpp` |
| `AMBase/Path.hpp` | 8 | P1 | `foundation` | WF-1 + WF-7 | bridged | Forwarder active -> `foundation/Path.hpp` |
| `AMBase/tools/json.hpp` | 9 | P1 | `foundation` | WF-1 + WF-7 | bridged | Forwarder active -> `foundation/tools/json.hpp` |
| `AMBase/tools/time.hpp` | 9 | P1 | `foundation` | WF-1 + WF-7 | bridged | Forwarder active -> `foundation/tools/time.hpp` |
| `AMBase/tools/auth.hpp` | 6 | P1 | `foundation` | WF-1 + WF-7 | bridged | Forwarder active -> `foundation/tools/auth.hpp` |
| `AMBase/tools/enum_related.hpp` | 6 | P1 | `foundation` | WF-1 + WF-7 | bridged | Forwarder active -> `foundation/tools/enum_related.hpp` |
| `AMBase/tools/bar.hpp` | 5 | P1 | `foundation` | WF-1 + WF-7 | bridged | Forwarder active -> `foundation/tools/bar.hpp` |
| `AMBase/tools/string.hpp` | 3 | P2 | `foundation` | WF-1 + WF-7 | bridged | Forwarder active -> `foundation/tools/string.hpp` |
| `AMBase/RustTomlRead.h` | 1 | P2 | `foundation` or `infrastructure` | WF-1/WF-2 + WF-7 | bridged | Forwarder active -> `foundation/RustTomlRead.h` |

## AMManager split (WF-2/WF-3/WF-5 with WF-7 compatibility tracking)

| Legacy Header | Ref Count | Priority | Target Layer | Owner | Status | Notes |
|---|---:|---|---|---|---|---|
| `AMManager/Config.hpp` | 17 | P0 | `infrastructure` | WF-2 + WF-7 | bridged | Forwarder active -> `infrastructure/Config.hpp` |
| `AMManager/Prompt.hpp` | 15 | P0 | `interface` | WF-5 + WF-7 | legacy | CLI prompt and formatting concerns |
| `AMManager/Client.hpp` | 11 | P0 | `domain` | WF-3 + WF-7 | legacy | Domain-facing client/session behavior |
| `AMManager/Host.hpp` | 10 | P0 | `domain` | WF-3 + WF-7 | legacy | Host model and operations |
| `AMManager/Var.hpp` | 8 | P1 | `domain` | WF-3 + WF-7 | legacy | Runtime/user variable model |
| `AMManager/Transfer.hpp` | 5 | P1 | `domain` | WF-3 + WF-7 | legacy | Transfer orchestration/domain service |
| `AMManager/SignalMonitor.hpp` | 5 | P1 | `infrastructure` | WF-2 + WF-7 | bridged | Forwarder active -> `infrastructure/SignalMonitor.hpp` |
| `AMManager/FileSystem.hpp` | 3 | P2 | `domain` | WF-3 + WF-7 | legacy | Filesystem domain operations |
| `AMManager/Logger.hpp` | 3 | P2 | `infrastructure` | WF-2 + WF-7 | bridged | Forwarder active -> `infrastructure/Logger.hpp` |

## AMCLI -> interface (WF-5 with WF-7 compatibility tracking)

| Legacy Header | Ref Count | Priority | Target Layer | Owner | Status | Notes |
|---|---:|---|---|---|---|---|
| `AMCLI/InteractiveLoop.hpp` | 5 | P1 | `interface` | WF-5 + WF-7 | legacy | Core CLI loop contract |
| `AMCLI/TokenTypeAnalyzer.hpp` | 5 | P1 | `interface` | WF-5 + WF-7 | legacy | Parser/token analysis |
| `AMCLI/CommandTree.hpp` | 5 | P1 | `interface` | WF-5 + WF-7 | legacy | Command schema metadata |
| `AMCLI/Completer/Engine.hpp` | 5 | P1 | `interface` | WF-5 + WF-7 | legacy | Completion runtime engine |
| `AMCLI/Completer/Proxy.hpp` | 5 | P1 | `interface` | WF-5 + WF-7 | legacy | Completion facade |
| `AMCLI/CLIArg.hpp` | 4 | P1 | `interface` | WF-5 + WF-7 | legacy | CLI context argument contracts |
| `AMCLI/Completer/Searcher.hpp` | 4 | P1 | `interface` | WF-5 + WF-7 | legacy | Completion searcher contract |
| `AMCLI/CLIBind.hpp` | 3 | P2 | `interface` | WF-5 + WF-7 | legacy | Command binding/dispatch |
| `AMCLI/Completer/SearcherCommon.hpp` | 3 | P2 | `interface` | WF-5 + WF-7 | legacy | Shared searcher helpers |
| `AMCLI/CommandPreprocess.hpp` | 2 | P2 | `interface` | WF-5 + WF-7 | legacy | Input pre-processing |

## AMClient split (WF-2/WF-3 with WF-7 compatibility tracking)

| Legacy Header | Ref Count | Priority | Target Layer | Owner | Status | Notes |
|---|---:|---|---|---|---|---|
| `AMClient/IOCore.hpp` | 7 | P1 | `infrastructure` + domain ports | WF-2/WF-3 + WF-7 | legacy | Adapter entry used by transfer/filesystem |
| `AMClient/Base.hpp` | 5 | P1 | `domain` port + infrastructure impl | WF-2/WF-3 + WF-7 | legacy | Base client contracts and shared state |
| `AMClient/SFTP.hpp` | 2 | P2 | `infrastructure` | WF-2 + WF-7 | legacy | SFTP concrete adapter |
| `AMClient/FTP.hpp` | 1 | P2 | `infrastructure` | WF-2 + WF-7 | legacy | Blocked: no layered replacement header yet |
| `AMClient/Local.hpp` | 1 | P2 | `infrastructure` | WF-2 + WF-7 | legacy | Blocked: no layered replacement header yet |

## Forwarder Audit (2026-03-04)

Confirmed compatibility forwarders:

- `AMBase/*` and `AMBase/tools/*` legacy headers forward to `foundation/*`.
- `AMManager/Config.hpp` forwards to `infrastructure/Config.hpp`.
- `AMManager/Logger.hpp` forwards to `infrastructure/Logger.hpp`.
- `AMManager/SignalMonitor.hpp` forwards to
  `infrastructure/SignalMonitor.hpp`.

## WF7-C Snapshot (2026-03-04)

Source: `pwsh -NoProfile -ExecutionPolicy Bypass -File tools/report_legacy_includes.ps1 -RepoRoot .`
Snapshot file: `md/refactor_wf7_legacy_include_snapshot.md`
Regression check: `pwsh -NoProfile -ExecutionPolicy Bypass -File tools/check_wf7_cutover.ps1 -RepoRoot .`

- Prefix totals:
  - `AMBase`: 0
  - `AMManager`: 52
  - `AMCLI`: 41
  - `AMClient`: 16
- Bridged families with zero first-party legacy include usage:
  - `AMBase/*`
  - `AMManager/{Config,Logger,SignalMonitor}.hpp`

## Cutover Gates

- Do not mark a header `migrated` until:
  - all first-party callers use layered includes,
  - the corresponding layered contract is stable,
  - rollback path is documented in WF-7 cutover schedule.
