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
| `AMManager/Prompt.hpp` | 15 | P0 | `interface` | WF-5 + WF-7 | bridged | Forwarder active -> `interface/Prompt.hpp` |
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
| `AMCLI/InteractiveLoop.hpp` | 5 | P1 | `interface` | WF-5 + WF-7 | bridged | Forwarder active -> `interface/InteractiveLoop.hpp` |
| `AMCLI/TokenTypeAnalyzer.hpp` | 5 | P1 | `interface` | WF-5 + WF-7 | bridged | Forwarder active -> `interface/TokenTypeAnalyzer.hpp` |
| `AMCLI/CommandTree.hpp` | 5 | P1 | `interface` | WF-5 + WF-7 | bridged | Forwarder active -> `interface/CommandTree.hpp` |
| `AMCLI/Completer/Engine.hpp` | 5 | P1 | `interface` | WF-5 + WF-7 | bridged | Forwarder active -> `interface/Completer/Engine.hpp` |
| `AMCLI/Completer/Proxy.hpp` | 5 | P1 | `interface` | WF-5 + WF-7 | bridged | Forwarder active -> `interface/Completer/Proxy.hpp` |
| `AMCLI/CLIArg.hpp` | 4 | P1 | `interface` | WF-5 + WF-7 | bridged | Forwarder active -> `interface/CLIArg.hpp` |
| `AMCLI/Completer/Searcher.hpp` | 4 | P1 | `interface` | WF-5 + WF-7 | bridged | Forwarder active -> `interface/Completer/Searcher.hpp` |
| `AMCLI/CLIBind.hpp` | 3 | P2 | `interface` | WF-5 + WF-7 | bridged | Forwarder active -> `interface/CLIBind.hpp` |
| `AMCLI/Completer/SearcherCommon.hpp` | 3 | P2 | `interface` | WF-5 + WF-7 | bridged | Forwarder active -> `interface/Completer/SearcherCommon.hpp` |
| `AMCLI/CommandPreprocess.hpp` | 2 | P2 | `interface` | WF-5 + WF-7 | bridged | Forwarder active -> `interface/CommandPreprocess.hpp` |

## AMClient split (WF-2/WF-3 with WF-7 compatibility tracking)

| Legacy Header | Ref Count | Priority | Target Layer | Owner | Status | Notes |
|---|---:|---|---|---|---|---|
| `AMClient/IOCore.hpp` | 7 | P1 | `infrastructure` + domain ports | WF-2/WF-3 + WF-7 | bridged | Forwarder active -> `infrastructure/client/runtime/IOCore.hpp` |
| `AMClient/Base.hpp` | 5 | P1 | `domain` port + infrastructure impl | WF-2/WF-3 + WF-7 | bridged | Forwarder active -> `infrastructure/client/common/Base.hpp` |
| `AMClient/SFTP.hpp` | 2 | P2 | `infrastructure` | WF-2 + WF-7 | bridged | Forwarder active -> `infrastructure/client/sftp/SFTP.hpp` |
| `AMClient/FTP.hpp` | 1 | P2 | `infrastructure` | WF-2 + WF-7 | bridged | Forwarder active -> `infrastructure/client/ftp/FTP.hpp` |
| `AMClient/Local.hpp` | 1 | P2 | `infrastructure` | WF-2 + WF-7 | bridged | Forwarder active -> `infrastructure/client/local/Local.hpp` |

## Forwarder Audit (2026-03-05)

Confirmed compatibility forwarders:

- `AMBase/*` and `AMBase/tools/*` legacy headers forward to `foundation/*`.
- `AMManager/Config.hpp` forwards to `infrastructure/Config.hpp`.
- `AMManager/Logger.hpp` forwards to `infrastructure/Logger.hpp`.
- `AMManager/SignalMonitor.hpp` forwards to
  `infrastructure/SignalMonitor.hpp`.
- `AMManager/Prompt.hpp` forwards to `interface/Prompt.hpp`.
- `AMCLI/*` forwards to `interface/*`.
- `AMClient/*` forwards to `infrastructure/client/*`.

## WF7-C Snapshot (2026-03-05)

Source: `pwsh -NoProfile -ExecutionPolicy Bypass -File tools/report_legacy_includes.ps1 -RepoRoot .`
Snapshot file: `md/refactor_wf7_legacy_include_snapshot.md`
Regression check: `pwsh -NoProfile -ExecutionPolicy Bypass -File tools/check_wf7_cutover.ps1 -RepoRoot .`

- Prefix totals:
  - `AMBase`: 0
  - `AMManager`: 55
  - `AMCLI`: 0
  - `AMClient`: 0
- Bridged families with zero first-party legacy include usage:
  - `AMBase/*`
  - `AMCLI/*`
  - `AMClient/*`
  - `AMManager/Prompt.hpp`

## Cutover Gates

- Do not mark a header `migrated` until:
  - all first-party callers use layered includes,
  - the corresponding layered contract is stable,
  - rollback path is documented in WF-7 cutover schedule.
