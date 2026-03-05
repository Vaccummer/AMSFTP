# WF-7 Legacy Include Snapshot

Date: 2026-03-05

Command:

`pwsh -NoProfile -ExecutionPolicy Bypass -File tools/report_legacy_includes.ps1 -RepoRoot . -AsMarkdown`

## Header Counts

| Header | Prefix | Include Count |
|---|---|---:|
| AMManager/Config.hpp | AMManager | 15 |
| AMManager/Client.hpp | AMManager | 10 |
| AMManager/Host.hpp | AMManager | 10 |
| AMManager/Transfer.hpp | AMManager | 6 |
| AMManager/FileSystem.hpp | AMManager | 4 |
| AMManager/SignalMonitor.hpp | AMManager | 3 |
| AMManager/Var.hpp | AMManager | 5 |
| AMManager/Logger.hpp | AMManager | 2 |
| AMBase/DataClass.hpp | AMBase | 0 |
| AMBase/Enum.hpp | AMBase | 0 |
| AMBase/Path.hpp | AMBase | 0 |
| AMBase/RustTomlRead.h | AMBase | 0 |
| AMBase/tools/auth.hpp | AMBase | 0 |
| AMBase/tools/bar.hpp | AMBase | 0 |
| AMBase/tools/enum_related.hpp | AMBase | 0 |
| AMBase/tools/json.hpp | AMBase | 0 |
| AMBase/tools/string.hpp | AMBase | 0 |
| AMBase/tools/time.hpp | AMBase | 0 |
| AMCLI/CLIArg.hpp | AMCLI | 0 |
| AMCLI/CLIBind.hpp | AMCLI | 0 |
| AMCLI/CommandPreprocess.hpp | AMCLI | 0 |
| AMCLI/CommandTree.hpp | AMCLI | 0 |
| AMCLI/Completer/Engine.hpp | AMCLI | 0 |
| AMCLI/Completer/Proxy.hpp | AMCLI | 0 |
| AMCLI/Completer/Searcher.hpp | AMCLI | 0 |
| AMCLI/Completer/SearcherCommon.hpp | AMCLI | 0 |
| AMCLI/InteractiveLoop.hpp | AMCLI | 0 |
| AMCLI/TokenTypeAnalyzer.hpp | AMCLI | 0 |
| AMClient/Base.hpp | AMClient | 0 |
| AMClient/FTP.hpp | AMClient | 0 |
| AMClient/IOCore.hpp | AMClient | 0 |
| AMClient/Local.hpp | AMClient | 0 |
| AMClient/SFTP.hpp | AMClient | 0 |
| AMManager/Prompt.hpp | AMManager | 0 |

## Prefix Totals

| Prefix | Total Include Count |
|---|---:|
| AMBase | 0 |
| AMCLI | 0 |
| AMClient | 0 |
| AMManager | 55 |

## Notes

- This snapshot reflects WF5 interface-header decoupling plus runtime adapter extraction for completer/highlighter/searcher flows.
- `AMCLI` includes are zero and `AMManager/Prompt.hpp` include usage remains zero.
- `src/interface/{TokenTypeAnalyzer,searcher/internal_searcher,searcher/path_searcher,completer/engine_skeleton}` no longer include `AMManager/*`.
- `src/interface/CLIArg.cpp` no longer includes `AMManager/FileSystem.hpp`; filesystem command calls now route through `interface/ApplicationAdapters::FileCommandGateway`.
- `src/interface/PromptGuards.cpp` now routes signal-hook toggles through `interface/ApplicationAdapters::Runtime` and no longer includes `AMManager/SignalMonitor.hpp` directly.
- Remaining `AMManager/*` includes are concentrated in `main.cpp` bootstrap
  wiring and `src/manager/*` compatibility/legacy implementation paths.
