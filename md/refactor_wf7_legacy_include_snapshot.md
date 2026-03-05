# WF-7 Legacy Include Snapshot

Date: 2026-03-04

Command:

`pwsh -NoProfile -ExecutionPolicy Bypass -File tools/report_legacy_includes.ps1 -RepoRoot . -AsMarkdown`

## Header Counts

| Header | Prefix | Include Count |
|---|---|---:|
| AMManager/Prompt.hpp | AMManager | 15 |
| AMManager/Client.hpp | AMManager | 11 |
| AMManager/Host.hpp | AMManager | 10 |
| AMManager/Var.hpp | AMManager | 8 |
| AMClient/IOCore.hpp | AMClient | 7 |
| AMCLI/CommandTree.hpp | AMCLI | 5 |
| AMCLI/Completer/Engine.hpp | AMCLI | 5 |
| AMCLI/Completer/Proxy.hpp | AMCLI | 5 |
| AMCLI/InteractiveLoop.hpp | AMCLI | 5 |
| AMCLI/TokenTypeAnalyzer.hpp | AMCLI | 5 |
| AMClient/Base.hpp | AMClient | 5 |
| AMManager/Transfer.hpp | AMManager | 5 |
| AMCLI/CLIArg.hpp | AMCLI | 4 |
| AMCLI/Completer/Searcher.hpp | AMCLI | 4 |
| AMCLI/CLIBind.hpp | AMCLI | 3 |
| AMCLI/Completer/SearcherCommon.hpp | AMCLI | 3 |
| AMManager/FileSystem.hpp | AMManager | 3 |
| AMCLI/CommandPreprocess.hpp | AMCLI | 2 |
| AMClient/SFTP.hpp | AMClient | 2 |
| AMClient/FTP.hpp | AMClient | 1 |
| AMClient/Local.hpp | AMClient | 1 |
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
| AMManager/Config.hpp | AMManager | 0 |
| AMManager/Logger.hpp | AMManager | 0 |
| AMManager/SignalMonitor.hpp | AMManager | 0 |

## Prefix Totals

| Prefix | Total Include Count |
|---|---:|
| AMBase | 0 |
| AMCLI | 41 |
| AMClient | 16 |
| AMManager | 52 |

## Notes

- This snapshot is the WF7-C baseline for caller migration.
- `AMBase` includes are at zero in first-party source/include trees.
- Next reduction focus is `AMManager` and `AMCLI` families.
