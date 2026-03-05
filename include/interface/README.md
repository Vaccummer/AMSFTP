# interface

Canonical interface-layer contracts for CLI-facing behavior:

- `interface/CLIArg.hpp`
- `interface/CLIBind.hpp`
- `interface/CommandPreprocess.hpp`
- `interface/CommandTree.hpp`
- `interface/InteractiveLoop.hpp`
- `interface/Prompt.hpp`
- `interface/TokenTypeAnalyzer.hpp`
- `interface/Completer/*`
- `interface/ApplicationAdapters.hpp`

Legacy `AMCLI/*` headers are compatibility forwarders to these paths.
Legacy manager dependencies are intentionally isolated in `src/interface/*`
adapter implementations.
