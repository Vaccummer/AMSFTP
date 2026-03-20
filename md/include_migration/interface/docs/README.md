# interface

Canonical interface-layer contracts for CLI-facing behavior:

- `interface/cli/CLIArg.hpp`
- `interface/cli/CLIBind.hpp`
- `interface/parser/CommandPreprocess.hpp`
- `interface/parser/CommandTree.hpp`
- `interface/cli/InteractiveLoop.hpp`
- `interface/prompt/Prompt.hpp`
- `interface/parser/TokenTypeAnalyzer.hpp`
- `interface/completion/*`
- `interface/adapters/ApplicationAdapters.hpp`

Legacy `AMCLI/*` headers are compatibility forwarders to these paths.
Legacy manager dependencies are intentionally isolated in `src/interface/*`
adapter implementations.
