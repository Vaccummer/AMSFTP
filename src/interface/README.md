# src/interface

WF-5 note: CLI implementation now lives in `src/interface/*`
(`CLI*`, `Completer/*`, `PromptGuards`) with canonical contracts in
`include/interface/*` and compatibility forwarders in `AMCLI/*` and
`AMManager/Prompt.hpp`.

Current interface adapters:

- `PromptGuards.cpp`: signal-hook guard behavior for prompt lifecycle,
  kept manager-header-free in interface.
- `CLIArg.cpp`, `CLIBind.cpp`, `CommandPreprocess.cpp`, `command_tree.cpp`,
  `InteractiveLoop.cpp`, `TokenTypeAnalyzer.cpp`: canonical CLI behavior.
- `completer/*`, `searcher/*`: canonical completion and search behavior.

Interface compatibility boundary (legacy manager-backed):

- `src/manager/ApplicationAdaptersCompat.cpp`: bridges workflow ports
  (`application/*`) to compatibility manager implementations.
- `src/manager/CliManagersCompat.cpp`: manager-bundle initializer over explicit
  references; singleton lookup is bootstrap-side in `main.cpp`.

Header-level decoupling:

- `PromptGuards.cpp` avoids direct manager headers by using
  `include/interface/Prompt.hpp` to avoid header-level manager dependency.
