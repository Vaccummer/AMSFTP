# src/interface

Interface implementation is organized by capability folders:

- `adapters/*`: application/domain gateway implementations.
- `cli/*`: CLI argument binding and interactive loop runtime.
- `parser/*`: input preprocessing, token/type analysis, and command tree.
- `completion/*`, `completion/search/*`: completion orchestration and searchers.
- `prompt/*`: prompt API/CLI/profile/guards.
- `style/*`: style service runtime.
- `commands/transfer/*`, `commands/var/*`: command-facing transfer/var actions.

Header contracts are published under matching `include/interface/<capability>/*` paths.
