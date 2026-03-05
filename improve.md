
**Cleanup Goal**
Remove **src/manager** as a legacy catch-all by relocating each file to its owning layer, with zero behavior change first, then structural cleanup.

**Current Facts**

1. **src/manager** still contains 15 files (client/host/transfer/var/prompt + 2 compat files).
2. Current guardrail blockers are only:
   * [TransferManager.hpp](https://file+.vscode-resource.vscode-cdn.net/c%3A/Users/am/.vscode/extensions/openai.chatgpt-0.4.74-win32-x64/webview/# "/d:/CodeLib/CPP/AMSFTP/include/domain/transfer/TransferManager.hpp (line 5)") (**domain -> infrastructure**)
   * [InteractiveLoop.cpp](https://file+.vscode-resource.vscode-cdn.net/c%3A/Users/am/.vscode/extensions/openai.chatgpt-0.4.74-win32-x64/webview/# "/d:/CodeLib/CPP/AMSFTP/src/interface/InteractiveLoop.cpp (line 8)") (**interface -> infrastructure**)
3. **check_wf7_cutover** passes.

**Final Cleanup Plan**

1. **Phase 0: Freeze Contracts (no file moves yet)**
   * Make canonical ownership explicit:
     * [ClientPort.hpp](https://file+.vscode-resource.vscode-cdn.net/c%3A/Users/am/.vscode/extensions/openai.chatgpt-0.4.74-win32-x64/webview/# "include/domain/client/ClientPort.hpp") (canonical client port)
     * [{HostModel,KnownHostQuery}.hpp](https://file+.vscode-resource.vscode-cdn.net/c%3A/Users/am/.vscode/extensions/openai.chatgpt-0.4.74-win32-x64/webview/# "include/domain/host/{HostModel,KnownHostQuery}.hpp") (canonical host models)
     * [VarModel.hpp](https://file+.vscode-resource.vscode-cdn.net/c%3A/Users/am/.vscode/extensions/openai.chatgpt-0.4.74-win32-x64/webview/# "include/domain/var/VarModel.hpp") (canonical var model)
   * Keep temporary forwarders only where needed.
   * Done criteria:
     * No first-party include uses [VarModel}.hpp](https://file+.vscode-resource.vscode-cdn.net/c%3A/Users/am/.vscode/extensions/openai.chatgpt-0.4.74-win32-x64/webview/# "foundation/{client/ClientPort,host/HostModel,host/KnownHostQuery,var/VarModel}.hpp") directly.
     * Only domain paths are canonical.
2. **Phase 1: Move **src/manager** files physically (path-only move, no logic change)**
   * Move to layer-owned locations:
     * [Operator.cpp](https://file+.vscode-resource.vscode-cdn.net/c%3A/Users/am/.vscode/extensions/openai.chatgpt-0.4.74-win32-x64/webview/# "src/manager/client/Operator.cpp") -> [ClientManagerOperator.cpp](https://file+.vscode-resource.vscode-cdn.net/c%3A/Users/am/.vscode/extensions/openai.chatgpt-0.4.74-win32-x64/webview/# "src/domain/client/ClientManagerOperator.cpp")
     * [PathOps.cpp](https://file+.vscode-resource.vscode-cdn.net/c%3A/Users/am/.vscode/extensions/openai.chatgpt-0.4.74-win32-x64/webview/# "src/manager/client/PathOps.cpp") -> [ClientManagerPathOps.cpp](https://file+.vscode-resource.vscode-cdn.net/c%3A/Users/am/.vscode/extensions/openai.chatgpt-0.4.74-win32-x64/webview/# "src/domain/client/ClientManagerPathOps.cpp")
     * [FileSystem.cpp](https://file+.vscode-resource.vscode-cdn.net/c%3A/Users/am/.vscode/extensions/openai.chatgpt-0.4.74-win32-x64/webview/# "src/manager/FileSystem.cpp") -> [FileSystemManager.cpp](https://file+.vscode-resource.vscode-cdn.net/c%3A/Users/am/.vscode/extensions/openai.chatgpt-0.4.74-win32-x64/webview/# "src/domain/filesystem/FileSystemManager.cpp")
     * [core.cpp](https://file+.vscode-resource.vscode-cdn.net/c%3A/Users/am/.vscode/extensions/openai.chatgpt-0.4.74-win32-x64/webview/# "src/manager/host/core.cpp") -> [HostManagerCore.cpp](https://file+.vscode-resource.vscode-cdn.net/c%3A/Users/am/.vscode/extensions/openai.chatgpt-0.4.74-win32-x64/webview/# "src/domain/host/HostManagerCore.cpp")
     * [cli.cpp](https://file+.vscode-resource.vscode-cdn.net/c%3A/Users/am/.vscode/extensions/openai.chatgpt-0.4.74-win32-x64/webview/# "src/manager/host/cli.cpp") -> [HostManagerCli.cpp](https://file+.vscode-resource.vscode-cdn.net/c%3A/Users/am/.vscode/extensions/openai.chatgpt-0.4.74-win32-x64/webview/# "src/domain/host/HostManagerCli.cpp")
     * [core.cpp](https://file+.vscode-resource.vscode-cdn.net/c%3A/Users/am/.vscode/extensions/openai.chatgpt-0.4.74-win32-x64/webview/# "src/manager/var/core.cpp") -> [VarManagerCore.cpp](https://file+.vscode-resource.vscode-cdn.net/c%3A/Users/am/.vscode/extensions/openai.chatgpt-0.4.74-win32-x64/webview/# "src/domain/var/VarManagerCore.cpp")
     * [cli.cpp](https://file+.vscode-resource.vscode-cdn.net/c%3A/Users/am/.vscode/extensions/openai.chatgpt-0.4.74-win32-x64/webview/# "src/manager/var/cli.cpp") -> [VarCli.cpp](https://file+.vscode-resource.vscode-cdn.net/c%3A/Users/am/.vscode/extensions/openai.chatgpt-0.4.74-win32-x64/webview/# "src/interface/var/VarCli.cpp")
     * [core.cpp](https://file+.vscode-resource.vscode-cdn.net/c%3A/Users/am/.vscode/extensions/openai.chatgpt-0.4.74-win32-x64/webview/# "src/manager/transfer/core.cpp") -> [TransferManagerCore.cpp](https://file+.vscode-resource.vscode-cdn.net/c%3A/Users/am/.vscode/extensions/openai.chatgpt-0.4.74-win32-x64/webview/# "src/domain/transfer/TransferManagerCore.cpp")
     * [cli.cpp](https://file+.vscode-resource.vscode-cdn.net/c%3A/Users/am/.vscode/extensions/openai.chatgpt-0.4.74-win32-x64/webview/# "src/manager/transfer/cli.cpp") -> [TransferCli.cpp](https://file+.vscode-resource.vscode-cdn.net/c%3A/Users/am/.vscode/extensions/openai.chatgpt-0.4.74-win32-x64/webview/# "src/interface/transfer/TransferCli.cpp")
     * [print.cpp](https://file+.vscode-resource.vscode-cdn.net/c%3A/Users/am/.vscode/extensions/openai.chatgpt-0.4.74-win32-x64/webview/# "src/manager/transfer/print.cpp") -> [TransferPrint.cpp](https://file+.vscode-resource.vscode-cdn.net/c%3A/Users/am/.vscode/extensions/openai.chatgpt-0.4.74-win32-x64/webview/# "src/interface/transfer/TransferPrint.cpp")
     * [api.cpp](https://file+.vscode-resource.vscode-cdn.net/c%3A/Users/am/.vscode/extensions/openai.chatgpt-0.4.74-win32-x64/webview/# "src/manager/prompt/api.cpp") -> [PromptApi.cpp](https://file+.vscode-resource.vscode-cdn.net/c%3A/Users/am/.vscode/extensions/openai.chatgpt-0.4.74-win32-x64/webview/# "src/interface/prompt/PromptApi.cpp")
     * [cli.cpp](https://file+.vscode-resource.vscode-cdn.net/c%3A/Users/am/.vscode/extensions/openai.chatgpt-0.4.74-win32-x64/webview/# "src/manager/prompt/cli.cpp") -> [PromptCli.cpp](https://file+.vscode-resource.vscode-cdn.net/c%3A/Users/am/.vscode/extensions/openai.chatgpt-0.4.74-win32-x64/webview/# "src/interface/prompt/PromptCli.cpp")
     * [profile.cpp](https://file+.vscode-resource.vscode-cdn.net/c%3A/Users/am/.vscode/extensions/openai.chatgpt-0.4.74-win32-x64/webview/# "src/manager/prompt/profile.cpp") -> [PromptProfile.cpp](https://file+.vscode-resource.vscode-cdn.net/c%3A/Users/am/.vscode/extensions/openai.chatgpt-0.4.74-win32-x64/webview/# "src/interface/prompt/PromptProfile.cpp")
     * [ApplicationAdaptersCompat.cpp](https://file+.vscode-resource.vscode-cdn.net/c%3A/Users/am/.vscode/extensions/openai.chatgpt-0.4.74-win32-x64/webview/# "src/manager/ApplicationAdaptersCompat.cpp") -> split later (Phase 3)
     * [CliManagersCompat.cpp](https://file+.vscode-resource.vscode-cdn.net/c%3A/Users/am/.vscode/extensions/openai.chatgpt-0.4.74-win32-x64/webview/# "src/manager/CliManagersCompat.cpp") -> split later (Phase 3)
   * Update includes/CMake paths only.
   * Done criteria:
     * **src/manager** contains only compat files or is empty.
     * No compile target references moved old paths.
3. **Phase 2: Namespace normalization for domain managers**
   * Wrap manager classes in **AMDomain::`<module>`** namespaces:
     * **AMClientManager**, **AMHostManager**, **AMTransferManager**, **AMVarManager**, **AMFileSystem**.
   * Keep temporary global aliases:
     * **using AMClientManager = AMDomain::client::ClientManager;** style.
   * Done criteria:
     * Canonical declarations are namespaced.
     * Existing call sites still compile via aliases.
4. **Phase 3: Split and relocate compat glue**
   * [ApplicationAdaptersCompat.cpp](https://file+.vscode-resource.vscode-cdn.net/c%3A/Users/am/.vscode/extensions/openai.chatgpt-0.4.74-win32-x64/webview/# "/d:/CodeLib/CPP/AMSFTP/src/manager/ApplicationAdaptersCompat.cpp"):
     * Interface workflow gateway implementations -> [ApplicationGateways.cpp](https://file+.vscode-resource.vscode-cdn.net/c%3A/Users/am/.vscode/extensions/openai.chatgpt-0.4.74-win32-x64/webview/# "src/interface/adapters/ApplicationGateways.cpp")
     * Runtime binding/static state (**Runtime::Bind/Reset/...**) -> [RuntimeBindings.cpp](https://file+.vscode-resource.vscode-cdn.net/c%3A/Users/am/.vscode/extensions/openai.chatgpt-0.4.74-win32-x64/webview/# "src/bootstrap/RuntimeBindings.cpp")
   * [CliManagersCompat.cpp](https://file+.vscode-resource.vscode-cdn.net/c%3A/Users/am/.vscode/extensions/openai.chatgpt-0.4.74-win32-x64/webview/# "/d:/CodeLib/CPP/AMSFTP/src/manager/CliManagersCompat.cpp"):
     * Move bootstrap wiring/init to [CliManagersBootstrap.cpp](https://file+.vscode-resource.vscode-cdn.net/c%3A/Users/am/.vscode/extensions/openai.chatgpt-0.4.74-win32-x64/webview/# "src/bootstrap/CliManagersBootstrap.cpp")
   * Done criteria:
     * No [*Compat.cpp](https://file+.vscode-resource.vscode-cdn.net/c%3A/Users/am/.vscode/extensions/openai.chatgpt-0.4.74-win32-x64/webview/# "*Compat.cpp") under **src/manager**.
     * Interface layer no longer includes infrastructure concrete headers directly.
5. **Phase 4: Eliminate the 2 remaining layer violations**
   * Fix **domain -> infrastructure**:
     * [TransferManager.hpp](https://file+.vscode-resource.vscode-cdn.net/c%3A/Users/am/.vscode/extensions/openai.chatgpt-0.4.74-win32-x64/webview/# "/d:/CodeLib/CPP/AMSFTP/include/domain/transfer/TransferManager.hpp") must not include [IOCore.hpp](https://file+.vscode-resource.vscode-cdn.net/c%3A/Users/am/.vscode/extensions/openai.chatgpt-0.4.74-win32-x64/webview/# "IOCore.hpp").
     * Introduce/consume domain port abstractions instead of concrete runtime types in header.
   * Fix **interface -> infrastructure**:
     * [InteractiveLoop.cpp](https://file+.vscode-resource.vscode-cdn.net/c%3A/Users/am/.vscode/extensions/openai.chatgpt-0.4.74-win32-x64/webview/# "/d:/CodeLib/CPP/AMSFTP/src/interface/InteractiveLoop.cpp") should read config/style through **ApplicationAdapters::Runtime** API only.
   * Done criteria:
     * [check_layers.ps1](https://file+.vscode-resource.vscode-cdn.net/c%3A/Users/am/.vscode/extensions/openai.chatgpt-0.4.74-win32-x64/webview/# "tools/check_layers.ps1") passes with 0 violations.
6. **Phase 5: Remove **src/manager** and legacy docs/scripts references**

* Delete **src/manager** tree.
* Remove **src/manager/*** globs from [CMakeLists.txt](https://file+.vscode-resource.vscode-cdn.net/c%3A/Users/am/.vscode/extensions/openai.chatgpt-0.4.74-win32-x64/webview/# "/d:/CodeLib/CPP/AMSFTP/CMakeLists.txt").
* Update status docs:
  * [WF6_STATUS.md](https://file+.vscode-resource.vscode-cdn.net/c%3A/Users/am/.vscode/extensions/openai.chatgpt-0.4.74-win32-x64/webview/# "/d:/CodeLib/CPP/AMSFTP/include/bootstrap/WF6_STATUS.md")
  * [WF7_STATUS.md](https://file+.vscode-resource.vscode-cdn.net/c%3A/Users/am/.vscode/extensions/openai.chatgpt-0.4.74-win32-x64/webview/# "/d:/CodeLib/CPP/AMSFTP/include/bootstrap/WF7_STATUS.md")
  * [include/infrastructure/README.md](https://file+.vscode-resource.vscode-cdn.net/c%3A/Users/am/.vscode/extensions/openai.chatgpt-0.4.74-win32-x64/webview/# "/d:/CodeLib/CPP/AMSFTP/include/infrastructure/README.md")
* Done criteria:
  * No **src/manager** paths in repo except migration history/docs.
  * **check_wf7_cutover** and **check_layers** both pass.

**Verification Checklist (each phase)**

1. **pwsh -NoProfile -ExecutionPolicy Bypass -File tools/check_layers.ps1 -RepoRoot .**
2. **pwsh -NoProfile -ExecutionPolicy Bypass -File tools/check_wf7_cutover.ps1 -RepoRoot .**
3. **pwsh -NoProfile -ExecutionPolicy Bypass -File tools/report_legacy_includes.ps1 -RepoRoot .**
4. No build run unless you explicitly request it.

**Execution Order Recommendation**

1. Phase 0
2. Phase 1
3. Phase 3
4. Phase 2
5. Phase 4
6. Phase 5

**Two decisions to confirm before execution**

1. Keep temporary global type aliases during Phase 2, or enforce namespace-only immediately?  this work may be finished, you can check it. if not, use enforce namespace-only
2. Keep [ClientFactory.hpp](https://file+.vscode-resource.vscode-cdn.net/c%3A/Users/am/.vscode/extensions/openai.chatgpt-0.4.74-win32-x64/webview/# "bootstrap/ClientFactory.hpp") as forwarder until final cleanup, or remove it in the same batch as Phase 3? remove it
