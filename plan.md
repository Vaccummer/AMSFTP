
**Concrete Plan**

1. Define a typed style payload model in interface layer.
   Files: [StyleModel.hpp](d:/CodeLib/CPP/AMSFTP/include/interface/style/StyleModel.hpp), [StyleModel.cpp](d:/CodeLib/CPP/AMSFTP/src/interface/style/StyleModel.cpp)
   Model split:

- Fixed schema sections: `CompleteMenu`, `Table`, `ProgressBar`, `CLIPrompt.templete/template`, `CLIPrompt.icons`, `InputHighlight`, `ValueQueryHighlight`, `Path`.
- Dynamic section: `CLIPrompt.shortcut` as `std::map<std::string, std::string>` (runtime keys).
- Keep `Json extras` for unknown keys so dump is round-trip safe.

2. Implement `AMStyleManager` in interface layer with init arg `std::shared_ptr<AMConfigSyncPort>`.
   Files: [StyleManager.hpp](d:/CodeLib/CPP/AMSFTP/include/interface/style/StyleManager.hpp), [StyleManager.cpp](d:/CodeLib/CPP/AMSFTP/src/interface/style/StyleManager.cpp)
   Core API:

- `ECM Init(std::shared_ptr<AMConfigSyncPort> port)`
- `std::string Format(...)`
- `std::string FormatUtf8Table(...)`
- `AMProgressBar CreateProgressBar(...)`
- optional prompt helpers: `ResolveCorePromptTemplate()`, `ResolveHistorySearchPrompt()`, `ResolveShortcutStyle(name)`.

3. In `Init`, load JSON from sync port, parse to typed state, normalize/clamp, then register dump callback.
   Callback shape:

- `port->RegisterDumpCallback([this](Json &j){ j = snapshot_.ToJson(); });`
  This satisfies “register dump callback to AMConfigSyncPort”.

4. Wire manager lifecycle in bootstrap before prompt init.
   Likely edits: [AppHandle.hpp](d:/CodeLib/CPP/AMSFTP/include/bootstrap/AppHandle.hpp), [CLIArg.hpp](d:/CodeLib/CPP/AMSFTP/include/interface/CLIArg.hpp), [CliManagersBootstrap.cpp](d:/CodeLib/CPP/AMSFTP/src/bootstrap/CliManagersBootstrap.cpp), [main.cpp](d:/CodeLib/CPP/AMSFTP/main.cpp)
   Flow:

- `config_manager.Init()`
- `style_port = config_manager.CreateOrGetSyncPort(DocumentKind::Settings, {"Style"}, Json::object())`
- `style_manager.Init(style_port)`
- then `prompt_manager.Init()`.

5. Expose style manager through runtime bindings and migrate call sites.
   Files: [ApplicationAdapters.hpp](d:/CodeLib/CPP/AMSFTP/include/interface/ApplicationAdapters.hpp), [RuntimeBindings.cpp](d:/CodeLib/CPP/AMSFTP/src/bootstrap/RuntimeBindings.cpp)
   Then migrate existing readers in:

- [InteractiveLoop.cpp](d:/CodeLib/CPP/AMSFTP/src/interface/InteractiveLoop.cpp)
- [PromptApi.cpp](d:/CodeLib/CPP/AMSFTP/src/interface/prompt/PromptApi.cpp)
- [TransferPrint.cpp](d:/CodeLib/CPP/AMSFTP/src/interface/transfer/TransferPrint.cpp)

**Questions Before I Implement**

1. Do you want full migration now (all style reads go through `StyleManager`) or staged migration (new manager + compatibility wrappers first)? no change or migration, implement this class first
2. For prompt template key, should dump always write canonical `template` and still read legacy `templete`? if there's spell errors in any file, correct it and tell me
3. Should I update `settings.schema.json` in this task, or keep schema changes separate? leave schema alone

**Extra Demmand**

leave schema alone and now don't concern with compatability problem, implement this class first
