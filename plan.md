**Refactor Plan: `AMInfraConfigManager` -> domain `ConfigManager`**

1. **Create domain config model + API contracts**

- Add [DocumentKind.hpp](d:/CodeLib/CPP/AMSFTP/include/domain/config/DocumentKind.hpp) (move/define `DocumentKind` here).
- Add [ConfigManager.hpp](d:/CodeLib/CPP/AMSFTP/include/domain/config/ConfigManager.hpp).
- Add [ConfigManager.cpp](d:/CodeLib/CPP/AMSFTP/src/domain/config/ConfigManager.cpp).
- Define:
  - `using Path = std::vector<std::string>;`
  - `struct DocumentInitSpec { std::filesystem::path json_path; std::filesystem::path schema_path; std::string schema_data; };`
  - `struct DocumentState { std::filesystem::path json_path; std::filesystem::path schema_path; std::string schema_data; std::shared_ptr<AMInfraConfigHandlePort> handle; };`
- `AMDomainConfigManager` holds `std::unordered_map<DocumentKind, DocumentState> docs_` and non-owning `AMAsyncWriteSchedulerPort* writer_`.

2. **Define init API exactly around your requirement**

- `ECM Init(const std::unordered_map<DocumentKind, DocumentInitSpec>& specs, AMAsyncWriteSchedulerPort* writer);`
- Behavior:
  - Validate all required `DocumentKind` entries exist.
  - Persist `schema_data` into `DocumentState` always.
  - Initialize each underlying `SuperTomlHandle` using `schema_data` first; fallback to schema file read only when schema_data empty.

3. **Implement domain read/write API (SuperHandle-like + DocumentKind arg)**

- Add methods with same semantics as handle port, keyed by `DocumentKind`:
  - `bool GetJson(DocumentKind kind, Json* out) const;`
  - `bool ReadValue(DocumentKind kind, const Path& path, JsonValue* out) const;`
  - `bool WriteValue(DocumentKind kind, const Path& path, const JsonValue& value);`
  - `bool DeleteValue(DocumentKind kind, const Path& path);`
  - `bool GetSchemaJson(DocumentKind kind, std::string* out) const;`
  - `bool GetSchemaJson(DocumentKind kind, Json* out) const;`
- Add typed helpers:
  - `template<typename T> bool Resolve(DocumentKind, const Path&, T* out) const;`
  - `template<typename T> bool Set(DocumentKind, const Path&, const T& value);`

4. **Implement dump/load API with `DocumentKind` + `async`**

- Add:
  - `ECM Load(std::optional<DocumentKind> kind = std::nullopt, bool force = false);`
  - `ECM Dump(DocumentKind kind, bool async = false, const std::string& dst_path = "");`
  - `ECM DumpAll(bool async = false);`
- Async path:
  - If `async == true`, enqueue task through `writer_->Submit(...)`.
  - If writer missing/not running, execute synchronously.
- Keep error callback hook in domain manager:
  - `void SetDumpErrorCallback(std::function<void(ECM)> cb);`

5. **Make infra config layer a thin adapter/composer**

- Refactor [Config.hpp](d:/CodeLib/CPP/AMSFTP/include/infrastructure/Config.hpp):
  - Remove storage-heavy responsibilities from `AMInfraConfigStorage`.
  - Keep style/UI helpers (`Format`, `CreateProgressBar`, `FormatUtf8Table`) in infra manager.
  - Compose domain manager instance instead of owning raw docs map.
- Refactor [io_base.cpp](d:/CodeLib/CPP/AMSFTP/src/infrastructure/config/io_base.cpp):
  - Build `DocumentInitSpec` map and call domain `Init`.
  - Delegate `ResolveArg/SetArg/DelArg/GetJson/GetJsonStr/Dump/Load` to domain manager.

6. **Preserve existing external behavior during transition**

- Keep existing public methods in infra config manager as passthrough wrappers so current callers (including logger) do not break.
- Do not refactor logger in this stage; it continues calling `SubmitWriteTask(...)` on config manager wrapper.

7. **Schema handling rules**

- `DocumentState::schema_data` is canonical runtime schema source.
- `schema_path` is treated as output/reference path for future hardcoded schema strategy.
- Add API: `bool GetSchemaData(DocumentKind kind, std::string* out) const;`

8. **File-level implementation order**

- First add domain files and compile-ready class skeleton.
- Then move `DocumentKind`.
- Then migrate core logic from infra `io_base.cpp` into domain `ConfigManager.cpp`.
- Then reduce infra `Config.hpp/io_base.cpp` to wrapper/delegation.
- Finally delete dead helpers from infra implementation.

9. **Acceptance criteria**

- Domain manager owns document map and schema string per doc.
- All JSON read/write operations require `DocumentKind`.
- Dump API supports `DocumentKind + async`.
- Async scheduler used only via `AMAsyncWriteSchedulerPort`.
- No behavior change for current logger/config call sites.

10. **Questions before conduct**
11. Should I move `DocumentKind` to domain now (`include/domain/config/DocumentKind.hpp`) and replace all current includes immediately? move but don't replace all
12. Preferred domain class name: `AMDomainConfigManager` or `AMConfigManager`? `AMConfigManager` but in domain namespace
