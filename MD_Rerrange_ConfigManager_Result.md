# ConfigManager Storage Refactor Draft

**Goal**
Build a clean storage layer that owns all persistence and raw data access. Higher layers handle domain logic, validation, and presentation.

**Target Layering**
- Storage: AMConfigStorage
- Core Data: AMConfigCoreData
- Style Data: AMConfigStyleData
- CLI Adapter: AMConfigCLIAdapter
- Facade: AMConfigManager (wires layers together, exposes a stable API)

**Proposed Storage API (Concrete Draft)**
```cpp
enum class DocumentKind { Config, Settings, KnownHosts, History };

struct DocumentState {
  std::filesystem::path path;
  std::filesystem::path schema_path;
  ConfigHandle* handle = nullptr;
  nlohmann::ordered_json json;
  std::mutex mtx;
  bool dirty = false;
};

class AMConfigStorage {
public:
  ECM Init(const std::filesystem::path& root_dir);
  ECM BindHandles(ConfigHandle* config, ConfigHandle* settings,
                  ConfigHandle* known_hosts, ConfigHandle* history);

  ECM LoadAll();
  ECM Load(DocumentKind kind);

  nlohmann::ordered_json Snapshot(DocumentKind kind) const;

  ECM Mutate(DocumentKind kind, std::function<void(nlohmann::ordered_json&)> fn,
             bool dump_now);

  ECM DumpAll();
  ECM Dump(DocumentKind kind);

  ECM BackupIfNeeded();
  void SubmitWriteTask(std::function<void()> task);

  void StartWriteThread();
  void StopWriteThread();
  void Close();
};
```
Notes:
- `Snapshot` returns a copy for readers to avoid long-held locks.
- `Mutate` is the only mutation entry point; it holds the document lock.
- `Dump` and `BackupIfNeeded` never perform business logic.

**AMConfigManager Method Mapping**
| AMConfigManager method | Target layer | Notes |
|---|---|---|
| `Instance()` | Facade | Singleton entry point. |
| `~AMConfigManager()` | Facade | Stops writer, closes handles. |
| `Init()` | Storage + Facade | Storage init/load + layer wiring. |
| `Dump()` | Storage | Delegates to `DumpAll()`. |
| `Format()` | Style Data | Pure styling. |
| `List()` | CLI Adapter | Delegates to CLI callbacks. |
| `ListName()` | CLI Adapter | Delegates to CLI callbacks. |
| `ListHostnames()` | Core Data | Reads config snapshot. |
| `PrivateKeys()` | Core Data | Reads config snapshot. |
| `FindKnownHost()` | Core Data | Reads known_hosts snapshot. |
| `UpsertKnownHost()` | Core Data | Mutates known_hosts via storage. |
| `BuildKnownHostCallback()` | Core Data | Uses known_hosts data. |
| `ProjectRoot()` | Storage | Storage owns root paths. |
| `GetClientConfig()` | Core Data | Builds domain object from config snapshot. |
| `CreateProgressBar()` | Style Data | Style-only. |
| `FormatUtf8Table()` | Style Data | Style-only. |
| `GetSettingInt()` | Core Data | Reads settings snapshot. |
| `ResolveArg()` | Core Data | Settings read + post-process rules. |
| `ResolveTimeoutMs()` | Core Data | Thin wrapper over `ResolveArg()`. |
| `ResolveRefreshIntervalMs()` | Core Data | Thin wrapper over `ResolveArg()`. |
| `ResolveHeartbeatInterval()` | Core Data | Thin wrapper over `ResolveArg()`. |
| `ResolveTraceNum()` | Core Data | Thin wrapper over `ResolveArg()`. |
| `GetSettingString()` | Core Data | Reads settings snapshot. |
| `GetUserVar()` | Core Data | Reads settings snapshot. |
| `ListUserVars()` | Core Data | Reads settings snapshot. |
| `SetUserVar()` | Core Data | Mutates settings via storage. |
| `RemoveUserVar()` | Core Data | Mutates settings via storage. |
| `Src()` | CLI Adapter | Delegates to CLI callbacks. |
| `Delete(std::string)` | CLI Adapter | Delegates to CLI callbacks. |
| `Delete(vector)` | CLI Adapter | Delegates to CLI callbacks. |
| `Rename()` | CLI Adapter | Delegates to CLI callbacks. |
| `Query(std::string)` | CLI Adapter | Delegates to CLI callbacks. |
| `Query(vector)` | CLI Adapter | Delegates to CLI callbacks. |
| `Add()` | CLI Adapter | Delegates to CLI callbacks. |
| `Modify()` | CLI Adapter | Delegates to CLI callbacks. |
| `ValidateNickname()` | Core Data | Domain validation. |
| `SetClientPasswordEncrypted()` | Core Data | Mutates config via storage. |
| `SetHostField()` | Core Data | Mutates config via storage. |
| `SetHostValue()` | Core Data | Parses + mutates config. |
| `LoadHistory()` | Core Data | Calls storage load. |
| `GetHistoryCommands()` | Core Data | Reads history snapshot. |
| `SetHistoryCommands()` | Core Data | Mutates history via storage. |
| `ResolveMaxHistoryCount()` | Core Data | Settings read + post-process. |
| `SubmitWriteTask()` | Storage | Direct write queue access. |
| `ConfigBackupIfNeeded()` | Storage | Backup scheduling only. |
| `QueryKey()` | Storage utility | Pure JSON traversal. |
| `SetKey()` | Storage utility | Pure JSON mutation helper. |
| `HostExists()` | Core Data | Reads config snapshot. |

**Notes / Migration Fit**
- `AMConfigStorage` already matches most of this API. The missing pieces are `DocumentKind`, `Snapshot()`, and `Mutate()` semantics.
- `AMConfigCoreData` currently contains history helpers and nickname validation; expand it to cover settings and config mutation paths.
- `AMConfigStyleData` should own style lookups and formatting utilities.
- `AMConfigCLIAdapter` remains a pure callback bridge.
