# Migration Plan: Refactor AMConfigManager into Layered Components

Migrate the majority of `AMConfigManager`'s member functions into four dedicated classes: `AMConfigStyleData`, `AMConfigCLIAdapter`, `AMConfigCoreData`, and `AMConfigStorage`. `AMConfigManager` will retain ownership of these components via composition (holding instances, not raw references for lifetime safety) and delegate calls to the appropriate layer.

`AMConfigStorage` requires further abstraction. Below is a refined design based on your reference code, with improvements for robustness, thread safety, and API clarity:

```cpp
enum class DocumentKind { Config, Settings, KnownHosts, History };

struct DocumentState {
  std::filesystem::path path;
  std::filesystem::path schema_path;
  ConfigHandle* handle = nullptr;
  nlohmann::ordered_json json;
  mutable std::mutex mtx;  // mutable for const-correct locking in Snapshot()
  bool dirty = false;
  std::chrono::system_clock::time_point last_modified;
};

class AMConfigStorage {
public:
  // Lifecycle
  ECM Init(const std::filesystem::path& root_dir,
           const std::unordered_map<DocumentKind, std::filesystem::path>& paths,
           const std::unordered_map<DocumentKind, std::filesystem::path>& schemas);
  
  ECM BindHandles(ConfigHandle* config, ConfigHandle* settings,
                  ConfigHandle* known_hosts, ConfigHandle* history);
  
  ECM LoadAll();
  ECM Load(DocumentKind kind);
  ECM Close();  // Graceful shutdown with final dump

  // Read operations (thread-safe snapshots)
  nlohmann::ordered_json Snapshot(DocumentKind kind) const;
  bool IsDirty(DocumentKind kind) const;

  // Mutation (thread-safe, supports deferred persistence)
  ECM Mutate(DocumentKind kind,
             std::function<void(nlohmann::ordered_json&)> mutator,
             bool dump_now = false);

  // Persistence
  ECM DumpAll();
  ECM Dump(DocumentKind kind);
  ECM BackupIfNeeded();

  // Writer thread management (typically called once during init/shutdown)
  void StartWriteThread();
  void StopWriteThread();  // Joins thread and flushes queue

private:
  // Thread-safe task submission (internal use)
  void SubmitWriteTask(std::function<ECM()> task);

  // Internal state
  std::filesystem::path root_dir_;
  std::unordered_map<DocumentKind, DocumentState> docs_;
  std::thread writer_thread_;
  std::mutex queue_mtx_;
  std::condition_variable queue_cv_;
  std::queue<std::function<ECM()>> write_queue_;
  std::atomic<bool> shutdown_requested_{false};
};
```
