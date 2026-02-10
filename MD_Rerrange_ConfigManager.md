• Goal
  Build a clean storage layer that owns all persistence and raw data access, while higher layers do only domain logic and presentation.

  Standard Separation Plan (Storage-Centric)

    - Own all file paths, schema paths, cfgffi handles, and JSON blobs.
      - Provide thread-safe load, read snapshots, mutation, and dump.
      - Run a single background writer thread with a queue.
      - Perform backups and recovery/repair if configured.
      - Never contain business rules, validation, or formatting.
  2. Design the Storage API (Minimal, Stable)
      - Init(root_dir, paths, schemas)
      - LoadAll() and Load(DocumentKind)
      - Mutate(DocumentKind, Fn mutator, bool dump_now)
      - DumpAll() and Dump(DocumentKind)
      - BackupIfNeeded()
      - Close()
  3. Model Internal Storage State
      - struct DocumentState { path, schema_path, ConfigHandle*, Json, mutex, dirty }
      - enum class DocumentKind { Config, Settings, KnownHosts, History }
      - unordered_map<DocumentKind, DocumentState> docs_
  4. Threading Rules
      - All mutation goes through Mutate() which locks per-document.
      - Writer thread executes queued tasks only; no direct business logic.
  5. Error Strategy
      - Use ECM everywhere.
      - Convert cfgffi and filesystem errors into consistent EC codes.
      - Never throw from storage; return ECM.
  6. Higher Layer Boundaries
      - AMConfigCoreData reads from storage_.Snapshot() and validates, builds domain objects, and writes via storage_.Mutate().
      - AMConfigStyleData reads style data only; no file access.
      - AMConfigCLIAdapter is just an interface, calls facade.
  Migration Strategy

1. Implement AMConfigStorage in isolation with tests for Load/Dump.
2. Wire AMConfigManager::Init() to call storage_.Init() and LoadAll().
3. Redirect read-only methods to storage snapshots.
4. Redirect mutators to storage Mutate() and Dump()/SubmitWriteTask().
5. Move history handling next.
6. Move known_hosts logic next.
7. Remove duplicated state after parity is proven.

draft a concrete storage API and map each existing AMConfigManager method to one of these layers.
write in a md file
