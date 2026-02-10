
# AMConfigManager Improvement Plan

The current `ConfigManager` class contains too many member functions, resulting in excessive responsibilities, poor maintainability, and high cognitive load. To address this, we propose a clean separation into **four distinct layers** while preserving backward compatibility through an append-only approach (no modification to existing code during initial refactoring).

## Proposed Layered Architecture

### 1. **ConfigStorage** – Low-level I/O Layer

*Responsible for raw config data persistence and thread-safe file operations*

- Maintains underlying config data structures
- Implements `dump()` for serialization
- Supports key-value queries/writes via `std::vector<std::string>` path notation
- Handles automatic backup mechanisms
- Manages background file-writing thread

*Member variable name in facade:* `storage_`

### 2. **ConfigDataAccess** – Data Access & Preprocessing Layer

*Split into two peer sub-layers with orthogonal responsibilities:*

#### 2.1 **ConfigCoreData** – Non-style Data Access

*Handles business-logic config entities*

- Manages `History`, `HostConfig`, and other non-styling data
- Provides typed accessors and validators for core configuration

*Member variable name in facade:* `core_data_`

#### 2.2 **ConfigStyleData** – Style Data Access

*Handles UI/style-related configuration*

- Reads/writes progress bar styles, table styles
- Provides string styling helpers (e.g., colorization, formatting)

*Member variable name in facade:* `style_data_`

### 3. **ConfigCLIAdapter** – CLI Exposure Layer

*Pure interface layer for command-line binding*

- Exposes all CLI-bound functions with clean, narrow interfaces
- Translates CLI arguments into internal operations
- Contains no business logic – delegates to lower layers

*Member variable name in facade:* `cli_adapter_`

### 4. **ConfigManager** – Public Facade (Top Layer)

*Minimal coordinator preserving existing public API*

- Holds instances of the four new components via composition
- Exposes only `init()` and legacy-compatible public methods (delegating internally)
- Serves as migration bridge during incremental refactoring

```cpp
class ConfigManager {
    ConfigStorage storage_;
    ConfigCoreData core_data_;
    ConfigStyleData style_data_;
    ConfigCLIAdapter cli_adapter_;
public:
    bool init();  // Orchestrates initialization of all subcomponents
    // Legacy methods delegate to subcomponents (append-only)
};
```

## Implementation Strategy (Append-Only)

1. **Phase 1**: Implement new classes *alongside* existing `ConfigManager` without modifying current code
2. **Phase 2**: Gradually migrate internal logic into new layers while maintaining original behavior
3. **Phase 3**: Update call sites incrementally; original interface remains functional throughout

> ✅ **Key constraint**: All changes must be *append-only* – no deletion/modification of existing functions until full migration validation is complete. New functionality is added via composition without breaking existing clients.
>
