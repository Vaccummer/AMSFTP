## Optimize AMSFTPCli.cpp

- Each command function should have its own dedicated parameter `struct`.
- Replace `CliOptions` with `CliArgsPool`, which stores parameter `struct`s for all command functions.
  for example

```cpp
CliArgsPool {
    auto ls = ConfigLsArgs {
        path,          // Target path
        list_like,     // List-like output mode
        show_all       // Show hidden entries
        // Excluded fields:
        // - interrupt_flag: internal control mechanism, not a user-facing parameter
        // - timeout_ms: redundant since operations can be terminated anytime via interrupt
    };
};
```

- Extract argument binding logic into a separate header file: `AMCLIBind.hpp`.
- Encapsulate a dispatch function with the following signature:

  - **Parameters**:
    - `cli_commands`: parsed command structure from CLI11
    - A `struct` containing `shared_ptr`s to all required managers (e.g., `AMFileSystem`, `ClientManager`, etc.)
  - **Behavior**: Executes the appropriate operation based on the command type
  - **Return type**: `void` (temporary design; may evolve to return execution status later)
