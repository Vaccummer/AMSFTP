## CLI Improvements (Rearranged)

### Targets / Files

- `src/manager/Config.cpp`
- `src/manager/FileSystem.cpp`
- `include/AMCLI/CLIBind.hpp`
- New file: `src/cli/CLIBind.cpp` (move implementations out of header)

---

### Behavior Notes

- After a successful connection via `sftp`,  `ftp`, or `connect`, call ch inside the function to change to that client
- In non-interactive mode, CLI11 cannot print usage with `-h`; it returns:
  "This should be caught in your main function, see examples".

---

### Refactor: CLI Binding Layout

- Create `CLIBind.cpp` and move concrete implementations from `CLIBind.hpp` into it.
- Store a pointer to the CLI `App` object inside `CliCommands`.
- In `DispatchCliCommands`, compute `const bool any_parsed = ...` using `app.get_subcommands()` (see CLI11 header for method).
- Decompose `BindCliOptions` into dedicated functions and call them:
  - bind `config`
  - bind `client`
  - bind filesystem-related commands not belonging to a module
  - bind `task`

---

### Config Module Changes

> PS: within `add_subcommand`, try to group related functions together.

- Rename `config ls -d` to `-l, --list` (same behavior).
- Add `config set` (non-interactive):
  - Usage: `config set <nickname> <property_name> <property_value>`
  - Exactly 3 string args; parse inside `SetHostValue`.
  - Errors if:
    - nickname does not exist
    - property name invalid/unsupported
    - property value malformed/invalid
  - Success message: `wsl.username: am -> haha`
- Bind `config save` to `dump` (no args).

---

### Host Config Fields

- Add new field `compression` to host config.
  - if not set to bool true, set false and write back
- Maintain consistent field ordering in print/prompt.(string-only input with validation?)

Example (field order matters):

```
nickname="wsl"
hostname="172.26.36.83"
username="am"
port=22
password="enc:70746B72"
protocol="sftp"
buffer_size=-1
trash_dir="/home/am/trash"
login_dir="/home/am"
keyfile=""
compression=false
```

---

### Client Subcommand

- Add top-level `client` subcommand (similar to `config` and `task`).
- 
- Under `client`, define:
  - `ls` (supports `-l, --list`)
    - corresponds to original:
      ```cpp
      commands.clients_cmd = app.add_subcommand("clients", "List client names");
      commands.clients_cmd->add_flag("-d,--detail", args.clients.detail, "Show full status details");
      ```
  - `check`
    - corresponds to:
      ```cpp
      commands.check_cmd = app.add_subcommand("check", "Check client status");
      commands.check_cmd->add_option("nicknames", args.check.nicknames, "Client nicknames")->expected(0, -1);
      ```
  - `rm`
    - corresponds to original `disconnect`:
      ```cpp
      commands.disconnect_cmd = app.add_subcommand("disconnect", "Disconnect clients");
      commands.disconnect_cmd->add_option("nicknames", args.disconnect.nicknames, "Client nicknames to disconnect")->expected(1, -1);
      ```

remove ori clients/check/disconnect bind

---

### Task Command Updates (Consistency)

```
commands.task_list_cmd = commands.task_cmd->add_subcommand("list", "List tasks");
commands.task_inspect_cmd = commands.task_cmd->add_subcommand("inspect", "Inspect a task");
```

```
commands.task_userset_cmd
  ->add_option("index", args.task_userset.index, "Cache index")
  ->expected(0, -1);
```

- Accept any number of indices; deduplicate before processing.
- If no index provided, print all cached usersets.

```
commands.task_taskentry_cmd =
  commands.task_cmd->add_subcommand("taskentry", "Inspect task entry");
commands.task_taskentry_cmd->add_option("id", args.task_entry.id, "Entry ID")
  ->required()
  ->expected(1, 1);
```

- Rename `taskentry` to `query`.
- Accept one or more entry IDs (`expected(1, -1)`).
