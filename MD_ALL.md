
# Translation

Finally, all functions need to be bound to the CLI. Users can invoke the program in two ways:

## Direct CLI Invocation (Non-interactive Mode)

+ Invoked directly via terminal
+ Commands are parsed by CLI11
+ If a function needs to create a client during execution, it creates one directly without prompting the user
+ All functions involving network I/O must:
  - Set a timeout (read from settings, default 5 seconds)
  - Add an `interrupt_flag` (preferably a global static variable with a prefix to avoid naming conflicts)
+ Capture Ctrl-C signals and convert them to activating the `interrupt_flag` for graceful termination
+ Exit the program immediately after operation completion, with the exit code set to the function's return value

## Interactive Invocation

Not required for current implementation, but extensibility and compatibility must be considered for future support:

+ Use `replxx` prompt to receive user commands
+ Parse commands manually, maintaining full compatibility with all non-interactive mode commands
+ Rich auto-completion features:
  - Tab completes uniquely matched items
  - **Completion menu**
  - Command completion
  - Path completion:
    - Delay completion search for a short period after output stops
    - Load completion items asynchronously to avoid blocking normal input
+ Input history:
  - Maintain independent history records for different hosts
+ Additional special commands:
  - Commands starting with `!` execute shell commands (not supported by FTP client)
  - Commands ending with `&` run in background (supported by select functions)

## Non-interactive Mode

@amio.cpp

CLI binding can be implemented using the `CLI11.hpp` library. Refer to `amio.cpp` for concrete usage examples.

The program exits with the function's returned `exit_code`.

**Current is just the first version, remain some place for improve and new features**

Below are the functions requiring CLI binding:

### `config` (subcommand)

+ `ls`
  - `-d` (detail): calls `AMConfigManager::List()`
  - Without `-d`: calls `AMConfigManager::ListName()`
+ `keys`: calls `AMConfigManager::PrivateKeys()`
+ `data`: calls `AMConfigManager::Src()`
+ `get`: calls `AMConfigManager::Query()`
+ `add`: calls `AMConfigManager::Add()`
+ `edit`: calls `AMConfigManager::Modify()`
+ `rename`: calls `AMConfigManager::Rename()`
+ `rm`: calls `AMConfigManager::RemoveHost()`
  - Supports batch deletion with space-separated hostnames

### Filesystem-related Functions

No subcommand required; callable directly.

+ Support `{nickname}@{path}` path format. After creating the client, execute operations directly without user confirmation for client creation.
+ Support special paths containing spaces when wrapped in double quotes (`""`)
+ Set a global `interrupt_flag` to allow users to gracefully terminate the program
+ `stat`

  - Accepts multiple paths separated by spaces
+ `ls` (accepts only a single path)

  - `-l` → `list_like`
  - `-a` → `show_all`
+ `size`

  - Calls `AMFileSystem::getsize()`
  - Accepts multiple paths:
    - `path1: size1`
    - `path2: size2`
+ `find` (accepts only a single path)
+ `mkdir`

  - Accepts multiple paths
    - ❌ `{rc}: Fail to mkdir path1, {msg}`
    - ✅ `Success to mkdir path2`
+ `rm`

  - Supports multiple paths
  - Prints results in the same style as `mkdir`
  - New `permanent` parameter:
    - When `true`: calls client's `remove()` function
    - When `false`: calls client's `saferm()` function
    - `AMFileSystem::rm` requires enhancement to support this
+ `mv`

  - Maps to `move` operation
+ `rename`

  - Maps to `rename` operation
+ `tree`

  - `-d`: specify maximum traversal depth
  - `-a`: print hidden directories and files
    - Default `false`: excludes entries starting with `.`
+ `walk`

  - `-d`: print directories only
  - `-f`: print files only
+ `trashdir`

  - Without argument: prints current trash directory path
  - With argument: sets the trash directory
    - On success, updates the configuration accordingly
+ `buffersize`: behaves similarly to `trashdir`

+
@./tomlread

@include\AMConfigManager.hpp

@config\config.toml

@config\settings.toml

@tomlread\src\lib.rs

我现在需要改用rust的库来读取和写入toml文件, rs文件目录已给出, 目前还存在编译报错

I want use rust lib to read and write toml file, rs src dir is given above, but there's still compile error, correct it

error[E0382]: use of moved value: `item`
   --> src\lib.rs:460:17
    |
407 | fn apply_json_updates_append_new(item: &mut Item, j: &J) {
    |                                  ---- move occurs because `item` has type `&mut Item`, which does not implement the `Copy` trait
408 |     match (item, j) {
    |            ---- value moved here
...
460 |                 *item = new_item;
    |                 ^^^^^ value used here after move

I have nlohmann-json for json-parse

expose rust functions to C++, and use these functions to improve 

configprocessor in @include\base\AMCommonTools.hpp

produce a format json shcuema file
@src\AMConfigManager.cpp

@include\AMConfigManager.hpp

- Replace `AMConfigManager::Status` with the `ECM` type.

  - If no corresponding code exists in `EC`, create a new one.
- Remove redundant checks in `AMConfigManager::EnsureInitialized`.
- Move generic prompt-related functions from `AMConfigManager` to `PromptManager` (excluding format-customized functions like `PromptModifyFields`).
- Remove the redundant function `AMConfigManager::StyledValue`.
- Replace `AMConfigManager::MaybeStyle` with direct usage of `Format`.
- Add a new field `login_dir` to `ClientConfig`.
- `AMConfigManager::GetClientConfig` must read **all** fields from `ClientConfig`.

  - If a field is missing, assign its default value.
  - Persist these default values back to the config file.
- Provide two utility functions:

  ```cpp
  bool QueryKey(Settings/config, AMConfigProcessor::Path, &value) {
      // Match and retrieve the value at the specified path.
      // Return false if the path does not exist or the value type mismatches.
  }
  ```
  ```cpp
  template<typename T>
  bool SetKey(Settings/config, AMConfigProcessor::Path, T value) {
      // Set/modify the value at the specified path.
      // Create the path if it does not exist (template function).
  }
  ```
- Enhance `AMConfigManager::Delete` to accept **multiple targets** (space-separated).
- Enhance `AMConfigManager::Query` to accept **multiple targets** (space-separated).
@include\AMFileSystem.hpp

@src\AMFileSystem.cpp

## Optimize AMFileSystem

### move

+ Support multiple source paths
+ Options for `mkdir` (auto-create parent directories) and `overwrite`
+ Cross-client operations not allowed
+ Support for interrupt and timeout control

### rename

+ Accepts only one source and one destination path
+ If destination is in path format (detected by `/` or `\\`), rename source to the full destination path
+ If destination is not in path format, replace the source filename with the destination name
+ Cross-client operations not allowed
+ Options for `mkdir` and `overwrite`
+ Support for interrupt and timeout control

### walk

+ Actually delegates to the client's `iwalk`, printing all subpaths under a given path
+ Supports flags `-f` (files only) and `-d` (directories only)

### tree

+ Uses the client's `walk` to retrieve directory structure
+ Implements a function to print the hierarchy in Unix-style `tree` format

### realpath

+ Internally uses `AMFS::abspath`, but resolves home and working directory using the client's context

---

## Add Client Information Query Functions

If no client name is provided, query the current client; raise an error if the client hasn't been created.

+ `GetProtocol`
+ `TrashDir`
+ `HomeDir`

## Add Client Parameter Modification Functions

+ `SetTrashDir`: Change the client's trash directory. Note: after successful update, the configuration file must also be modified accordingly.
+ `SetBufferSize`: Modify the client's buffer size.
@include\AMClientManager.hpp

## Improve AMClientManager

I want to support passing a `quiet` parameter when creating a client.

- When `quiet` is **false** (default), the creation process—primarily the connection phase—should display a live status line:

  `{dynamic indicator}  Connecting to SFTP/FTP Server   [{nickname}]`

  where `{dynamic indicator}` is a rotating spinner or similar visual cue that updates in place.
- When `quiet` is **true**, suppress all such output. Additionally, temporarily suspend any logging during the authentication callback (`authcb`) phase.


@include\AMFileSystem.hpp

@src\AMFileSystem.cpp

AMFileSystem::connect

+ 支持接收多个client
+ 单个client创建失败打印错误但不停止

AMFileSystem::change_client

+ cleint不存在直接调用manager的addclient创建, 不需要再询问

AMFileSystem::cd

+ cd - 时, 直接清空last_cd_, 在调用一次cd last_cd_(copied)即可, 减少代码复杂度
+
# Improve ClientManager

@include\AMClientManager.hpp

- Treat `LocalClient` the same as other regular clients: initialize it by reading the config entry with nickname `"local"`.
- Change `AMClientManager::client_maintainer` to be held by a **shared pointer** (`std::shared_ptr`).
- Remove the `ClientMaintainerRef& ResolveMaintainer_()` function.Replace its usage sites with a ternary operator (`condition ? a : b`).
- When a `Client` is created:

  1. Read the `login_dir` field from the client's config.
  2. If the value is missing **or** the path does not exist:
     - Fall back to `home_dir`
     - Persist this fallback value back to the config file
  3. Store the resolved directory path in `client->public_kv["workdir"]`.
- Remove the `CreClient()` function.

## Improve AMFilesystem

- `AMFileSystem::check` should accept multiple clients as input.
- Add a new function `AMFileSystem::sftp`, corresponding to `ClientManager::Connect` but with the protocol fixed to SFTP. Upon successful connection, automatically switch to the newly created client.
- Add a new function `AMFileSystem::ftp`, with the same behavior as above but with the protocol fixed to FTP.
- `remove_client` should accept multiple target clients, but prompt for confirmation only once collectively.
- `AMFileSystem::stat` should accept multiple targets and print their status information one by one.
- `AMFileSystem::getsize` should accept multiple targets and print each target's size on a separate line.
- General-purpose functions related to `treeNode` creation and printing in `AMFileSystem::tree` should be moved to `CommonTools` for reuse.
- `mkdir` and `rm` should support multiple target paths for batch operations.
- Remove `AMFileSystem::NormalizeNickname`; replace all usages with `AMStr::lowercase()`.
- Remove `AMFileSystem::PromptYesNo`; use the confirmation prompt functionality provided by `PromptManager` instead.
- Replace `AMFileSystem::IsAbsolutePath` with `AMPathStr::IsAbs`.
