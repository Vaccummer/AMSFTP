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

## 优化AMSFTPCli.cpp

每个函数拥有自己的参数的struct

CliOptions 换为CliArgsPool, 存储所有的函数的参数struct

CliArgsPool{

auto ls = ConfiglsArg{

path =
list_like
show_all
interrupt_flag(不包括, 因为本质上interrupt_flag用于内部控制, 不是操作的参数)

timeout_ms(也不包括, 因为可以随时终止, timeout_ms意义不大了)

}

}

将绑定参数的操作独立出来成一个新文件AMCLIBind.hpp
封装一个函数: 参数为cli_commands, 以及一个存储各个manager的共享指针的struct, 在函数中根据指令执行操作, 返回值暂时设置为void

# Non-Interactive Improve

部分非交互的cli函数比较特殊, 因为它们是交互模式的入口, 所以需要修改并新添部分函数, 可通过DispatchCliCommands函数的返回值设定

+ bash: 直接进入交互模式
+ sftp/ftp : 连接成功后进入
+ connect: 连接成功后进入

# Interactive Mode

交互模式的函数依旧绑定到CliCommands, 但是在DispatchCliCommands中不分配执行, 即cli_commands.sub_commands()读取到指令但是DispatchCliCommands中没有执行的情况.

DispatchCliCommands暂时不需要更改, 先完成交互模式的函数绑定

# check

real_func: AMFileSystem::ECMAMFileSystem::check(conststd::vector[std::string](std::string) &nicknames, amfinterrupt_flag)

 ClientRefclient = resolve_by_name(name);

这里返回结果需要更详细, 是client未建立还是config不存在, 而且还要打印信息

+ 同时也需要包括其他函数比如cd
+ 返回的ECM只是用于设置状态, 出错时需要在函数内部打印错误信息
  + 格式 ❌ {cli_func_name}: {msg}

# ch

real_func:

AMFileSystem::change_client(conststd::string&nickname,amfinterrupt_flag)

# disconnect

AMFileSystem::remove_client

# cd

AMFileSystem::cd

# clients

AMFileSystem::print_clients

# Improve Transfer Manager

取消初始化参数, 因为各类manager都是单例模式, 可以直接通过函数获取

tm需要增添一些功能

+ 新增一个UserTransferSet的cache池, 并设置函数让用户提交新set, 查看已有的set以及删除某些不需要的se
  + 当然, 还需要设置一个函数执行这些transferset
+ show: 可以使用TaskInfoPrint::Show, 但是这个show接收ID和flag
+ list: 使用TaskInfoPrint::List, 但接收的时三个pending, finished, conducting bool option和一个flag
+ inspect: 接收ID, set, entry 两个bool option. 以及两个衍伸函数
  + userset: 接收ID
  + taskentry: 接收ID
+ 以及一些控制任务的函数
  + terminate
  + resume
  + pause

# Non-Interactive Improve

部分非交互的cli函数比较特殊, 因为它们是交互模式的入口, 所以需要修改并新添部分函数, 可通过DispatchCliCommands函数的返回值设定

+ bash: 直接进入交互模式
+ sftp/ftp : 连接成功后进入
+ connect: 连接成功后进入

# Interactive Mode

交互模式的函数依旧绑定到CliCommands, 但是在DispatchCliCommands中不分配执行, 即cli_commands.sub_commands()读取到指令但是DispatchCliCommands中没有执行的情况.

DispatchCliCommands暂时不需要更改, 先完成交互模式的函数绑定

# check

real_func: AMFileSystem::ECMAMFileSystem::check(conststd::vector[std::string](std::string) &nicknames, amfinterrupt_flag)

 ClientRefclient = resolve_by_name(name);

这里返回结果需要更详细, 是client未建立还是config不存在, 而且还要打印信息

+ 同时也需要包括其他函数比如cd
+ 返回的ECM只是用于设置状态, 出错时需要在函数内部打印错误信息
  + 格式 ❌ {cli_func_name}: {msg}

# ch

real_func:

AMFileSystem::change_client(conststd::string&nickname,amfinterrupt_flag)

# disconnect

AMFileSystem::remove_client

# cd

AMFileSystem::cd

# clients

AMFileSystem::print_clients: 该函数需要新加detail 的option, 设置时才需要打印状态, 不设置只需要打印名称即可

# task 子命令

以下函数在task子命令下

+ cache子命令

  + add : 添加userset, 签名和cp相同
  + rm: 可接收多个index
  + clear: 清除cache
  + submit : 生成taskinfo并提交, 设置quiet参数, 非quiet模式下需要打印userset信息,  并确认
    + 提交成功才清空cache
    + 空cache提交报错
+ show(函数)
+ list

  + AMTransferManager::List的三个option都不传入时,默认全打印
+ show

  + AMTransferManager::Show, flag由内部传入(一般是amgif)
+ inspect

  + 新增一个show_info
  + 三个option均未传入时, 使用show_info
  + 否则, 传入什么打印什么
+ terminate

  + workermanager的terminate函数需要改进一下， 应该直接从registry中找任务, 并根据任务状态执行.返回 `pair<`taskinfo `, bool>` 后者代表是否终止成功(已完成的任务无法终止)
  + 同样, get_task(constTaskId&id)也需要更改
  + 
  + 所有任务控制函数都支持批量操作, 而且每个需要打印结果
+ pause
+ resume
  命令的解析使用CLI11, 但是在交互模式下, 需要对用户输入的原始命令字符串进行预处理解析

所以需要有一个指令的预处理系统

# var函数

+ 该函数文件中没有定义, 需要实现
+ 该函数用于变量定义, 为了使用方便, 不需要对$转义, 所以改函数的参数不能进行解析, 甚至不经过CLI11解析
+ 检测到var关键字, 除非开头有!标识, 否则直接传给var
+ ${name} = {value} 的类型也需要传给var

# 内置符号

内置符号在传入CLI11前, 需要被解析并替换

+ ! 在开头代表将指令作为作为终端命令指令(调用ConductCmd)

  + 只有SFTPClient支持ConductCmd
  + 其他client类型报错
+ & 在结尾, 且函数为transfer以及task submit时, 用于异步执行

  + 不符合要求时, 不进行剥离
+ $ 符号, 是用于用户自定义变量的替代

## $ 引用系统

### 定义

+ setting中读取内置值

  + 在UserPaths中, 所有变量值只能是字符串
+ 内存定义

  + $arg_name = yeshahah
  + 定义在内存中, 程序重启后丢弃
  + 覆盖值时, 需要确认
    + 确认的prompt需要区分覆盖的时内置值还是内存值
+ 内置定义

  + 使用var ${name}={value} 定义
    + 写入内存, 并且写回config
    + 覆盖时依旧需要确认
+ 命名规范

  + 英文大小写, 数值, 和下划线
  + 不规范时报错提醒
  + 变量名区分大小写
+ 格式规范

1. 变量名与=之间可以有空格
2. 变量值与等号之间的空格不计入值中, 变量值需要两端strip
3. 变量值不需要引号包裹(因为值只能是字符串类型)
4. 但是也需要兼容被引号包裹的情况
   1. 若完全包裹 "  asdas   ": 则去除引号
   2. 若不完全包裹 "   asd   "bd  : 则报错

### 引用使用规范

+ $dsk/test1  \$dsk\test1

  + $解析名称时, 遇到非法符停止
+ $(dsk)1

  + 人为可以用()包裹目标
  + 若使用了$(但是括号不闭合, 需要报错
+ 原始路径中存在$

  + 若匹配的的名称不存在, 则返回不解析, 返回原字符串
  + 若$被`转义, 不解析
+ 解析若成功, 则使用字符串替换即可

# Command Preprocessing System

Command parsing is handled by CLI11. However, in interactive mode, raw user input strings require preprocessing before being passed to CLI11.

Therefore, a dedicated **command preprocessing system** is needed.

ps: any blankspace in front of a command is allowed and ignored

---

## `var` Function

+ This function is not yet implemented and needs to be added.
+ It is used for variable definition. For usability, **no `$` escaping is required**, meaning its arguments must **bypass CLI11 parsing entirely** and remain unparsed.
+ When the keyword `var` is detected at the beginning of a command (unless prefixed with `!`), the entire line should be routed directly to the `var` handler.
+ The syntax `${name} = {value}` must also be supported and forwarded to `var`.

---

## Built-in Symbols

Built-in symbols must be parsed and replaced **before** the command string is passed to CLI11:

+ **`!` at the beginning**Indicates the command should be executed as a native shell command via `ConductCmd`.

  + Only `SFTPClient` supports `ConductCmd`.
  + Other client types must return an error.
  + strip ! and return, don't parsing Variable Reference
  + ignore leading blankspace; if first non-space is `!`, treat as shell mode; otherwise `!` is literal
  + if ! is leagal, remove !,  strip blankspace, end parsing and call `ConductCmd`
+ example

  + ! ls .    ->   ls .
  + ls !. -> ls !.
  + ls . ! -> ls .!
  + !ls-> ls
  + ! ls -> ls
+ **`&` at the end**Used for asynchronous execution when the command is `cp` or `task submit`.

  + If conditions are not met (wrong command or position), return an error; do not treat `&` as literal input.
  + example

    + cp path1 path2 &  -> cp path1 path2
    + cp path1 path2& ->  cp path1 path2&    (& not a token, it's in the path)
    + ls  path1& ->  ls  path1&
    + ls  path1 & -> Return Error:  & not permited in functions except cp and task submit(Not Literal, you need to return an error)
+ **`$` symbol**
  Used for substituting user-defined variables.

---

## `$` Variable Reference System

### Definition Sources

+ **Built-in values from settings**

  + In `UserPaths`, all variable values must be strings.
+ **In-memory definition**

  + Syntax: `$arg_name = yeshahah`
  + Stored in memory only; discarded on program restart.
  + Overwriting requires confirmation.
    + The confirmation prompt must distinguish whether the value being overwritten is built-in or in-memory.
+ **Persistent definition**

  + Syntax: `var ${name}={value}`
  + Writes to both memory and config file.
  + Overwriting still requires confirmation.

### Naming Rules

+ Allowed characters: letters (case-sensitive), digits, and underscores (`_`). can startwith any allowed char
+ Invalid names trigger an error with a reminder.
+ Variable names are **case-sensitive**.

### Format Rules

1. Whitespace is allowed between the variable name and `=`.
2. Leading/trailing whitespace around `=` is **not** part of the value; values must be stripped.
3. Quotation marks are **not required** (values are always strings).
4. Quoted(" or ') values must be handled compatibly:
   a. Fully wrapped (e.g., `"  asdas   "`): strip outer quotes.
   b. Partially or malformed quotes (e.g., `"   asd   "bd`): report an error.
5. leading and tailing blankspace of name/value/command will be removed

### Reference Usage Rules

+ `$dsk/test1`

  + Variable name parsing stops at the first illegal character.
+ **`${dsk}1`**

  + Parentheses {}can be used to explicitly delimit the variable name.
  + Unclosed `${...}` must trigger an error.
  + invalid names inside {} cause no substitution and keep original.
+ **Literal `$` in paths**

  + If the referenced variable name does not exist, the original string is preserved (no substitution).
  + Escaped `$` (via backtick `` `$ ``) is not parsed.
  + \\ can't escape $
+ **Successful substitution**

  + Performs simple string replacement at the reference site.
  + recursive substitution is not allowed
    + $a = b
    + $b = c
    + $a expands to $b (literal), not c

## TokenType Analyser

replxx::Replxx rx;
rx.set_highlighter_callback([](std::string const& input, replxx::colors_t& colors){
});

用于实现input的语法高亮, 我需要一个解析器, 并实现上述回调

Token类型包括

module(task, config)

command

variable(`$varname  ${varname}`)

value (value of the variable)

nickname

option(-f -d)

atsign(只是真实生效的@, 即前面的nickname在config中)

dollarsign(`不包括转义的$, 且在后面跟着的变量名合法时生效, 但不检测变量是否存在`)

## DispatchCliCommands优化:

返回类型改为ECM

在函数最前方检测有没有subcommand匹配到, 打印错误, 返回错误

在函数下方验证是否为Interactive模式, 非交互模式退出, 返回EC::OperationUnsupported, {cmd_name} not supported in Non-Interactive mode

然后继续写分派执行交互模式函数的逻辑

# Interactive Loop

交互模式本质是一个询问指令->执行指令->询问指令的循环

但我需要对这个循环进行一定的设置

## 整体流程

1. 使用replxx库获取用户输入
2. 如果命令在去除两段空格并且转小写后为exit, 则清理资源退出程序
3. 使用CommandPreprocessor预解析参数
   1. 部分函数会在预处理阶段执行
   2. 部分操作可能在预处理阶段完成
4. 使用CLI11 解析命令(部分情况会跳过)
5. 解析失败则打印CLI11的报错信息
6. DispatchCliCommands执行命令
7. 获取执行结果更新input中的状态信息

## Input Custom

+ Prompt

  + 格式为
  + sysicon在setting.toml中, 需要结合GetOSType选择适当的图标
  + EC从函数返回值取
  + 复制生成Input可以缓存一个当前nickname的变量, 可以检测这个变量是否改变, 决定是否更新{sysicon} {username}{hostname}{nickname}

  {sysicon} {username}@{hostname}  {last_eplased}  ✅/❌ {EC_name if not success}

  ({nickname}){work_dir} $
+ input函数的注意点

  1. 需要额外的prompt的函数, 并为将来的补全留下接口(刚才提到的Completer)
  2. input 还需要set_highlighter_callback
  3. 该input函数不和PromptManager里的其他prompt函数共享replxx句柄, 但他的句柄仍由PromptManager管理
  4. 初始化时注册COREPROMPT HOOK, 效果类似PROMPT, 但目标是本句柄
  5. 该input前需要激活信号处理器中的COREPROMPT, 重置amgif(不重置iskill)
  6. 获取input内容后需要检查amgif
     3.1 如果amgif的iskill触发, 则清理资源退出
     3.2 如果amgif的is_interrupted触发, 则打印信息告诉用户如何退出(输入exit), 然后continue
  7. 获取input后需要沉默COREPROMPT
  8. 如果用户输入内容为空或者全是空字符, continue
     @InteractiveLoop.cpp

line 276 monitor.ResumeHook("COREPROMPT");

COREPROMPT这个钩子注册了吗?

ECMrcm = ExecuteShellCommand_(prompt, client_manager, config_manager,

    pre_result.command);

这个函数返回类型为ConducCmd的CR

返回后先检测EC是否success,

是success的话需要打印msg, 然后换行打印
Command exit with code {code}

elapsed_time时从用户确认输入的时间, 到命令执行完, 进入下一个循环前的时间

修复这些问题,然后在main.cpp中生成主函数入口
@InteractiveLoop.cpp

@main.cpp

Line 276: `monitor.ResumeHook("COREPROMPT");`

Has the "COREPROMPT" hook been registered?

```cpp
ECMrcm = ExecuteShellCommand_(prompt, client_manager, config_manager,
    pre_result.command);
```

This function returns a `CR` of type `ConducCmd`.

After returning, first check whether `EC` is successful.
If it is successful, print the `msg`, then print a newline followed by:

```
Command exit with code {code}
```

`elapsed_time` refers to the duration from when the user confirms their input until the command execution completes—just before entering the next loop iteration.

Fix these issues, then generate the main function entry point in `main.cpp`.
@InteractiveLoop.cpp

ResolveSysIcon_中, icon是[#3490de]icon[/]格式, 需要尝试对其进行ANSI转义, 格式不对再返回原字符串

SplitCommandLine_(pre_result.command, &argv, &parse_error)

这个是没必要的, 调用CLI交给它解析
CLI::App::parse(std::string commandline, bool program_name_included=false)

后续的argv.insert(argv.begin(), app_name);也没必要

# All Functions below are used in Interacctive Mode

## check

real_func: `AMFileSystem::ECM AMFileSystem::check(const std::vector<std::string>& nicknames, amf_interrupt_flag)`

```cpp
ClientRef client = resolve_by_name(name);
```

The return result needs to be more detailed—distinguish between "client not established" and "config does not exist"—and error messages must be printed accordingly.

+ This requirement also applies to other functions such as `cd`.
+ The returned `ECM` is only used to set the status. When an error occurs, the function itself must print the error message internally.
  + Format: `❌ {cli_func_name}: {msg}`

## ch

real_func:
`AMFileSystem::change_client(const std::string& nickname, amf_interrupt_flag)`

## disconnect

`AMFileSystem::remove_client`

## cd

`AMFileSystem::cd`

## clients

`AMFileSystem::print_clients`: This function requires a new `detail` option. When enabled, it should print the client status; otherwise, it should print only the client names.

## Input History

需要对交互模式的input新加一个历史命令功能

使用上下键可以切换历史指令(注意不能和补全菜单冲突, 有补全菜单时优先选择补全项目, 沉默历史指令选择)

历史命令存在项目根目录的.AMSFTP_History.toml中

注意需要以 nickname = list(cmd)的形式保存, 不同client不共享历史命令

文件由ConfigManager管理, PromptManager向其读取

历史最大entry最大数目为settings.InternalVars.MaxHistoryCount

+ 最小值与默认值均为10

PrompManager负责将历史数据写入replxx中

向上键往前翻, 向下键往后翻

但末尾有两个临时条目(在选择时启用但不加入历史中)

+ 在使用上下键使用历史前已经input的内容(如果空, 则不启用)
+ 空白条目, 用于清空input

在input返回且内容不为空且COREPROMPT钩子没有被触发时, 加入prompt到历史中

程序退出时,获取replxx的history写回.AMSFTP_History.toml
sftp, ch, ftp, connect连接成功后, 或切换到该client

CLI11在非交互模式下无法通过-h打印使用说明,  而是返回This should be caught in your main function, see examples

新设一个CLIBind.cpp, 将CLIBind.hpp中函数的具体定义移到其中

CliCommands中存一个CLI的app的指针, DispatchCliCommands中获取const bool any_parsed =可以用app.get_subcommands()方法(去查header找函数)

# 以下是关于CLI绑定及其对应工作函数的修改

ps: 在add_subcommand, 尽量将相关的函数放在一起

config的ls的-d选项改名为-l, --list  效果等同

config 添加一个函数SetHostValue, 绑定cli名称为set(在config subcommand中), 函数可在非交互模式下使用

config set wsl  username haha

set在cli中接收有且仅有三个字符串(nickname, 属性名, 属性值), 需要在SetHostValue中解析

nickname不存在, 属性名不存在, 或者属性值非法 都报错

更改成功时需要提示, 案例:  wsl.username:   am  ->   haha

config绑定一个save函数, 对应dump, 无需参数

host的config新加一个compression的字段, 字段排序(打印或者询问用户时)

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

新增一个client subcommand(和config, task类似 ), 并在该子命令下添加子命令

ls (支持-l, --list选项)对应原绑定:

commands.clients_cmd=app.add_subcommand("clients", "List client names");

  commands.clients_cmd->add_flag("-d,--detail", args.clients.detail,"Show full status details");

check  对应原绑定:

  commands.check_cmd=app.add_subcommand("check", "Check client status");

  commands.check_cmd ->add_option("nicknames", args.check.nicknames, "Client nicknames")->expected(0, -1);

rm 对应原绑定:

  commands.disconnect_cmd=

    app.add_subcommand("disconnect", "Disconnect clients");

  commands.disconnect_cmd ->add_option("nicknames", args.disconnect.nicknames, "Client nicknames to disconnect")->expected(1, -1);

以下指令我做了修改, 你保证其他地方一致性

  commands.task_list_cmd=commands.task_cmd->add_subcommand("list", "List tasks");

  commands.task_inspect_cmd=commands.task_cmd->add_subcommand("inspect", "Inspect a task");

  commands.task_userset_cmd

    ->add_option("index", args.task_userset.index, "Cache index")

    ->expected(0, -1);

可接收任意数量的index, 但需要对index进行去重

没有index传入打印所有cached的userset

  commands.task_taskentry_cmd=

    commands.task_cmd->add_subcommand("taskentry", "Inspect task entry");

  commands.task_taskentry_cmd->add_option("id", args.task_entry.id, "Entry ID")

    ->required()

    ->expected(1, 1);

改名为query, 可1+个ID
@

@src\manager\Transfer.cpp

封装一个函数CollectClients, 接收vector `<nicknames>`, 返回pair `<ecm, maintainer_ptr>`用于根据需要的client创建maintainer, 逻辑类似PrepareTasks_中的相关操作

将PrepareTasks_返回值修改成pair<ECM, TaskInfo_ptr>, 添加两个参数quiet,interrupt_flag,   PrepareTasks_中完成生成TaskInfo的操作(但结果回调在两类transfer中)

ReturnClientsToIdle_直接接收ClientMaintainer, 读取ClientMaintainer.hosts将所有非local的clients添加回公有池

transfer_async和transfer添加直接接收taskinfo的重载

修复transfer中progress的bug, transfer只提交一个任务, 用不着进度条组

TaskInfo持有maintainer的共享指针

TaskInfo新增 attr  vector `<str> nicknames`

TaskInfo在AMTransferManager::ResultCallback中将maintainer的client放回后, 设为nullptr释放

取消TransferManager中查询任务函数对maintainer调用

# Resume

新加resume用在已经失败的任务的重新提交/续传

resume接收两个参数

+ str id: 位置参数已经存在而且状态是已完成的任务的id, 非已完成的任务直接报错
+ bool: is_async = false
+ bool: quiet = false
+ vector `<int>` index: 接收可变数量的整数, 为TaskInfo的TASKS的指定任务的下标

先查询任务id是否合法

过滤非法的index(超界/负数), 过滤时需要警告用户这些index被过滤

根据index传输情况, 重新构造TASKS(已经IsSuccess的task不再重传)

分析需要的clients, 调用CollectClients创建maintainer, 若失败直接报错
调用workermanager的cre_taskinfo创建Taskinfo, 根据is_async 调用相关的transfer函数

## Completor Blueprint

### 1) 高层架构

- **补全流水线**：输入 → 解析cursor前的input → 构建查询 → 获取候选（同步/异步） → 排序/格式化 → 渲染 → 应用选择
- **核心类型**：
  - `CompletionContext`（光标位置、当前令牌、完整行、解析状态、模式）
  - `CompletionCandidate`（显示文本、插入文本、类型、帮助信息、评分、元数据）
  - `CompletionResult`（候选列表 + 匹配策略 + 延迟信息）
- **补全源（可选择开启与关闭）**：
  - `CommandSource`（命令/子命令/选项）
  - `InternalSource`（任务ID、客户端名称、主机配置昵称、变量名  以及一些内置属性名）
  - `PathSource`（本地/远程路径）
- **协调器（Coordinator）**：
  - 一个根据上下文分发请求至各补全源并合并结果的 `Completer`
  - **统一补全流程**：即使命令补全很快，也使用相同的 `CompletionRequest`流水线，确保UI行为一致，简化系统并提升可扩展性

### 2) 上下文解析

- 目前已经存在input解析器@src\cli\TokenTypeAnalyzer.cpp
- 支持引号、转义符和 `nickname@path`语法的令牌化
- **目标类型判定**   越靠前优先级越高 ：

  - 以!开头, 屏蔽补全, 因为时调用远程终端
  - input还没有有效命令 → 补全模块名或者顶层函数名
  - input存在有效模块名-> 补全该模块下的函数名
  - input存在有效函数

    - 以未被转义 `$`开头 → 变量名补全
    - 以 `--`开头-> 根据选项全称补全
    - 以 `-`开头 → 根据选项简写进行补全
    - 补全函数特有的参数

      - 例如config set 第一个参数时nickname, 第二个参数是config中各项属性的名称
      - task inspect 需要补全任务id
    - 出现路径的明显特征 如以/ , ~/, c:/, nickname@c开头
    - 1. 路径以/或\结果则获取该路径的所有子项目作为补全目标
      2. 否则, 遍历父级目录, 以匹配前缀的作为补全目标
  - 未触发以上规则, 不进行补全.
  - 触发一个规则后, 不再触发下面的规则

### 3) 候选模型

- **类型（kind）**：Module, Command, Option, VariableName, ClientName, HostConfigNickname, HostConfigAttrName, TaskId, PathLocal, PathRemote
- **字段**：
  - `insert_text`：实际插入内容
  - `display`：菜单中显示文本(被style化)
  - `help`：简要用法说明（命令尤为重要）
- **排序策略**：
  - 前缀匹配优先
  - 路径匹配时

    - regular文件优先
    - 其次文件夹
    - 然后链接文件
    - 最后其他特殊文件

### 4) 异步模型

- 每次输入都会产生一个请求ID, 修改输入时会改变请求ID并终止非该请求ID的补全任务，应用补全结果时核验请求ID, 自动丢弃过期的异步结果
- 补全远程路径时, 设置一个延时(用户可自定义), 在延时期内可以无成本地取消服务器请求, 减轻网络IO压力
- **补全缓存** : 主要需要存储路径补全的缓存,  包含 dir, nickname, vector `<PathInfo>`等属性即可, 如有其他需要的属性, 可以再添加. 其他补全存储在本地内存中, 无需缓存. 该缓存最好可以提供指令清除(因为路径会变动), 缓存的size也不宜过大
  - 只有文件夹内的子项目超过指定数量(用户设置)才进行缓存, 否则不进行缓存

### 5) 命令补全数据

- 可以定义一个定义静态命令树：命令 → 子命令 → 选项 → 位置参数类型
- 每个节点包含用法/帮助字符串
- 补全源根据当前节点仅推荐相关子命令/选项

### 6) 内部值来源

- 任务ID：来自 `AMWorkManager`（进行中/执行中/历史）
- 客户端名称：来自 `ClientMaintainer`
- 主机配置昵称：来自 `ConfigManager`（即使未连接也提供）

+ Bug1: path recognise error
  (local)D:/Document/Desktop/1 $ cd ./aad
  ❌ cd: Path not found: aad
  󰨡 am@localhost  5ms  ❌ PathNotExist
  (local)D:/Document/Desktop/1 $ cd aad
  󰨡 am@localhost  5ms  ✅
  (local)D:/Document/Desktop/1/aad $
+ Bug2: item name has a [/] and not Aligned (this bug seems only in windows)

(local)D:/Document/Desktop/1/aad $ ls d:/
  1 $RECYCLE.BIN[/]    6 Downloads[/]   11 System Volume Information[/]
  2 CodeLib[/]    7 Drivers[/]   12 WSL[/]
  3 Compiler[/]    8 Powershell[/]   13 Windows Kits[/]
  4 Config.Msi[/]    9 Program Files[/]   14 tmp[/]
  5 Document[/]   10 Softwares[/]

+ Improve3: Cycle page switch

when tab on the last page, return to first page

+ Improve4: set max rows num per page

given in CompleteOption.maxrows_perpage

+ Adjust1: set default complete type

when function need path:

1. token for path is empty: complete current client path
2. path has no @
   1. token for path is not empty but is not Path-like pattern
      1. if has clients macthed: complete client names
      2. else match current client path
   2. token for path is not empty and is  Path-like pattern : complete current client path
3. path has @
   1. if client not exists: no complete
   2. else, complete that client path

+ Improve5: number_pick switch

given in CompleteOption.number_pick, if off, recognise number as common input instead of item choose

+ Improve6:hightlight item if select
+ Improve7: custom select item sign

 →10 .AMSFTP_Trash/    the   →   sign and style can be customed

given in CompleteOption.item_select_sign

+ Improve8: add switch for auto fill in

when there's only one candidate or candidates have a same prefix,  auto fill in happened
but

+ bug3:

Unix path parse seems has problem

(wsl)/home/am $ cd ./yes/haha/yes2/
 am@172.26.36.83  5ms  ✅
(wsl)yes/haha/yes2 $

(wsl)/home/am/yes/home/am $ cd ../am/
❌ cd: Get stat failed: File does not exist
 am@172.26.36.83  5ms  ❌ FileNotExist
(wsl)/home/am/yes/home/am $

# Improve To Completor

# Align Command Complete

(local)D:/CodeLib $
 1 bash  Enter interactive mode
 2 cd  Change working directory
 3 ch  Change current client
 4 client  Client manager
 5 complete  Completion utilities
when no valid function situation, complete menu should show module first , then functions

modules, functions names should be aligned and styled in style.InputHighlight

and two builtin functions are missing: var, del

# Problems in resovling relative path . and ..

AMFS::abspath and AMFS::join should be carefully designed to be able to process:

+ Linux path
+ Windows path
+ Network path
+ relative path
+ .
+ ..
+ mix sep path
+ duplicate sep path

(wsl)/home $ cd am/haha
❌ cd: Get stat failed: File does not exist
 am@172.26.36.83  7ms  ❌ FileNotExist
(wsl)/home $ cd ./am/haha
❌ cd: Get stat failed: File does not exist
 am@172.26.36.83  6ms  ❌ FileNotExist

# Bugs: auto menu show and auto fillin set

It seems that you implement auto menu show by simulate tab key

but if there's only one candidate, it triggers auto fill in, that's not I want

# Adjust: Style set adjust

Now all element style (except path and debugger) is defined in [style.InputHighlight]

debugger style

path style is defined in [style.Path1]  [style.File2]  the one has greater number override small one

[style.PathExtraStyle] is extra style when path met certain demand(default is empty string, means no user extra style)

[style.File2] define files have certain extension name styles, overide style in [style.Path1]

# Improves

## tab行为修改

complete menu 现在不再自动触发, 而是使用tab触发

在complete menu 状态, 取消tab和shift tab切换页面功能

切换页面功能移到左右方向键

tab键在complete menu状态用于补全左右选项的相同前缀

# Tree 优化

tree新增一个onlydir参数, 默认为false, 为true时只打印目录(绑定option为-o,--onlydir)

# Interupt Bug

当ctrl-c中断一个指令后, 再调用一次这个指令,再中断, 程序就会退出

AMCliSignalMonitor的信号捕获的优先级好像不是很高, 信号似乎会泄露到其他地方

tree指令无法及时相应中断

ProgressBar Improve

在configmanager中新加一个创建进度条的函数, 读取style.ProgressBar中的配置创建, 注意限制color取值, 并映射成以下color

namespace indicators { enum class Color { grey, red, green, yellow, blue, magenta, cyan, white, unspecified };}

进度条的config不会在运行时改变, 可以创建一个, 然后进行复制
翻译成英文
将AMConfigManager的大部分函数迁移到AMConfigStyleData, AMConfigCLIAdapter,AMConfigCoreData, AMConfigStorage中实现, AMConfigManager持有以上几个类的引用, 并修改调用方式
AMConfigStorage需要进一步抽象, 参考为以下代码, 你可以在其中不足之处进行优化
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

  ECM Mutate(DocumentKind kind, std::function[void(nlohmann::ordered_json&amp;)](void(nlohmann::ordered_json&)) fn,
             bool dump_now);

  ECM DumpAll();
  ECM Dump(DocumentKind kind);

  ECM BackupIfNeeded();
  void SubmitWriteTask(std::function<void()> task);

  void StartWriteThread();
  void StopWriteThread();
  void Close();
};
@include\AMManager\Client.hpp

将 class AMClientManager 拆分为几个类

1. 信息数据读取类
   1. 从config中读取host的配置
   2. 读取know_host的数据
   3. src\manager\config\manager.cpp 中的ConfigManager已被弃用, 若该类中的FindKnownHost, GetClientConfig需要取回
   4. Client的public_kv的读写
2. Client操作类
   1. client的创建, 删除, 枚举
   2. 各种callback函数的定义与绑定
3. Path操作类
   1. BuildPath, GetOrInitWorkdir, AbsPath, ParsePath 等与路径操作相关的函数
      @include\AMManager\Client.hpp
      adjust class arrage structure to inherit mode

AMClientInfoReader->AMClientOperator->AMClientPathOps

set memeber function DefaultPasswordCallback and DefaultDisconnectCallback as builtin value for password_cb_ and disconnect_cb_

wrapp class of include\AMManager\Client.hpp in namespace AMClientManage
rename AMClientInfoReader -> Reader

AMClientOperator -> Operator

AMClientPathOps -> PathOps

AMClientManager -> Manager

function in different classes implemented in different src files stored in src\manager\client
@include\AMManager\Config.hpp

remove AMConfigCoreData, cause specific config read won't be implement in configMANAGER

make class structure to inherit type

AMConfigStorage->AMConfigStyleData->AMConfigCLIAdapter->AMConfigManager
function implemented in different cpp file in src\manager\config

Implement bool SetArg(DocumentKindkind, constPath&path, T value)

Dump and DumpAll add option bool async
if true, add task to write thread

add new mechanism DumpErrorCallback void(ECM)
when dump error, transit error to ECM and callback
AMConfigStorage suply interface to set the callback
@include\AMManager\Config.hpp

remove AMConfigCoreData, cause specific config read won't be implement in configMANAGER

make class structure to inherit type

AMConfigStorage->AMConfigStyleData->AMConfigCLIAdapter->AMConfigManager
function implemented in different cpp file in src\manager\config

Implement bool SetArg(DocumentKindkind, constPath&path, T value)

Dump and DumpAll add option bool async
if true, add task to write thread

add new mechanism DumpErrorCallback void(ECM)
when dump error, transit error to ECM and callback
AMConfigStorage suply interface to set the callback
@src\cli\CLIBind.cpp

@include\AMCLI\CLIBind.hpp
在类似ConfigLsArgs 所有存储函数参数的结构体中定义一个Run函数

CommonArg: 类型为所有Args结构体的variant

为所有命令绑定添加一个callback: 将CommonArg设置为指定结构体

使用CLI11解析指令, 检查CommonArg是否为空, 非空使用std::visit进行调用Run函数并获取ECM
AMCompleteEngine Improve

# 低耦合性和可扩展性是该类设计的主要目标

该类依旧存在很强的耦合性, 你需要进行如下改善:

1. AMCompleteEngine不包含任何补全搜索的逻辑, 而是提供一个接口RegisterSearchEngine(vector CompletionTarget, SearchEngine_ptr) 并将指针放入字典中
2. SearchEngine是一个搜索引擎的基类, 有CollectCandidate, SortCandate 的纯虚函数

   1. CollectCandidate是同步的, 如果需要异步补全, 需要在CollectCandidate返回一个AsynRequest供AMCompleteEngine识别, 然后进入异步处理流程

      1. AsynRequest 至少包含以下内容
         1. ID
         2. Timeout_ms
         3. Interuput flag(用于AMCompleteEngine终止函数执行)
         4. 具体搜索函数Attr(本质上为SearchEngine)
         5. 成员函数Search(使用AsynRequest中的参数执行4中的函数)
   2. 同步或者异步处理流程完全由AMCompleteEngine实现, 同时异步的工作线程也由AMCompleteEngine管理

      1. Cache 之类的由SearchEngine自行管理
   3. AMCompleteEngine不必再持有config_manager_, client_manager_, filesystem_, transfer_manager_, 因为它不需要实现具体的补全搜索逻辑
      @include\AMBase\DataClass.hpp

@include\AMManager\Logger.hpp

@log

优化TraceInfo: 新增一个 std::optional `<ConRequest>`

优化LogManager

logger支持两种类型的log

+ client log: 使用回调绑定到Client上, 写入@log\Client.log
+ program log: 无ConRequest 的trace, 写入@log\Programm.log

logger需要提供两种类型Trace的公开函数, 都是任务提交的异步模式

logger持续打开两个log文件, 不再循环打开关闭
AMCompleteEngine Improve

Engine Features

+ 一类Target只能有一个engine(但允许不同target 共用一个engine)
+ AsyncWorkerLoop_ 最终目标不是将匹配结果写入缓存, 而是直接执行补全
+ engine不进行sort, 该函数由searcher提供
+ AMCompletionAsyncRequest 的interrupt_flag应该是一个函数或者函数指针, 这样的通用性更强
+ 没有设置interrupt_flag的request将被丢弃
  @ src\cli\completer\searcher.cpp

## AMPathSearchEngine Improve

我在setting.toml中新加了如下配置:
[CompleteOption.Engine.Path."*"]
use_async = false
cache_items_threshold = 50
cache_max_entries = 1000
timeout_ms = 5000
[CompleteOption.Engine.Path.local]
use_async = false  # when lack, set false
cache_items_threshold = 50  # when lack set 50, when <=0, set to 1
cache_max_entries = 1000  # default is 3
timeout_ms = 5000
[CompleteOption.Engine.Path.wsl]
use_async = false
cache_items_threshold = 50
cache_max_entries = 1000
timeout_ms = 5000
"*" 代表默认配置, nickname不存在时使用

在searcher初始化时, 需要读取这些配置到内存中, 以unordered_map `<str, confgi_struct>` 格式存储
在进行路径搜索时, 根据path对应的nickname读取相应的配置, 并进行搜索
ps: 不同nickname不共享缓存, 缓存需要以dict `<nickname, dict<path, `cache_struct `>>` 格式存储
还需要设置一个dict `<nickname, list<path>>` 用于在缓存溢出时决定谁被删除

## AMPathSearchEngine::CollectCandidates Improve

auto [rcm, items] = client->listdir(path.dir_abs, nullptr, timeout_ms, am_ms());
client->listdir 应该传入一个interupt_flag, 并绑定触发函数到AMCompletionCollectResult上, 而不是在外部检查终止,因为listdir才是主要耗时操作
另外, 缓存中读取到的匹配结果和实时结果需要进行区分, 在completemenu渲染时也需要标识缓存结果

## Add New Functions

添加函数用于查询各种nickname的cache情况

添加函数用于删除指定nickname或者所有cache的函数
@include\AMCLI\Completer\Searcher.hpp

@include\AMManager\Host.hpp

improve PathEngineConfig (you can refer to ClientConfig)

add a GetJson() function turn config to json

add init function to enable init with a json
@config\settings.toml

以下为原先版本的备份, 你可以用来参考

@bak.toml
我对settings.toml的数据排布进行了修改, 这种修改有的只是单纯的key变换, 但有些改变需要更改原先的config管理代码

[Options] 内的设置为单纯的key位置变换, 更新读取函数的key即可

[Style] 大部分是单出的位置修改, 但有些例外

+ [Style.CompleteMenu] 是新加的属性
+ [Style.Path] 进行简化, 不再多级匹配

[UserVars] 存储方式以及VarManager都需要升级

+ 变量不再区分mem和storage, 而是分公有和私有
+ 公有的变量存在[UserVars."*"]中, 私有的变量存在[UserVars.nickname]中, nickname是client的名称
+ 读取顺序: 优先读取私有变量区, 未找到再读公有变量区
+ 命名规则:
  + 名称字符范围不变
  + 同一区内, 变量名不可相同. 跨区允许名称相同
+ CLI接口修改: 暂时不修改, 等VarManager稳定再修改
  @include\AMCLI\TokenTypeAnalyzer.hpp

AMTokenTypeAnalyzer Problem

+ Abundant const decoration

auto *self = const_cast<AMTokenTypeAnalyzer *>(this);

  self->RefreshHostSet();

these codes are too wierd, it's origining from abundant const decoration on functions, fix it

+ Attr missing in PathEngineConfig

PathEngineConfig Should involves all atttrs in settings.toml [HostSet]

Highlight.Path.use_check= true  # default true

Highlight.Path.timeout_ms=1000  # default 1000, when <=0, set to default

+ RefreshHostSet Problems

!QueryKey(it.value(), {"CompleteOption", "Searcher", "Path"},

    &path_cfg)

only if path_cfg is a json object, it's a valid config
if some value missing, use "*" config values

AMTokenTypeAnalyzer::Tokenize Problem

didn't take ` to escape $ or @ into account

so casual on distiguishing option, you should determine command first then judge whether an option is valid

AMTokenTypeAnalyzer::Tokenize Improve

AMTokenType add new items:
Path: path token when  Highlight.Path.use_check is false

Nonexistentpath: nonexistent path token when Highlight.Path.use_check is true

File: regular path token when Highlight.Path.use_check is true

Dir: ...

Symlink: ...

Special: other special path token when Highlight.Path.use_check is true
新建一个SetManager类

该类与HostManager平级, 负责管理settings.toml中的[HostSet]

整体的读取逻辑与TokenAnalyzer中现有的逻辑类似

Setanager 提供方便的接口供其他类读取指定host的set的指定属性, 或者是整个config(如果host的set不存在, 需要返回*对应的值, 并且返回标志提示当前值为默认值回退)

在SetManager的基础上, 建立一个子类SetCLI, 该类主要用于实现一个供CLI绑定的函数:

+ 建立某个host的set
+ 修改某host的set
+ 删除某host的set
+ 将SetManager管理的config写回ConfigManager的json中并保存到settings.toml

交互逻辑可以参考HostManager的CLI函数

@include\AMManager\Var.hpp

当前AMVarManager存在大量的legacy函数, 现在需要进行清理

AMVarManager在Init函数中读取ConfigManager中的数据, 保存为 dict<nickname, dict `<varname, varvalue>>` varvalue 必须为字符串

新的AMVarManager的Var只有两种类型, 公有Var([UserVars."*"]), 各个Host的私有Var([UserVars.Nickname])

Var需要以VarInfo为最小单元进行处理, VarInfo包括domain, varname, varvalue的attrs

还包括bool IsPublic() 函数, ECM IsValid()函数, 后者需要检查domain或varname是否为空: 为空则为未初始化的VarInfo, 用于查询失败时的结果返回

AMVarManager 还需要提供一个save函数, 将数据写回json并保存到toml文件

还需要一个子类VarCLISet, 主要包含一些用于CLI绑定的函数

+ Var Query函数

CLI调用方式为 var get $varname

检索所有名为varname的变量, 输出

[zonename] $varname = value

[zonename2] $varname = value

(可以不对齐, 但需要字符串style化)

+ Var Add函数

CLI调用方式为 var def -g $varname varvalue

-g: --global, 如果为true, 则定义到pulic区中, 如果为false, 定义到当前host的private区中

注意: 当定义到private区中时, 如果改private区已经存在, 需要打印已经存在的键值对, 并向用户进行确认是否覆盖

+ Var Delete函数

CLI调用方式为 var del -a (nickname) $varname

-a: --all 删除所有私有区和公有区的$varname (需要打印匹配到的键值对, 并进行确认)

nickname: 目标区的名称, 可为*, nickname. 当-a提供时, 不允许提供nickname

指定区删除不进行确认, 若删除失败, 需要报错

+ var List函数

CLI调用方式为 var ls 区名1 区名2 区名3

可接收多个区名, 也可以空区名(打印所有区的变量)

多个区名需要先去重, 然后滤除不合法的区名并报错, 然后打印变量

打印格式为

[name]

$var1 = value1

$var2 = value2

$var3 = value3

[name2]

$var1 = value1

$var2 = value2

$var3 = value3

+ 注意$varname的对齐
+ 值为空字符串时, 需要打印为"", 而不是空白

## Completion Refactor Plan (BuildContext_)
1. Tokenize with `AMTokenTypeAnalyzer::SplitToken`.
2. Keep only tokens before cursor plus token-at-cursor.
3. Parse and store `module`, `cmd`, `options`, `args` in `AMCompletionContext`.
   - Keep `$var` and `$var=value` shortcut branch as highest-priority path.
4. Detect cursor placement (`in token` vs `outside token`) and keep token index.
5. Store cursor token prefix/postfix (raw + unescaped).
6. Target selection rules:
   - If no certain module/cmd yet: top command target.
   - If module is certain but cmd not certain: subcommand target under module.
   - If prefix is `-` / `--`: short/long option target.
   - If prefix is `--name=`: option-value semantic target.
   - If cursor is after an option requiring value: option-value semantic target.
   - Else use command arg semantic from `CommandTree` for current arg index.
7. Behavior constraints:
   - Unknown token before legal command/module => `Disabled`.
   - `-ov` does not treat `v` as option value.
   - Bare `--` is treated as common positional arg.
   - Command/module certainty precedes option/arg interpretation (except var shorthand).
what do you think of plan blow

@src\cli\completer\engine_worker.cpp

remove AMCompletionToken, use AMTokenTypeAnalyzer::AMToken

AMCompleteEngine::BuildContext_ Improve

My expected protocol:

1. use AMTokenTypeAnalyzer::SplitToken to split
2. analyse short-hand expression (independent flow, won't go on with the protocol)
3. get module and cmd option( exclude named arg)
   1. module and cmd must be determined first, all other tokens are invalid, and will cause abort in completion
      1. but if this is the first nonempty token, complete module/top cmd
      2. if this is the first nonempty token after valid module, complete its cmds
   2. option must be valid for the cmd, if option is not exist, will be viewed as arg, but allow duplicate
      1. -ov if o exists but v not,  viewed as arg
   3. named arg only suport expression like: -n value; --name value; --name=value
      1. ilegal expression viewed as arg
   4. ilegal arg like token will be viewed as arg, but won't stop option parse
4. find where cursor is, get prefix and postfix
5. get AMCommandArgSemantic according to module, cmd, option record and any other neccessary context
6. transit AMCommandArgSemantic to targets according to prefix and any other neccessary context
New features to be implement, do you have any questions?

@src\cli\completer\searcher.cpp

@include\AMCLI\Completer\Engine.hpp

### Some little improve

AMCompletionCollectResult use AMCompletionCandidates instead of AMCompletionCandidate

move AMSearchEngineRegistration to engine's header file

move AMBuildDefaultSearchEngineRegistrations to searcher's header as inline function

move AMCompleteEngine::Init() to engine's header

### Searcher File Structure Change

implement different search in different cpp and store in src\cli\searcher


Gerneral match rule (when prefix not empty)

+ Need case match
  + find item starts with prefix
  + find item has prefix (lower score, can't duplicate with the former)
+ No-case match (only when case-sensitive match empty trigger)
  + find item starts with prefix
  + find item has prefix (lower score, can't duplicate with the former)

### AMCommandSearchEngine 

use Gerneral match rule

### AMInternalSearchEngine 

use Gerneral match rule

hold reference of VarManager

search varnames in pulic zone and current private zone

candidate's help should has value

display string should be styled

### AMPathSearchEngine

use Gerneral match rule

set init function as default, set manager using AMConfigManager &config_manager_ = AMConfigManager::Instance();

set an temp cache like current cache, trigger all the time, but clear when CorePrompt return(use register)

hold a ref to VarManager, path sometimes has var, need resolve it
# CommandTree Improve

Set this class as a singleton like manager(built once at startup only, no thread-safe because changes happen in main thread), remove

inlineconststd::shared_ptr`<CommandTree>` g_command_tree =

    std::make_shared`<CommandTree>`();

use Instance() to get ref of the class

move this class to a solo hearder file and implement in solo src file(command_tree.cpp)

std::unordered_map<std::string, CommandNode> nodes_; key should be {part1, part2} like instead of join by space (set a simple hash func)

+ variable-length,case-sensitive

CommandNode add str help to store help info of current node

+ live only in CommandNode
I have a new improve plan, do you have any suggestion?
@src\cli\CLIBind.cpp

@include\AMCLI\CommandTree.hpp

将各种arg struct和app的CliCommands 到新的CLIArg.hpp中

将具体的绑定函数移动到include\AMCLI\InteractiveLoop.hpp中

# CommandTree

弃用CommandTree, 使用CommandNode自身作为顶层, 成为和CLI11::App一样的完全链式结构

# CommandNode

设置一个Instance()静态函数以获取一个静态对象(用于兼容当前代码), 但是不能去继承NoCopy的那个class, 公有初始化函数

将CommandNode移出CommandTree, 转换成class

移除CommandNode中AddFunction/Flag/Option 对target是否已经存在的检查, 

新建一个find(Path)函数, 用于寻找下级节点

AddFunction 新加两个参数: CliArgsPool&args, T CliArgsPool::*member, 用于设置原本的CLI11回调

AddFlag 需要新加一个参数: bool & 用于CLI11绑定参数存储位置

AddOption需要设置为模版函数, 设置一个T&value用于CLI11绑定参数存储位置
Great Improve on ConductCmd (sftp/local)

add an str cmd_prefix(you can choose a suitable argname) bool wrap_cmd in HostConfig in config\config.toml, this cmd_prefix is invisible to Client, but should be stored in ClientConfig

ConductCmd itself only recept final command and conduct it. remove cmd check in IsCommandAllowed

add a function in Filesystem ShellRun(str cmd, and other args you think necessary) for CLI bind, it proximately does things:

+ build command(if no prefix, just use arg cmd)
  + prefix'cmd' (if wrap)
  + prefixcmd
+ call ConductCmd
