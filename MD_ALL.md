
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
