# AMSFTP

[English](./README.md) | [简体中文](./README.zh-CN.md)

AMSFTP 是一个基于 C++20 的命令行工具，用于多主机文件管理与终端工作流。它把本地、SFTP、FTP 和 HTTP 下载整合到同一个 CLI 中，并提供主机配置保存、异步传输任务、交互式终端、命令补全和样式化输出。

## 🚀 项目简介

AMSFTP 面向希望通过一个命令行入口统一处理“文件操作 + 终端访问”的用户场景。

当前仓库中的代码已经提供以下能力：

- 在本地、SFTP、FTP 客户端之间切换
- 管理 host、profile、config、client、pool 和变量
- 执行 `stat`、`ls`、`size`、`find`、`mkdir`、`rm`、`tree`、`realpath`、`cp`、`mv`、`clone`、`wget` 等文件操作
- 执行 `ssh`、`term`、`channel` 等终端相关工作流
- 通过 `task ls`、`task inspect`、`task pause`、`task resume`、`task terminate` 管理异步传输任务
- 通过 `bash` 进入交互模式，并使用基于 Isocline 的补全、高亮和历史记录

AMSFTP 启动前需要设置环境变量 `AMSFTP_ROOT`。程序首次运行时会在该目录下初始化以下文件：

- `config/config.toml`
- `config/settings.toml`
- `config/known_hosts.toml`
- `config/history.toml`
- `config/bak/`

## 🛠️ 如何 Build

### 前置条件

当前仓库提供的 CMake preset 主要面向 Windows。

- CMake 3.20 或更高版本
- Ninja
- LLVM/Clang，且可使用 `clang-cl`
- Rust 与 `cargo`
- `vcpkg`

当前有效的 CMake 构建会通过 `vcpkg` 链接这些库：

- OpenSSL
- ZLIB
- CURL
- nlohmann_json
- Lua
- libssh2
- CLI11

### 构建前需要检查的值

配置项建议先检查：

- 在 [CMakePresets.json](./CMakePresets.json) 中，确认 `CMAKE_TOOLCHAIN_FILE` 指向你本机的 `vcpkg.cmake`。
- 在 [CMakePresets.json](./CMakePresets.json) 中，静态 release preset 使用 `VCPKG_TARGET_TRIPLET=x64-windows-static`。
- 在 [CMakeLists.txt](./CMakeLists.txt) 中，`CMAKE_MSVC_RUNTIME_LIBRARY` 当前设置为 `MultiThreaded`。
- 在 [CMakeLists.txt](./CMakeLists.txt) 中，`AMSFTP_PROGRAM_NAME` 控制 version 文本中显示的程序名。
- 在 [CMakeLists.txt](./CMakeLists.txt) 中，正式发布前应更新 `AMSFTP_PROGRAM_VERSION`。
- 在 [CMakeLists.txt](./CMakeLists.txt) 中，真实私有构建不要继续使用默认的 `AMSFTP_PASSWORD_KEY` 示例值。

### 构建步骤

1. 先以 `release` 模式构建 Rust TOML 辅助库。

当前 `CMakeLists.txt` 只会从 `src/foreign/tomlread/target/release` 查找 `rust_toml_read.lib`，所以这一步应该保持 `--release`。

```powershell
Set-Location .\src\foreign\tomlread
cargo build --release
Set-Location ..\..\..
```

2. 配置静态 release preset：

```powershell
cmake --preset win-clang-static-release
```

3. 编译 AMSFTP：

```powershell
cmake --build --preset win-clang-static-release --target amsftp
```

`CMakePresets.json` 中当前设置了：

```text
binaryDir = ${sourceDir}/build/${presetName}
```

因此，当使用 `win-clang-static-release` preset 时，生成的程序路径为：

```text
build/win-clang-static-release/amsftp.exe
```

## 💡 如何使用

### 初始设置

运行程序前，先把 `AMSFTP_ROOT` 设置为一个可写目录：

```powershell
$env:AMSFTP_ROOT = "D:\Data\amsftp"
```

启动交互模式：

```powershell
.\build\win-clang-static-release\amsftp.exe bash
```

如果你只想先看帮助：

```powershell
.\build\win-clang-static-release\amsftp.exe --help
```

下面的示例都是进入交互模式后输入的 AMSFTP 命令。

### Host 与 Client

```text
host add dev
host ls -d
profile edit dev

local self
sftp dev user@example.com -P 22
ftp ftpbox user@example.com -P 21
connect dev
ch dev
```

### 文件操作

```text
ls
stat dev@/var/log/syslog
mkdir dev@/tmp/upload
rm dev@/tmp/old.txt
realpath dev@../logs
```

`find` 有两种用法：

```text
find dev@/var/log/**/*.log
find dev@/var/log "*.log"
```

第一种把单个参数直接当作完整搜索模式。第二种是在指定路径下递归搜索匹配模式，内部等价于 `path/**/pattern`。当前支持的模式特性包括 `*`、`**`，以及类似 `<abc>` 的字符集合。

传输示例：

```text
cp @D:\tmp\a.txt dev@/tmp/
cp @D:\tmp\large.zip dev@/tmp/ --resume
cp @D:\tmp\a.txt @D:\tmp\b.txt --output dev@/tmp/
cp @D:\tmp\a.txt dev@/tmp/ &
clone dev@/data/file.bin @D:\backup\file.bin --resume
wget https://example.com/file.zip @D:\tmp\file.zip --resume
```

常用传输参数：

- `--resume`：目标文件已存在时尽量断点续传
- `--force`：覆盖已存在目标
- `--output`：复制多个源时显式指定目标目录
- 末尾 `&`：异步运行传输任务

### 变量系统

AMSFTP 的变量不是宏。变量替换只会在“路径类参数”中生效，例如文件路径、传输路径和下载目标路径。它不会改写任意命令文本，也不会改写 option 名称。

```text
var def ${dev:logs} /var/log
var def --global $cache @D:\cache
var ls
var get ${dev:logs}
var del ${dev:logs}
```

交互模式中也支持快捷写法：

```text
$logs=/var/log
$
${dev:}
```

变量查找规则：

- `$name` 定义或读取当前 client 分区中的变量。
- `var def --global $name value` 会把变量保存到公共分区。
- `${zone:name}` 显式指定分区。
- `${:name}` 显式指定公共分区。
- 路径替换中，未指定分区的 `$name` 从当前 client 分区查找；如果想在路径中使用公共变量，请写 `${:name}`。
- `nickname@path` 目标不会改变变量查找分区。如果变量属于 `dev`，请写 `${dev:name}`。

示例：

```text
var def ${dev:logs} /var/log
find dev@${dev:logs} "*.log"
cp dev@${dev:logs}/app.log @D:\logs\app.log
```

### 转义方法

交互输入使用反引号作为转义字符。

```text
stat dev@/tmp/a`@b.txt
stat dev@/tmp/price`$1.txt
stat "dev@/tmp/name with spaces.txt"
stat "dev@/tmp/a`"quoted`".txt"
rm -- -file-starting-with-dash.txt
stat "-file-starting-with-dash.txt"
```

重要规则：

- 使用引号把包含空格的内容包成一个参数。
- 使用 `` `@`` 表示路径中的字面量 `@`，避免被当成 client 分隔符。
- 使用 `` `$`` 表示字面量 `$`，避免被当成变量。
- 在引号中使用 `` `"`` 或 `` `'`` 表示字面量引号。
- 使用 `--` 表示后面的内容是位置参数，避免被误认为 option。
- 交互模式中，以 `-` 开头且被引号包住的路径会被规范化为 `./-name`。
- `!command` 是 `cmd command` 的快捷写法，例如 `!pwd`。

### 终端会话

```text
ssh dev@main
term ls
channel add dev@main
channel ls dev
channel rm dev@main
```

终端目标语法是 `[terminal]@[channel]` 或单独的 `channel`。例如 `ssh dev@main` 表示打开 `dev` 终端/client 下的 `main` channel。

终端快捷键：

- `Ctrl+]`，然后按 `q` 或 `Q`：从前台终端 detach，回到 AMSFTP prompt。
- 远端或本地 shell 正常退出时，前台会话会关闭。
- detach 后可以用 `term ls` 和 `channel ls` 查看仍可复用的 terminal/channel 状态。

### 交互快捷键

AMSFTP 使用 Isocline 作为交互输入组件。常用按键：

- `Tab`：打开补全菜单或补全当前 token
- `End`：当有 inline hint 时接受补全提示
- `Up` / `Down`：光标在第一行或最后一行时切换历史记录
- `Ctrl+P` / `Ctrl+N`：上一条或下一条历史记录
- `Ctrl+R` / `Ctrl+S`：历史搜索
- `Ctrl+A` / `Ctrl+E`：移动到行首或行尾
- `Ctrl+B` / `Ctrl+F`：向左或向右移动
- `Ctrl+Left` / `Ctrl+Right`，或 `Alt+B` / `Alt+F`：按单词移动
- `Ctrl+U` / `Ctrl+K`：删除到行首或行尾
- `Ctrl+W`：删除前一个以空白分隔的单词
- `Alt+D`：删除到下一个单词末尾
- `Ctrl+L`：清屏
- `Ctrl+Z` 或 `Ctrl+_`：撤销
- `Ctrl+Y`：重做
- `F1`：显示 Isocline 帮助
- `Ctrl+C`：取消当前输入，或中断可取消的操作

### 保存配置

```text
config save
```

很多命令路径会自动 flush 配置，但 `config save` 是显式保存配置的命令。

### 路径目标语法

很多文件命令都支持 `nickname@path` 形式的目标：

- `dev@/var/log/syslog`：使用 `dev` 客户端
- `@D:\tmp\a.txt`：使用本地客户端
- `/tmp/a.txt`：使用当前客户端
- `@`：表示本地当前目录
