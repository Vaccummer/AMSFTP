# AMSFTP

[English](./README.md) | [简体中文](./README.zh-CN.md)

![AMSFTP 封面](./resource/cover1.png)

AMSFTP 是一个基于 C++20 的命令行工作区，用于在本地、SFTP、FTP 和 HTTP 目标之间执行文件操作与终端访问。它的目标是把 `ssh`、`sftp`、脚本化文件传输和常用终端工作流收敛到一个清爽的 CLI 入口里。

项目已经接近首个公开版本。当前有效实现位于 `src/`；旧迁移记录、废弃原型和本地构建产物不再属于发布树。

## 当前能力

- 本地、SFTP、FTP 与 HTTP 下载相关客户端工作流
- 保存 host profile，并快速切换 client
- 文件命令：`stat`、`ls`、`size`、`find`、`mkdir`、`rm`、`tree`、`realpath`、`cp`、`mv`、`rn`、`clone`、`wget`
- 异步传输任务：`task ls`、`task inspect`、`task pause`、`task resume`、`task terminate`
- 通过 `bash` 进入交互模式
- 通过 `ssh` 和 `term` 管理 SSH/本地终端会话
- 基于 Isocline 的补全、高亮和历史记录
- 样式化终端输出和可配置 prompt profile

## 构建要求

- CMake 3.20 或更高版本
- Ninja
- Rust 与 `cargo`
- OpenSSL、ZLIB、CURL、nlohmann_json、Lua、libssh2、CLI11

Windows 下使用 vcpkg 为所选 triplet 安装依赖，并在配置前设置 `VCPKG_ROOT`：

```powershell
$env:VCPKG_ROOT = "D:\Compiler\vcpkg"
```

Windows preset 使用 `clang-cl`、`llvm-rc` 和 `$env{VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake`。

macOS 下内置 arm64 preset 预期使用 Homebrew 包，并通过 `/opt/homebrew` 下的 pkg-config 静态元数据查找依赖。

## 构建

### Windows

配置 release preset：

```powershell
cmake --preset windows-msvc-release
```

编译可执行文件：

```powershell
cmake --build --preset windows-msvc-release --target amsftp
```

Windows release 可执行文件生成在：

```text
build/windows-msvc-release/amsftp.exe
```

### macOS

配置 arm64 release preset：

```sh
cmake --preset macos-arm64-release
```

编译可执行文件：

```sh
cmake --build --preset macos-arm64-release --target amsftp
```

macOS release 可执行文件生成在：

```text
build/macos-arm64-release/amsftp
```

CMake 会通过 `cargo build --release --locked` 自动构建 `src/foreign/amsrust` 中的 Rust 辅助 crate。

发布前建议检查 `CMakeLists.txt` 中这些值：

- `AMSFTP_PROGRAM_VERSION`
- `AMSFTP_PASSWORD_KEY`
- `AMSFTP_APP_DESCRIPTION_TEXT`

## 首次运行

AMSFTP 需要 `AMSFTP_ROOT` 指向一个可写运行目录：

```powershell
$env:AMSFTP_ROOT = "D:\Data\amsftp"
```

启动交互模式：

```powershell
.\build\win-clang-static-release\amsftp.exe bash
```

或者先查看命令帮助：

```powershell
.\build\win-clang-static-release\amsftp.exe --help
```

首次运行时，AMSFTP 会在 `AMSFTP_ROOT` 下初始化运行配置，包括：

- `config/config.toml`
- `config/settings.toml`
- `config/known_hosts.toml`
- `config/history.toml`
- `config/bak/`

## 示例

创建并连接 client：

```text
host add dev
profile edit dev
local self
sftp dev user@example.com -P 22
ftp ftpbox user@example.com -P 21
connect dev
ch dev
```

执行文件操作：

```text
ls
stat dev@/var/log/syslog
find dev@/var/log "*.log"
mkdir dev@/tmp/upload
cp @D:\tmp\a.txt dev@/tmp/
clone dev@/data/file.bin @D:\backup\file.bin --resume
wget https://example.com/file.zip @D:\tmp\file.zip --resume
```

在命令末尾加 `&` 可以后台运行传输：

```text
cp @D:\tmp\large.zip dev@/tmp/ --resume &
task ls
task inspect 1
task pause 1
task resume 1
```

管理终端会话：

```text
term add dev@main
ssh dev@main
term ls
term rm dev@main
```

## 路径语法

很多命令都接受 `nickname@path` 形式：

- `dev@/var/log/syslog` 使用 `dev` client
- `@D:\tmp\a.txt` 使用本地 client
- `/tmp/a.txt` 使用当前 client
- `@` 表示本地当前目录

交互输入使用反引号作为转义字符：

```text
stat dev@/tmp/a`@b.txt
stat dev@/tmp/price`$1.txt
stat "dev@/tmp/name with spaces.txt"
rm -- -file-starting-with-dash.txt
```

## 变量

变量只在路径类参数中解析，不是通用命令宏。

```text
var def ${dev:logs} /var/log
var def --global $cache @D:\cache
find dev@${dev:logs} "*.log"
cp dev@${dev:logs}/app.log @D:\logs\app.log
```

## 交互快捷键

### Isocline 输入

- `Tab`：打开补全或补全当前 token
- `End`：接受 inline completion hint
- `Up` / `Down`：光标在第一行或最后一行时切换历史记录
- `Ctrl+R` / `Ctrl+S`：搜索历史记录
- `Ctrl+C`：取消当前输入，或中断可取消操作

### Terminal Control Mode

- `Ctrl+]`：从当前终端会话进入 control mode
- `e` 或 `Esc`：退出 control mode 并回到终端会话
- `q`：从前台终端会话 detach
- `Tab` / `Right`：切换到下一个终端会话
- `Shift+Tab` / `Left`：切换到上一个终端会话
- `Up` / `Down`：按行滚动终端历史
- `Page Up` / `Page Down`：按页滚动终端历史
- `Home`：跳到最早的终端缓存历史
- `End`：回到实时终端输出
