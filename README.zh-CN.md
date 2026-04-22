# AMSFTP

[English](./README.md) | [简体中文](./README.zh-CN.md)

AMSFTP 是一个基于 C++20 的命令行工具，用于多主机文件管理与终端工作流。它把本地、SFTP、FTP 和 HTTP 下载能力整合到同一个 CLI 中，并提供主机配置保存、异步传输任务、交互式终端以及命令补全能力。

## 项目简介

AMSFTP 面向希望通过一个命令行入口统一处理“文件操作 + 终端访问”的用户场景。

当前仓库中的代码已经提供以下能力：

- 在本地、SFTP、FTP 客户端之间切换
- 管理 host、profile、config、client、pool 和变量
- 执行 `stat`、`ls`、`size`、`find`、`mkdir`、`rm`、`tree`、`realpath`、`cp`、`mv`、`clone`、`wget` 等文件操作
- 执行 `ssh`、`term`、`channel` 等终端相关工作流
- 通过 `task ls`、`task inspect`、`task pause`、`task resume`、`task terminate` 管理异步传输任务
- 通过 `bash` 进入交互模式，并使用补全与高亮

AMSFTP 启动前需要设置环境变量 `AMSFTP_ROOT`。程序首次运行时会在该目录下初始化以下文件：

- `config/config.toml`
- `config/settings.toml`
- `config/known_hosts.toml`
- `config/history.toml`
- `config/bak/`

## 如何 Build

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

如果你的本地 `vcpkg` 路径与 [CMakePresets.json](/d:/CodeLib/CPP/AMSFTP/CMakePresets.json) 中配置的不一致，需要先修改其中的 `CMAKE_TOOLCHAIN_FILE`。

### 构建步骤

1. 先构建 Rust TOML 辅助库：

```powershell
Set-Location .\src\foreign\tomlread
cargo build --release
Set-Location ..\..\..
```

2. 配置项目：

```powershell
cmake --preset win-clang-debug
```

3. 编译可执行文件：

```powershell
cmake --build --preset win-clang-debug --target amsftp
```

生成的程序路径为：

```text
build/win-clang-debug/amsftp.exe
```

仓库中还提供以下 preset：

- `win-clang-debug`
- `win-clang-static-debug`
- `win-clang-release`
- `win-clang-static-release`

## 如何使用

### 初始设置

运行程序前，先把 `AMSFTP_ROOT` 设置为一个可写目录：

```powershell
$env:AMSFTP_ROOT = "D:\Data\amsftp"
```

然后查看顶层帮助：

```powershell
.\build\win-clang-debug\amsftp.exe --help
```

也可以查看某个命令组的帮助：

```powershell
.\build\win-clang-debug\amsftp.exe host --help
.\build\win-clang-debug\amsftp.exe task --help
```

### 常见工作流

创建或查看已保存的主机：

```powershell
.\build\win-clang-debug\amsftp.exe host add dev
.\build\win-clang-debug\amsftp.exe host ls -d
.\build\win-clang-debug\amsftp.exe profile edit dev
```

连接本地、SFTP 或 FTP 目标：

```powershell
.\build\win-clang-debug\amsftp.exe local
.\build\win-clang-debug\amsftp.exe sftp dev user@example.com -P 22
.\build\win-clang-debug\amsftp.exe ftp ftpbox user@example.com -P 21
.\build\win-clang-debug\amsftp.exe connect dev
```

执行文件系统命令：

```powershell
.\build\win-clang-debug\amsftp.exe ls
.\build\win-clang-debug\amsftp.exe stat dev@/var/log/syslog
.\build\win-clang-debug\amsftp.exe find dev@/var/log "*.log"
.\build\win-clang-debug\amsftp.exe cp @D:\tmp\a.txt dev@/tmp/
.\build\win-clang-debug\amsftp.exe wget https://example.com/file.zip @D:\tmp\file.zip
```

打开终端会话：

```powershell
.\build\win-clang-debug\amsftp.exe ssh dev@main
.\build\win-clang-debug\amsftp.exe term ls
.\build\win-clang-debug\amsftp.exe channel ls dev
```

管理异步传输任务：

```powershell
.\build\win-clang-debug\amsftp.exe task ls -c
.\build\win-clang-debug\amsftp.exe task inspect 12 -s -e
.\build\win-clang-debug\amsftp.exe task pause 12
.\build\win-clang-debug\amsftp.exe task resume 12
.\build\win-clang-debug\amsftp.exe task terminate 12
```

进入交互模式：

```powershell
.\build\win-clang-debug\amsftp.exe bash
```

在交互模式中，AMSFTP 会保留当前 client/session 上下文，并提供命令补全与高亮。

### 路径目标语法

很多文件命令都支持 `nickname@path` 形式的目标：

- `dev@/var/log/syslog`：使用 `dev` 客户端
- `@D:\tmp\a.txt`：使用本地客户端
- `/tmp/a.txt`：使用当前客户端
- `@`：表示本地当前目录

### 保存配置

当你修改了 host、profile 或 settings 后，可以执行：

```powershell
.\build\win-clang-debug\amsftp.exe config save
```
