# AMSFTP

[English](./README.md) | [简体中文](./README.zh-CN.md)

AMSFTP is a C++20 command-line tool for multi-host file and terminal workflows. It combines local, SFTP, FTP, and HTTP download operations in one CLI, with support for saved host profiles, asynchronous transfer tasks, interactive shell sessions, and prompt completion.

## 🚀 Project Overview

AMSFTP is designed for users who want one command-line entry point for both file operations and terminal access across multiple environments.

Current code in this repository provides:

- Local, SFTP, and FTP client switching
- Host, profile, config, client, pool, and variable management
- File operations such as `stat`, `ls`, `size`, `find`, `mkdir`, `rm`, `tree`, `realpath`, `cp`, `mv`, `clone`, and `wget`
- Terminal workflows such as `ssh`, `term`, and `channel`
- Asynchronous transfer task control with `task ls`, `task inspect`, `task pause`, `task resume`, and `task terminate`
- Interactive mode via `bash`, with integrated completion and highlighting

Before startup, AMSFTP requires the `AMSFTP_ROOT` environment variable. On first run it initializes these files under that directory:

- `config/config.toml`
- `config/settings.toml`
- `config/known_hosts.toml`
- `config/history.toml`
- `config/bak/`

## 🛠️ Build

### Prerequisites

The repository currently provides Windows-oriented CMake presets.

- CMake 3.20 or newer
- Ninja
- LLVM/Clang with `clang-cl`
- Rust and `cargo`
- `vcpkg`

The active CMake build links these libraries from `vcpkg`:

- OpenSSL
- ZLIB
- CURL
- nlohmann_json
- Lua
- libssh2
- CLI11

If your local `vcpkg` path differs from the one in [CMakePresets.json](/d:/CodeLib/CPP/AMSFTP/CMakePresets.json), update the `CMAKE_TOOLCHAIN_FILE` value before configuring.

### Build Steps

1. Build the Rust TOML helper library in `release` mode.

`CMakeLists.txt` currently searches `rust_toml_read.lib` only in `src/foreign/tomlread/target/release`, so this step should stay as `--release` even if you plan to build AMSFTP with a debug preset.

```powershell
Set-Location .\src\foreign\tomlread
cargo build --release
Set-Location ..\..\..
```

2. Configure the project:

```powershell
cmake --preset win-clang-debug
```

3. Build the executable:

```powershell
cmake --build --preset win-clang-debug --target amsftp
```

`CMakePresets.json` sets:

```text
binaryDir = ${sourceDir}/build/${presetName}
```

So with the `win-clang-debug` preset, the generated binary is:

```text
build/win-clang-debug/amsftp.exe
```

Other available presets are:

- `win-clang-debug`
- `win-clang-static-debug`
- `win-clang-release`
- `win-clang-static-release`

## 💡 Usage

### Initial Setup

Set `AMSFTP_ROOT` to a writable directory before running the program:

```powershell
$env:AMSFTP_ROOT = "D:\Data\amsftp"
```

Then start AMSFTP. For example:

```powershell
.\build\win-clang-debug\amsftp.exe bash
```

If you only want to inspect help first:

```powershell
.\build\win-clang-debug\amsftp.exe --help
```

### Common Workflows Inside AMSFTP

Create or inspect saved hosts:

```text
host add dev
host ls -d
profile edit dev
```

Connect to local, SFTP, or FTP targets:

```text
local
sftp dev user@example.com -P 22
ftp ftpbox user@example.com -P 21
connect dev
```

Run filesystem commands:

```text
ls
stat dev@/var/log/syslog
find dev@/var/log "*.log"
cp @D:\tmp\a.txt dev@/tmp/
wget https://example.com/file.zip @D:\tmp\file.zip
```

Open terminal sessions:

```text
ssh dev@main
term ls
channel ls dev
```

Manage asynchronous transfer tasks:

```text
task ls -c
task inspect 12 -s -e
task pause 12
task resume 12
task terminate 12
```

Save config changes:

```text
config save
```

In interactive mode, AMSFTP keeps the current client or session context and provides completion and highlighting. Typing `bash` from a non-interactive start enters this workflow.

### Path Target Syntax

Many file commands accept a `nickname@path` style target:

- `dev@/var/log/syslog`: use client `dev`
- `@D:\tmp\a.txt`: use the local client
- `/tmp/a.txt`: use the current client
- `@`: refer to the local current directory
