# AMSFTP

[English](./README.md) | [简体中文](./README.zh-CN.md)

AMSFTP is a C++20 command-line tool for multi-host file and terminal workflows. It combines local, SFTP, FTP, and HTTP download operations in one CLI, with support for saved host profiles, asynchronous transfer tasks, interactive shell sessions, and prompt completion.

## Project Overview

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

## Build

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

1. Build the Rust TOML helper library:

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

The generated binary is:

```text
build/win-clang-debug/amsftp.exe
```

Other available presets are:

- `win-clang-debug`
- `win-clang-static-debug`
- `win-clang-release`
- `win-clang-static-release`

## Usage

### Initial Setup

Set `AMSFTP_ROOT` to a writable directory before running the program:

```powershell
$env:AMSFTP_ROOT = "D:\Data\amsftp"
```

Then check the top-level help:

```powershell
.\build\win-clang-debug\amsftp.exe --help
```

You can also inspect a specific command group:

```powershell
.\build\win-clang-debug\amsftp.exe host --help
.\build\win-clang-debug\amsftp.exe task --help
```

### Common Workflows

Create or inspect saved hosts:

```powershell
.\build\win-clang-debug\amsftp.exe host add dev
.\build\win-clang-debug\amsftp.exe host ls -d
.\build\win-clang-debug\amsftp.exe profile edit dev
```

Connect to local, SFTP, or FTP targets:

```powershell
.\build\win-clang-debug\amsftp.exe local
.\build\win-clang-debug\amsftp.exe sftp dev user@example.com -P 22
.\build\win-clang-debug\amsftp.exe ftp ftpbox user@example.com -P 21
.\build\win-clang-debug\amsftp.exe connect dev
```

Run filesystem commands:

```powershell
.\build\win-clang-debug\amsftp.exe ls
.\build\win-clang-debug\amsftp.exe stat dev@/var/log/syslog
.\build\win-clang-debug\amsftp.exe find dev@/var/log "*.log"
.\build\win-clang-debug\amsftp.exe cp @D:\tmp\a.txt dev@/tmp/
.\build\win-clang-debug\amsftp.exe wget https://example.com/file.zip @D:\tmp\file.zip
```

Open terminal sessions:

```powershell
.\build\win-clang-debug\amsftp.exe ssh dev@main
.\build\win-clang-debug\amsftp.exe term ls
.\build\win-clang-debug\amsftp.exe channel ls dev
```

Manage asynchronous transfer tasks:

```powershell
.\build\win-clang-debug\amsftp.exe task ls -c
.\build\win-clang-debug\amsftp.exe task inspect 12 -s -e
.\build\win-clang-debug\amsftp.exe task pause 12
.\build\win-clang-debug\amsftp.exe task resume 12
.\build\win-clang-debug\amsftp.exe task terminate 12
```

Enter interactive mode:

```powershell
.\build\win-clang-debug\amsftp.exe bash
```

Inside interactive mode, AMSFTP keeps the current client/session context and provides command completion and highlighting.

### Path Target Syntax

Many file commands accept a `nickname@path` style target:

- `dev@/var/log/syslog`: use client `dev`
- `@D:\tmp\a.txt`: use the local client
- `/tmp/a.txt`: use the current client
- `@`: refer to the local current directory

### Save Config Changes

After editing hosts, profiles, or settings, persist changes with:

```powershell
.\build\win-clang-debug\amsftp.exe config save
```
