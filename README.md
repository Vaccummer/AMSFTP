# AMSFTP

[English](./README.md) | [简体中文](./README.zh-CN.md)

AMSFTP is a C++20 command-line tool for multi-host file and terminal workflows. It combines local, SFTP, FTP, and HTTP download operations in one CLI, with saved host profiles, asynchronous transfer tasks, interactive terminal sessions, command completion, and styled output.

## 🚀 Project Overview

AMSFTP is designed as one command-line entry point for file operations and terminal access across multiple environments.

Current code in this repository provides:

- Local, SFTP, and FTP client switching
- Host, profile, config, client, pool, and variable management
- File operations such as `stat`, `ls`, `size`, `find`, `mkdir`, `rm`, `tree`, `realpath`, `cp`, `mv`, `clone`, and `wget`
- Terminal workflows such as `ssh` and `term`
- Asynchronous transfer task control with `task ls`, `task inspect`, `task pause`, `task resume`, and `task terminate`
- Interactive mode via `bash`, with Isocline-based completion, highlighting, and history

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

### Values To Check Before Building

Check these values before configuring the project:

- In [CMakePresets.json](./CMakePresets.json), make sure `CMAKE_TOOLCHAIN_FILE` points to your local `vcpkg.cmake`.
- In [CMakePresets.json](./CMakePresets.json), the release static preset uses `VCPKG_TARGET_TRIPLET=x64-windows-static`.
- In [CMakeLists.txt](./CMakeLists.txt), `CMAKE_MSVC_RUNTIME_LIBRARY` is set to `MultiThreaded`.
- In [CMakeLists.txt](./CMakeLists.txt), `AMSFTP_PROGRAM_NAME` controls the compiled program name shown in version text.
- In [CMakeLists.txt](./CMakeLists.txt), update `AMSFTP_PROGRAM_VERSION` when making a release.
- In [CMakeLists.txt](./CMakeLists.txt), change `AMSFTP_PASSWORD_KEY` for real private builds instead of keeping the default demo key.

### Build Steps

1. Build the Rust helper library in `release` mode.

`CMakeLists.txt` currently searches `rust_toml_read.lib` only in `src/foreign/tomlread/target/release`, so this step should stay as `--release`. This crate also includes the Rust VT backend exports used by interactive terminal history rendering.

```powershell
Set-Location .\src\foreign\tomlread
cargo build --release
Set-Location ..\..\..
```

2. Configure the static release preset:

```powershell
cmake --preset win-clang-static-release
```

3. Build AMSFTP:

```powershell
cmake --build --preset win-clang-static-release --target amsftp
```

`CMakePresets.json` sets:

```text
binaryDir = ${sourceDir}/build/${presetName}
```

So with `win-clang-static-release`, the generated binary is:

```text
build/win-clang-static-release/amsftp.exe
```

## 💡 Usage

### Initial Setup

Set `AMSFTP_ROOT` to a writable directory before running the program:

```powershell
$env:AMSFTP_ROOT = "D:\Data\amsftp"
```

Start interactive mode:

```powershell
.\build\win-clang-static-release\amsftp.exe bash
```

If you only want to inspect help first:

```powershell
.\build\win-clang-static-release\amsftp.exe --help
```

The following examples are AMSFTP commands typed inside interactive mode.

### Hosts And Clients

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

### File Operations

```text
ls
stat dev@/var/log/syslog
mkdir dev@/tmp/upload
rm dev@/tmp/old.txt
realpath dev@../logs
```

`find` has two forms:

```text
find dev@/var/log/**/*.log
find dev@/var/log "*.log"
```

The first form treats the single argument as the full search pattern. The second form searches recursively under the path using the pattern, internally like `path/**/pattern`. Supported pattern features include `*`, `**`, and character classes such as `<abc>`.

Transfer examples:

```text
cp @D:\tmp\a.txt dev@/tmp/
cp @D:\tmp\large.zip dev@/tmp/ --resume
cp @D:\tmp\a.txt @D:\tmp\b.txt --output dev@/tmp/
cp @D:\tmp\a.txt dev@/tmp/ &
clone dev@/data/file.bin @D:\backup\file.bin --resume
wget https://example.com/file.zip @D:\tmp\file.zip --resume
```

Useful transfer flags:

- `--resume`: resume from an existing destination file when possible
- `--force`: overwrite existing targets
- `--output`: provide the destination when copying multiple sources
- trailing `&`: run the transfer asynchronously

### Variables

AMSFTP variables are not macros. Variable replacement only happens in path-like arguments, such as filesystem paths, transfer paths, and download destinations. It does not rewrite arbitrary command text or option names.

```text
var def ${dev:logs} /var/log
var def --global $cache @D:\cache
var ls
var get ${dev:logs}
var del ${dev:logs}
```

Interactive shortcuts are also supported:

```text
$logs=/var/log
$
${dev:}
```

Variable lookup rules:

- `$name` defines or reads a variable in the current client zone.
- `var def --global $name value` stores a public variable.
- `${zone:name}` explicitly selects a zone.
- `${:name}` explicitly selects the public zone.
- In path substitution, unqualified `$name` resolves from the current client zone; use `${:name}` when you want a public variable in a path.
- A `nickname@path` target does not change variable lookup scope. Use `${dev:name}` when the variable belongs to `dev`.

Example:

```text
var def ${dev:logs} /var/log
find dev@${dev:logs} "*.log"
cp dev@${dev:logs}/app.log @D:\logs\app.log
```

### Escaping

Interactive input uses the backtick character as the escape character.

```text
stat dev@/tmp/a`@b.txt
stat dev@/tmp/price`$1.txt
stat "dev@/tmp/name with spaces.txt"
stat "dev@/tmp/a`"quoted`".txt"
rm -- -file-starting-with-dash.txt
stat "-file-starting-with-dash.txt"
```

Important escaping rules:

- Use quotes for whitespace in one argument.
- Use `` `@`` for a literal `@` inside a path so it is not treated as a client separator.
- Use `` `$`` for a literal `$` so it is not treated as a variable.
- Use `` `"`` or `` `'`` inside quoted strings.
- Use `--` before positional arguments that could be confused with options.
- In interactive mode, quoted path literals that start with `-` are normalized to `./-name`.
- `!command` is shorthand for `cmd command`, for example `!pwd`.

### Terminal Sessions

```text
term add dev@main
ssh dev@main
ssh main
ssh
term ls
term rm dev@main
```

Term target syntax is `host@name` or just `name`. `ssh name` resolves the term under the current client, while bare `ssh` re-enters the last term used during the current program run.

Terminal shortcuts:

- `Ctrl+]`: enter God Mode.
- In God Mode, `Esc` returns to the current term, `Ctrl+]` sends a literal `Ctrl+]`, `Left` or `Shift+Tab` switches to the previous term, `Right` or `Tab` switches to the next term, and `q` detaches back to the AMSFTP prompt.
- Exiting the remote or local shell closes the term normally.
- `term ls` shows reusable terms after detaching.

Terminal prompt templates in `config/settings.toml` can also use these Lua globals:

- `term_num`: total managed terms
- `term_ok`, `term_disconnected`: term session state counts

### Interactive Shortcuts

AMSFTP uses Isocline for the interactive prompt. Common keys:

- `Tab`: open completion or complete the current token
- `End`: accept an inline completion hint when one is shown
- `Up` / `Down`: navigate history when the cursor is on the first or last input row
- `Ctrl+P` / `Ctrl+N`: previous or next history entry
- `Ctrl+R` / `Ctrl+S`: history search
- `Ctrl+A` / `Ctrl+E`: move to line start or end
- `Ctrl+B` / `Ctrl+F`: move left or right
- `Ctrl+Left` / `Ctrl+Right`, or `Alt+B` / `Alt+F`: move by word
- `Ctrl+U` / `Ctrl+K`: delete to line start or end
- `Ctrl+W`: delete the previous whitespace-separated word
- `Alt+D`: delete to the end of the next word
- `Ctrl+L`: clear the screen
- `Ctrl+Z` or `Ctrl+_`: undo
- `Ctrl+Y`: redo
- `F1`: show Isocline help
- `Ctrl+C`: cancel the current prompt input or interrupt a cancellable operation

### Save Config Changes

```text
config save
```

Config is also flushed by many command paths, but `config save` is the explicit command to persist changes.

### Path Target Syntax

Many file commands accept a `nickname@path` style target:

- `dev@/var/log/syslog`: use client `dev`
- `@D:\tmp\a.txt`: use the local client
- `/tmp/a.txt`: use the current client
- `@`: refer to the local current directory
