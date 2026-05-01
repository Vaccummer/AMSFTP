# AMSFTP

[English](./README.md) | [Simplified Chinese](./README.zh-CN.md)

AMSFTP is a C++20 command-line workspace for file operations and terminal access across local, SFTP, FTP, and HTTP targets. It is designed as a compact alternative to switching between `ssh`, `sftp`, shell scripts, and ad-hoc transfer tools.

The project is approaching its first public release. The active implementation lives under `src/`; old migration notes, deprecated prototypes, and local build artifacts are intentionally excluded from the release tree.

## Current Features

- Local, SFTP, FTP, and HTTP download client workflows
- Saved host profiles and quick client switching
- File commands including `stat`, `ls`, `size`, `find`, `mkdir`, `rm`, `tree`, `realpath`, `cp`, `mv`, `rn`, `clone`, and `wget`
- Asynchronous transfer tasks with `task ls`, `task inspect`, `task pause`, `task resume`, and `task terminate`
- Interactive mode through `bash`
- SSH/local terminal sessions through `ssh` and `term`
- Isocline-based completion, highlighting, and command history
- Styled terminal output and configurable prompt profiles

## Repository Layout

```text
src/
  application/      Use-case orchestration
  bootstrap/        Program composition and startup
  domain/           Domain models and ports
  foreign/amsrust/  Rust FFI helpers used by CMake
  foundation/       Shared low-level utilities
  infrastructure/   Concrete client, config, terminal, and transfer adapters
  interface/        CLI parsing, rendering, prompt, completion, and adapters
  third_party/      Vendored Isocline sources
resource/           Windows icon and resource script
config/schema/      Configuration schema
```

## Build Requirements

The bundled presets are currently Windows-oriented.

- CMake 3.20 or newer
- Ninja
- LLVM/Clang with `clang-cl`
- Rust and `cargo`
- vcpkg with these packages installed for the selected triplet:
  OpenSSL, ZLIB, CURL, nlohmann_json, Lua, libssh2, and CLI11

Set `VCPKG_ROOT` before configuring:

```powershell
$env:VCPKG_ROOT = "D:\Compiler\vcpkg"
```

`CMakePresets.json` uses `$env{VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake`, so contributors do not need to edit the preset just because vcpkg is installed in a different directory.

## Build

Configure the static release preset:

```powershell
cmake --preset win-clang-static-release
```

Build the executable:

```powershell
cmake --build --preset win-clang-static-release --target amsftp
```

CMake builds the Rust helper crate in `src/foreign/amsrust` automatically through `cargo build --release --locked`. The release executable is generated at:

```text
build/win-clang-static-release/amsftp.exe
```

Before publishing a release, check these values in `CMakeLists.txt`:

- `AMSFTP_PROGRAM_VERSION`
- `AMSFTP_PASSWORD_KEY`
- `AMSFTP_APP_DESCRIPTION_TEXT`

## First Run

AMSFTP requires `AMSFTP_ROOT` to point to a writable runtime directory:

```powershell
$env:AMSFTP_ROOT = "D:\Data\amsftp"
```

Start interactive mode:

```powershell
.\build\win-clang-static-release\amsftp.exe bash
```

Or inspect the command surface first:

```powershell
.\build\win-clang-static-release\amsftp.exe --help
```

On first run, AMSFTP initializes runtime configuration under `AMSFTP_ROOT`, including:

- `config/config.toml`
- `config/settings.toml`
- `config/known_hosts.toml`
- `config/history.toml`
- `config/bak/`

## Examples

Create and connect to clients:

```text
host add dev
profile edit dev
local self
sftp dev user@example.com -P 22
ftp ftpbox user@example.com -P 21
connect dev
ch dev
```

Run file operations:

```text
ls
stat dev@/var/log/syslog
find dev@/var/log "*.log"
mkdir dev@/tmp/upload
cp @D:\tmp\a.txt dev@/tmp/
clone dev@/data/file.bin @D:\backup\file.bin --resume
wget https://example.com/file.zip @D:\tmp\file.zip --resume
```

Run transfers in the background by appending `&`:

```text
cp @D:\tmp\large.zip dev@/tmp/ --resume &
task ls
task inspect 1
task pause 1
task resume 1
```

Manage terminal sessions:

```text
term add dev@main
ssh dev@main
term ls
term rm dev@main
```

## Path Syntax

Many commands accept `nickname@path` targets:

- `dev@/var/log/syslog` uses the `dev` client
- `@D:\tmp\a.txt` uses the local client
- `/tmp/a.txt` uses the current client
- `@` refers to the local current directory

Interactive input uses the backtick as the escape character:

```text
stat dev@/tmp/a`@b.txt
stat dev@/tmp/price`$1.txt
stat "dev@/tmp/name with spaces.txt"
rm -- -file-starting-with-dash.txt
```

## Variables

Variables are resolved only in path-like arguments, not as general command macros.

```text
var def ${dev:logs} /var/log
var def --global $cache @D:\cache
find dev@${dev:logs} "*.log"
cp dev@${dev:logs}/app.log @D:\logs\app.log
```

## Interactive Keys

- `Tab`: open completion or complete the current token
- `End`: accept an inline completion hint
- `Up` / `Down`: navigate history when the cursor is on the first or last input row
- `Ctrl+R` / `Ctrl+S`: search history
- `Ctrl+C`: cancel prompt input or interrupt a cancellable operation
- `Ctrl+]`: enter terminal session control mode

## Configuration

Use `config save` to explicitly flush configuration changes:

```text
config save
```
