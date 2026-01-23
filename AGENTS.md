# Repository Guidelines

## Project Structure & Module Organization
- Core C++ sources and headers live in the repo root (e.g., `AMBinding.cpp`, `AMCore.hpp`, `AMFTPClient.hpp`).
- Python extension stubs are in `AMSFTP/` (`.pyi` files).
- Tests are in `test/` (`.py` and `.cpp` files).
- Build artifacts are in `build/` (e.g., `lib.win-amd64-cpython-310`) and the compiled module appears as `AMSFTP.cp310-win_amd64.pyd`.
- Notes/working docs appear as `*.md` in the root (e.g., `AMSFTPWorker.md`).

## Build, Test, and Development Commands
- `python setup.py build_ext --inplace` — build the C++ extension (Windows/MSVC, C++17).
- `python -m pybind11_stubgen AMSFTP --ignore-all-errors -o .` — regenerate Python stub files in `AMSFTP/`.
- `python test/test_ftp_simple.py` — run a specific Python test file directly.
- For C++ test files (e.g., `test/test_ftp.cpp`), compile with your local toolchain as needed.

## Coding Style & Naming Conventions
- C++ style is enforced by `.clang-format` (LLVM base, 4-space indent, 120 column limit, no tabs, C++17).
- Keep file and type naming consistent with existing patterns (e.g., `AM*` prefixes for library components).
- Prefer one class per header where practical; keep public API headers tidy and stable.

## Testing Guidelines
- Python tests live under `test/` and are runnable directly with `python`.
- C++ tests are standalone compile/run checks in `test/*.cpp`.
- No explicit coverage tooling is configured; add tests alongside changes to public APIs or transfer logic.

## Commit & Pull Request Guidelines
- Recent commits use short, imperative sentences without ticket prefixes (e.g., “add uid to BaseClient”).
- Keep commit messages single-line and focused on the primary change.
- For PRs, include: summary, test commands run, and any external dependencies (e.g., vcpkg libs or DLLs).

## Security & Configuration Notes
- `setup.py` references vcpkg include/lib paths and links to `libssh2`, `libssl`, `libcrypto`, `libcurl`, `zlib`, etc.; ensure these are installed and on PATH where required.
- The project targets Windows (see `.pyd` and MSVC flags). If adding cross‑platform support, document toolchain changes.

## Library Docmentation Lookup
- use "context7" to look up the use of certain library
