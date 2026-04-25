# AMSFTP Rust FFI

This crate owns the Rust code exported to the C++ application.

- `toml.rs` implements the TOML read/write bridge used by config storage.
- `vt.rs` implements the VT parser and renderer used by terminal sessions.
- `include/` keeps the stable C ABI headers consumed by the C++ side.

The exported C function names are intentionally kept stable so C++ callers do
not need to know how the Rust modules are organized internally.
