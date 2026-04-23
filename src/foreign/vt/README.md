# AMSFTP VT

Rust terminal emulator backend for AMSFTP interactive channels.

## Integration order

1. Split server output into main-screen and alternate-screen blocks in C++.
   Feed only main-screen blocks into `AmsVtFeed`; alternate-screen output stays
   raw and is written directly to the physical terminal while the channel is
   attached.
2. Keep the Rust VT size synchronized with the physical terminal size through
   `AmsVtResize`.
3. Use `AmsVtGetSnapshot` and `AmsVtRenderBufferLineUtf8` to render replay
   content instead of replaying raw escape sequences from C++ caches.
4. Move channel detach cleanup to the Rust-rendered buffer model, so row
   accounting is derived from the emulator state rather than cursor guesses.

The C++ runtime is intentionally not wired to this backend yet. CMake only links
`amsftp_vt.lib` when the Rust static library already exists.
