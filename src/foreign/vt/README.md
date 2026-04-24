# AMSFTP VT

Rust terminal emulator backend for AMSFTP interactive channels.

## Current integration

The C++ channel cache feeds server output into the Rust VT through
`AmsVtFeed`, keeps the viewport synchronized with `AmsVtResize`, and uses
`AmsVtGetSnapshot` plus rendered frames to drive foreground terminal redraw.

The VT model owns parsed terminal state:

- main screen
- alternate screen
- scrollback
- cursor position and visibility
- terminal modes, including mouse reporting and application key modes

The C++ cache still keeps raw main/alternate output blocks for fallback,
threshold accounting, and VT rebuild after cache truncation. Interactive redraw
and exported history should prefer VT-rendered content rather than replaying raw
escape sequences.

## Export behavior

`AmsVtRenderMainReplayAnsiUtf8` renders main-screen scrollback plus the current
viewport as ANSI text. `AmsVtRenderVisibleFrameWithOffsetAnsiUtf8` renders the
active visible frame, optionally offset into scrollback.

The C++ `IVtFramePort::RenderPlainTextHistory()` path converts VT-rendered
history to plain text for `channel export <terminal>@<channel> <local-file>`.
ANSI formatting is stripped, and the interface layer appends the result to a
local file after creating missing parent directories.

## Build note

The root build currently links the Rust exports through the `rust_toml_read`
static library, which includes this backend as a path module. Build
`src/foreign/tomlread` in `release` mode before configuring the CMake preset.
