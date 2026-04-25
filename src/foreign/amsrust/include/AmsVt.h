#pragma once

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct AmsVtHandle AmsVtHandle;

typedef struct AmsVtSnapshot {
  int32_t rows;
  int32_t cols;
  int32_t cursor_row;
  int32_t cursor_col;
  uint64_t history_lines;
  uint64_t total_lines;
  uint64_t display_offset;
  uint64_t damage_serial;
  uint64_t rendered_main_rows;
  uint8_t in_alternate_screen;
  uint8_t cursor_visible;
  uint8_t mouse_reporting_active;
  uint8_t mouse_report_click;
  uint8_t mouse_drag;
  uint8_t mouse_motion;
  uint8_t mouse_sgr_encoding;
  uint8_t mouse_utf8_encoding;
  uint8_t app_cursor_keys;
  uint8_t app_keypad;
  uint8_t alternate_scroll;
} AmsVtSnapshot;

AmsVtHandle *AmsVtCreate(int32_t rows, int32_t cols,
                         uint64_t scrollback_limit);
void AmsVtFree(AmsVtHandle *handle);

void AmsVtResize(AmsVtHandle *handle, int32_t rows, int32_t cols);
void AmsVtFeed(AmsVtHandle *handle, const uint8_t *data, size_t len);

AmsVtSnapshot AmsVtGetSnapshot(const AmsVtHandle *handle);

// Render an alacritty logical line. Negative values address scrollback,
// non-negative values address the visible viewport.
char *AmsVtRenderLogicalLineUtf8(const AmsVtHandle *handle, int32_t line);

// Render a stable buffer line: [oldest scrollback ... visible viewport].
char *AmsVtRenderBufferLineUtf8(const AmsVtHandle *handle, uint64_t index);

// Render main-screen scrollback plus current viewport as ANSI text.
char *AmsVtRenderMainReplayAnsiUtf8(const AmsVtHandle *handle);

// Render the currently visible active screen viewport as ANSI text.
char *AmsVtRenderVisibleFrameAnsiUtf8(const AmsVtHandle *handle);
char *AmsVtRenderVisibleFrameWithOffsetAnsiUtf8(const AmsVtHandle *handle,
                                                uint64_t viewport_offset);

void AmsVtFreeString(char *text);

#ifdef __cplusplus
} // extern "C"
#endif
