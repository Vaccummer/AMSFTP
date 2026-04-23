#pragma once

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#if defined(AMSFTP_VT_STATIC)
#define AMSFTP_VT_API
#elif defined(_WIN32) || defined(_WIN64)
#if defined(AMSFTP_VT_BUILD_DLL)
#define AMSFTP_VT_API __declspec(dllexport)
#else
#define AMSFTP_VT_API __declspec(dllimport)
#endif
#elif defined(__GNUC__) || defined(__clang__)
#define AMSFTP_VT_API __attribute__((visibility("default")))
#else
#define AMSFTP_VT_API
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
  uint8_t in_alternate_screen;
  uint8_t cursor_visible;
} AmsVtSnapshot;

AMSFTP_VT_API AmsVtHandle *AmsVtCreate(int32_t rows, int32_t cols,
                                       uint64_t scrollback_limit);
AMSFTP_VT_API void AmsVtFree(AmsVtHandle *handle);

AMSFTP_VT_API void AmsVtResize(AmsVtHandle *handle, int32_t rows,
                               int32_t cols);
AMSFTP_VT_API void AmsVtFeed(AmsVtHandle *handle, const uint8_t *data,
                             size_t len);

AMSFTP_VT_API AmsVtSnapshot AmsVtGetSnapshot(const AmsVtHandle *handle);

// Render an alacritty logical line. Negative values address scrollback,
// non-negative values address the visible viewport.
AMSFTP_VT_API char *AmsVtRenderLogicalLineUtf8(const AmsVtHandle *handle,
                                               int32_t line);

// Render a stable buffer line: [oldest scrollback ... visible viewport].
AMSFTP_VT_API char *AmsVtRenderBufferLineUtf8(const AmsVtHandle *handle,
                                              uint64_t index);

// Render main-screen scrollback plus current viewport as ANSI text.
AMSFTP_VT_API char *AmsVtRenderMainReplayAnsiUtf8(const AmsVtHandle *handle);

AMSFTP_VT_API void AmsVtFreeString(char *text);

#ifdef __cplusplus
} // extern "C"
#endif
