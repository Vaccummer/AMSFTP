#pragma once

#include <algorithm>

#ifdef _WIN32
#include <windows.h>
#else
#include <sys/ioctl.h>
#include <unistd.h>
#endif

namespace AMTerminalTools {

struct TerminalViewportInfo {
  int cols = 80;
  int rows = 24;
  int width = 0;
  int height = 0;
};

inline TerminalViewportInfo GetTerminalViewportInfo() {
  TerminalViewportInfo out = {};
#ifdef _WIN32
  CONSOLE_SCREEN_BUFFER_INFO info = {};
  HANDLE output = GetStdHandle(STD_OUTPUT_HANDLE);
  if (output != INVALID_HANDLE_VALUE &&
      GetConsoleScreenBufferInfo(output, &info) != 0) {
    out.cols = std::max<int>(1, info.srWindow.Right - info.srWindow.Left + 1);
    out.rows = std::max<int>(1, info.srWindow.Bottom - info.srWindow.Top + 1);
  }
#else
  winsize ws = {};
  if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == 0) {
    if (ws.ws_col > 0) {
      out.cols = static_cast<int>(ws.ws_col);
    }
    if (ws.ws_row > 0) {
      out.rows = static_cast<int>(ws.ws_row);
    }
    out.width = static_cast<int>(ws.ws_xpixel);
    out.height = static_cast<int>(ws.ws_ypixel);
  }
#endif
  return out;
}

} // namespace AMTerminalTools

