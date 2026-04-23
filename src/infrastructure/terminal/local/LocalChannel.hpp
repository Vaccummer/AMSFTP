#pragma once

#include "foundation/tools/string.hpp"
#include "infrastructure/terminal/ChannelCachePort.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#ifndef PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE
#define PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE 0x00020016
#endif
#else
#include <cerrno>
#include <csignal>
#include <cstring>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#if defined(__linux__)
#include <pty.h>
#elif defined(__APPLE__) || defined(__FreeBSD__)
#include <util.h>
#endif
#endif

namespace AMInfra::client::LOCAL::terminal {
namespace AMT = AMDomain::terminal;
using AMInfra::terminal::ChannelCacheStore;
namespace detail {

struct ChannelIdentity_ {
  std::string terminal_key = {};
  std::string channel_name = {};
};

struct ChannelRuntimeAttrs_ {
  bool eof = false;
  bool process_exited = false;
  int exit_status = -1;
  ECM state = OK;
  int window_cols = 80;
  int window_rows = 24;
  int window_width = 0;
  int window_height = 0;
  std::string term = "xterm-256color";
#ifdef _WIN32
  void *pseudo_console = nullptr;
  HANDLE input_write = INVALID_HANDLE_VALUE;
  HANDLE output_read = INVALID_HANDLE_VALUE;
  HANDLE process_handle = INVALID_HANDLE_VALUE;
#else
  int master_fd = -1;
  pid_t child_pid = -1;
#endif
};

struct ChannelForegroundAttrs_ {
  std::string send_buffer = {};
  int last_cols = -1;
  int last_rows = -1;
  bool foreground_bound = false;
  bool detach_requested = false;
  bool closed = false;
  ECM last_error = OK;
  std::intptr_t key_event_handle = -1;
  AMAtomic<std::vector<char>> *key_cache = nullptr;
};

#ifdef _WIN32
struct ChannelLoopEvents_ {
  HANDLE state_wait_handle = nullptr;
};

struct ConPTYApi_ {
  using CreatePseudoConsoleFn = HRESULT(WINAPI *)(COORD, HANDLE, HANDLE, DWORD,
                                                  void **);
  using ResizePseudoConsoleFn = HRESULT(WINAPI *)(void *, COORD);
  using ClosePseudoConsoleFn = void(WINAPI *)(void *);

  HMODULE kernel = nullptr;
  CreatePseudoConsoleFn create = nullptr;
  ResizePseudoConsoleFn resize = nullptr;
  ClosePseudoConsoleFn close = nullptr;

  ConPTYApi_() {
    kernel = GetModuleHandleW(L"kernel32.dll");
    if (kernel == nullptr) {
      return;
    }
    create = reinterpret_cast<CreatePseudoConsoleFn>(
        GetProcAddress(kernel, "CreatePseudoConsole"));
    resize = reinterpret_cast<ResizePseudoConsoleFn>(
        GetProcAddress(kernel, "ResizePseudoConsole"));
    close = reinterpret_cast<ClosePseudoConsoleFn>(
        GetProcAddress(kernel, "ClosePseudoConsole"));
  }

  [[nodiscard]] bool IsAvailable() const {
    return create != nullptr && resize != nullptr && close != nullptr;
  }
};

[[nodiscard]] inline const ConPTYApi_ &ConPTYApiInstance_() {
  static const ConPTYApi_ api = {};
  return api;
}

inline void CloseHandleSafe_(HANDLE *handle) {
  if (handle != nullptr && *handle != nullptr &&
      *handle != INVALID_HANDLE_VALUE) {
    (void)CloseHandle(*handle);
    *handle = INVALID_HANDLE_VALUE;
  }
}

inline void ClosePseudoConsoleSafe_(void **pseudo_console) {
  if (pseudo_console == nullptr || *pseudo_console == nullptr) {
    return;
  }
  const auto &api = ConPTYApiInstance_();
  if (api.close != nullptr) {
    api.close(*pseudo_console);
  }
  *pseudo_console = nullptr;
}

inline void UpdateWindowsProcessState_(ChannelRuntimeAttrs_ *runtime) {
  if (runtime == nullptr || runtime->process_handle == INVALID_HANDLE_VALUE) {
    return;
  }
  DWORD code = STILL_ACTIVE;
  if (GetExitCodeProcess(runtime->process_handle, &code) == 0) {
    return;
  }
  if (code != STILL_ACTIVE) {
    runtime->process_exited = true;
    runtime->exit_status = static_cast<int>(code);
  }
}

[[nodiscard]] inline bool DrainWindowsOutput_(ChannelRuntimeAttrs_ *runtime,
                                              std::string *output,
                                              size_t max_bytes) {
  if (runtime == nullptr || output == nullptr ||
      runtime->output_read == INVALID_HANDLE_VALUE || max_bytes == 0U) {
    return false;
  }
  bool wrote = false;
  std::array<char, 4096> buffer = {};
  while (output->size() < max_bytes) {
    DWORD available = 0;
    if (PeekNamedPipe(runtime->output_read, nullptr, 0, nullptr, &available,
                      nullptr) == 0) {
      runtime->eof = true;
      break;
    }
    if (available == 0) {
      break;
    }
    const DWORD want = static_cast<DWORD>(std::min<size_t>(
        static_cast<size_t>(available),
        std::min<size_t>(buffer.size(), max_bytes - output->size())));
    DWORD nread = 0;
    if (ReadFile(runtime->output_read, buffer.data(), want, &nread, nullptr) ==
        0) {
      runtime->eof = true;
      break;
    }
    if (nread == 0) {
      break;
    }
    output->append(buffer.data(), static_cast<size_t>(nread));
    wrote = true;
  }
  return wrote;
}

[[nodiscard]] inline bool WaitReadableWindows_(ChannelRuntimeAttrs_ *runtime,
                                               const ControlComponent &control,
                                               bool *timed_out) {
  if (timed_out != nullptr) {
    *timed_out = false;
  }
  if (runtime == nullptr) {
    if (timed_out != nullptr) {
      *timed_out = true;
    }
    return false;
  }

  auto deadline = std::chrono::steady_clock::time_point::max();
  const auto remain_opt = control.RemainingTimeMs();
  if (remain_opt.has_value()) {
    deadline = std::chrono::steady_clock::now() +
               std::chrono::milliseconds(*remain_opt);
  }

  while (true) {
    if (control.IsInterrupted()) {
      return false;
    }
    if (control.IsTimeout()) {
      if (timed_out != nullptr) {
        *timed_out = true;
      }
      return false;
    }

    std::array<HANDLE, 2> handles = {runtime->output_read,
                                     runtime->process_handle};
    DWORD count = 0;
    if (runtime->output_read != INVALID_HANDLE_VALUE) {
      handles[count++] = runtime->output_read;
    }
    if (runtime->process_handle != INVALID_HANDLE_VALUE) {
      handles[count++] = runtime->process_handle;
    }
    if (count == 0) {
      if (timed_out != nullptr) {
        *timed_out = true;
      }
      return false;
    }

    DWORD slice = 100;
    if (deadline != std::chrono::steady_clock::time_point::max()) {
      const auto now = std::chrono::steady_clock::now();
      if (now >= deadline) {
        if (timed_out != nullptr) {
          *timed_out = true;
        }
        return false;
      }
      const auto remain =
          std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now);
      slice = static_cast<DWORD>(std::min<int64_t>(
          static_cast<int64_t>(slice), std::max<int64_t>(1, remain.count())));
    }

    const DWORD wait_rc =
        WaitForMultipleObjects(count, handles.data(), FALSE, slice);
    if (wait_rc == WAIT_TIMEOUT) {
      continue;
    }
    if (wait_rc >= WAIT_OBJECT_0 && wait_rc < WAIT_OBJECT_0 + count) {
      return true;
    }
    if (wait_rc == WAIT_FAILED) {
      return false;
    }
  }
}

inline ECM OpenChannelWindows_(ChannelRuntimeAttrs_ *runtime,
                               const AMT::ChannelInitArgs &init_args) {
  if (runtime == nullptr) {
    return Err(EC::InvalidArg, "terminal.channel.init", "channel",
               "Channel runtime is null");
  }

  const auto &api = ConPTYApiInstance_();
  if (!api.IsAvailable()) {
    return Err(EC::OperationUnsupported, "terminal.channel.init", "conpty",
               "ConPTY API is unavailable on current Windows runtime");
  }

  SECURITY_ATTRIBUTES sa = {};
  sa.nLength = sizeof(sa);
  sa.bInheritHandle = TRUE;
  sa.lpSecurityDescriptor = nullptr;

  HANDLE input_read = INVALID_HANDLE_VALUE;
  HANDLE input_write = INVALID_HANDLE_VALUE;
  HANDLE output_read = INVALID_HANDLE_VALUE;
  HANDLE output_write = INVALID_HANDLE_VALUE;
  if (CreatePipe(&input_read, &input_write, &sa, 0) == 0) {
    return Err(EC::CommonFailure, "terminal.channel.init", "conpty",
               "CreatePipe failed for terminal input");
  }
  if (CreatePipe(&output_read, &output_write, &sa, 0) == 0) {
    CloseHandleSafe_(&input_read);
    CloseHandleSafe_(&input_write);
    return Err(EC::CommonFailure, "terminal.channel.init", "conpty",
               "CreatePipe failed for terminal output");
  }
  (void)SetHandleInformation(input_write, HANDLE_FLAG_INHERIT, 0);
  (void)SetHandleInformation(output_read, HANDLE_FLAG_INHERIT, 0);

  COORD size = {};
  size.X = static_cast<SHORT>(std::max(1, init_args.cols));
  size.Y = static_cast<SHORT>(std::max(1, init_args.rows));

  void *pseudo_console = nullptr;
  const HRESULT create_hr =
      api.create(size, input_read, output_write, 0, &pseudo_console);
  CloseHandleSafe_(&input_read);
  CloseHandleSafe_(&output_write);
  if (FAILED(create_hr) || pseudo_console == nullptr) {
    CloseHandleSafe_(&input_write);
    CloseHandleSafe_(&output_read);
    return Err(EC::OperationUnsupported, "terminal.channel.init", "conpty",
               AMStr::fmt("CreatePseudoConsole failed (hr=0x{:08X})",
                          static_cast<unsigned int>(create_hr)));
  }

  SIZE_T attr_size = 0;
  (void)InitializeProcThreadAttributeList(nullptr, 1, 0, &attr_size);
  std::vector<char> attr_buffer(attr_size);
  auto *attr_list =
      reinterpret_cast<PPROC_THREAD_ATTRIBUTE_LIST>(attr_buffer.data());
  if (InitializeProcThreadAttributeList(attr_list, 1, 0, &attr_size) == 0) {
    ClosePseudoConsoleSafe_(&pseudo_console);
    CloseHandleSafe_(&input_write);
    CloseHandleSafe_(&output_read);
    return Err(EC::CommonFailure, "terminal.channel.init", "conpty",
               "InitializeProcThreadAttributeList failed");
  }

  const BOOL update_ok = UpdateProcThreadAttribute(
      attr_list, 0, PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE, pseudo_console,
      sizeof(pseudo_console), nullptr, nullptr);
  if (update_ok == 0) {
    DeleteProcThreadAttributeList(attr_list);
    ClosePseudoConsoleSafe_(&pseudo_console);
    CloseHandleSafe_(&input_write);
    CloseHandleSafe_(&output_read);
    return Err(EC::CommonFailure, "terminal.channel.init", "conpty",
               "UpdateProcThreadAttribute failed");
  }

  STARTUPINFOEXW startup = {};
  startup.StartupInfo.cb = sizeof(STARTUPINFOEXW);
  startup.lpAttributeList = attr_list;
  PROCESS_INFORMATION proc = {};
  std::wstring cmd = L"cmd.exe";
  const BOOL created =
      CreateProcessW(nullptr, cmd.data(), nullptr, nullptr, FALSE,
                     EXTENDED_STARTUPINFO_PRESENT, nullptr, nullptr,
                     &startup.StartupInfo, &proc);
  DeleteProcThreadAttributeList(attr_list);
  if (created == 0) {
    ClosePseudoConsoleSafe_(&pseudo_console);
    CloseHandleSafe_(&input_write);
    CloseHandleSafe_(&output_read);
    return Err(EC::CommonFailure, "terminal.channel.init", "cmd.exe",
               "CreateProcessW failed");
  }

  CloseHandleSafe_(&proc.hThread);
  runtime->pseudo_console = pseudo_console;
  runtime->input_write = input_write;
  runtime->output_read = output_read;
  runtime->process_handle = proc.hProcess;
  runtime->process_exited = false;
  runtime->eof = false;
  runtime->exit_status = -1;
  return OK;
}
#else
inline void UpdatePosixProcessState_(ChannelRuntimeAttrs_ *runtime) {
  if (runtime == nullptr || runtime->child_pid <= 0 ||
      runtime->process_exited) {
    return;
  }
  int status = 0;
  const pid_t rc = waitpid(runtime->child_pid, &status, WNOHANG);
  if (rc != runtime->child_pid) {
    return;
  }
  runtime->process_exited = true;
  if (WIFEXITED(status)) {
    runtime->exit_status = WEXITSTATUS(status);
  } else if (WIFSIGNALED(status)) {
    runtime->exit_status = 128 + WTERMSIG(status);
  } else {
    runtime->exit_status = -1;
  }
  runtime->child_pid = -1;
}

[[nodiscard]] inline bool DrainPosixOutput_(ChannelRuntimeAttrs_ *runtime,
                                            std::string *output,
                                            size_t max_bytes) {
  if (runtime == nullptr || output == nullptr || runtime->master_fd < 0 ||
      max_bytes == 0U) {
    return false;
  }
  bool wrote = false;
  std::array<char, 4096> buffer = {};
  while (output->size() < max_bytes) {
    const size_t cap =
        std::min<size_t>(buffer.size(), max_bytes - output->size());
    const ssize_t n = read(runtime->master_fd, buffer.data(), cap);
    if (n > 0) {
      output->append(buffer.data(), static_cast<size_t>(n));
      wrote = true;
      continue;
    }
    if (n == 0) {
      runtime->eof = true;
    }
    if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
      runtime->eof = true;
    }
    break;
  }
  return wrote;
}

[[nodiscard]] inline bool WaitReadablePosix_(ChannelRuntimeAttrs_ *runtime,
                                             const ControlComponent &control,
                                             bool *timed_out) {
  if (timed_out != nullptr) {
    *timed_out = false;
  }
  if (runtime == nullptr || runtime->master_fd < 0) {
    if (timed_out != nullptr) {
      *timed_out = true;
    }
    return false;
  }

  auto deadline = std::chrono::steady_clock::time_point::max();
  const auto remain_opt = control.RemainingTimeMs();
  if (remain_opt.has_value()) {
    deadline = std::chrono::steady_clock::now() +
               std::chrono::milliseconds(*remain_opt);
  }

  while (true) {
    if (control.IsInterrupted()) {
      return false;
    }
    if (control.IsTimeout()) {
      if (timed_out != nullptr) {
        *timed_out = true;
      }
      return false;
    }
    fd_set readfds = {};
    FD_ZERO(&readfds);
    FD_SET(runtime->master_fd, &readfds);
    timeval tv = {};
    timeval *tv_ptr = nullptr;
    if (deadline != std::chrono::steady_clock::time_point::max()) {
      const auto now = std::chrono::steady_clock::now();
      if (now >= deadline) {
        if (timed_out != nullptr) {
          *timed_out = true;
        }
        return false;
      }
      const auto remain =
          std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now);
      tv.tv_sec = static_cast<time_t>(remain.count() / 1000);
      tv.tv_usec = static_cast<suseconds_t>((remain.count() % 1000) * 1000);
      tv_ptr = &tv;
    }
    const int rc =
        select(runtime->master_fd + 1, &readfds, nullptr, nullptr, tv_ptr);
    if (rc < 0) {
      if (errno == EINTR) {
        continue;
      }
      return false;
    }
    if (rc == 0) {
      if (timed_out != nullptr) {
        *timed_out = true;
      }
      return false;
    }
    return true;
  }
}

inline ECM OpenChannelPosix_(ChannelRuntimeAttrs_ *runtime,
                             const AMT::ChannelInitArgs &init_args) {
  if (runtime == nullptr) {
    return Err(EC::InvalidArg, "terminal.channel.init", "channel",
               "Channel runtime is null");
  }
  winsize ws = {};
  ws.ws_col = static_cast<unsigned short>(std::max(1, init_args.cols));
  ws.ws_row = static_cast<unsigned short>(std::max(1, init_args.rows));
  ws.ws_xpixel = static_cast<unsigned short>(std::max(0, init_args.width));
  ws.ws_ypixel = static_cast<unsigned short>(std::max(0, init_args.height));
  int master_fd = -1;
  const pid_t pid = forkpty(&master_fd, nullptr, nullptr, &ws);
  if (pid < 0) {
    return Err(fec(std::error_code(errno, std::generic_category())),
               "terminal.channel.init", "/bin/sh", std::strerror(errno));
  }
  if (pid == 0) {
    execl("/bin/sh", "sh", static_cast<char *>(nullptr));
    _exit(127);
  }
  const int flags = fcntl(master_fd, F_GETFL, 0);
  if (flags >= 0) {
    (void)fcntl(master_fd, F_SETFL, flags | O_NONBLOCK);
  }
  runtime->master_fd = master_fd;
  runtime->child_pid = pid;
  runtime->process_exited = false;
  runtime->eof = false;
  runtime->exit_status = -1;
  return OK;
}
#endif

[[nodiscard]] inline bool IsConnectionBrokenCode_(ErrorCode code) {
  return code == EC::NoConnection || code == EC::ConnectionLost ||
         code == EC::NoSession || code == EC::ClientNotFound;
}

} // namespace detail

class LocalChannelPort final : public AMT::IChannelPort {
private:
  [[nodiscard]] bool RuntimeOpenedUnlocked_() const {
#ifdef _WIN32
    return runtime_.process_handle != INVALID_HANDLE_VALUE ||
           runtime_.output_read != INVALID_HANDLE_VALUE ||
           runtime_.input_write != INVALID_HANDLE_VALUE;
#else
    return runtime_.master_fd >= 0 || runtime_.child_pid > 0;
#endif
  }

  void UpdateProcessStateUnlocked_() {
#ifdef _WIN32
    detail::UpdateWindowsProcessState_(&runtime_);
#else
    detail::UpdatePosixProcessState_(&runtime_);
#endif
    if (runtime_.process_exited) {
      runtime_.eof = true;
    }
  }

  void CloseRuntimeUnlocked_(bool force) {
#ifdef _WIN32
    detail::UpdateWindowsProcessState_(&runtime_);
    if (!runtime_.process_exited &&
        runtime_.process_handle != INVALID_HANDLE_VALUE) {
      if (!force && runtime_.input_write != INVALID_HANDLE_VALUE) {
        const std::string exit_cmd = "exit";
        DWORD wrote = 0;
        (void)WriteFile(runtime_.input_write, exit_cmd.data(),
                        static_cast<DWORD>(exit_cmd.size()), &wrote, nullptr);
      }
      DWORD wait_rc =
          WaitForSingleObject(runtime_.process_handle, force ? 10 : 300);
      if (wait_rc == WAIT_TIMEOUT) {
        (void)TerminateProcess(runtime_.process_handle, 1);
        (void)WaitForSingleObject(runtime_.process_handle, 300);
      }
    }
    detail::UpdateWindowsProcessState_(&runtime_);
    detail::CloseHandleSafe_(&runtime_.input_write);
    detail::CloseHandleSafe_(&runtime_.output_read);
    detail::CloseHandleSafe_(&runtime_.process_handle);
    detail::ClosePseudoConsoleSafe_(&runtime_.pseudo_console);
#else
    detail::UpdatePosixProcessState_(&runtime_);
    if (!runtime_.process_exited && runtime_.child_pid > 0) {
      if (!force && runtime_.master_fd >= 0) {
        const std::string exit_cmd = "exit\n";
        (void)write(runtime_.master_fd, exit_cmd.data(), exit_cmd.size());
      }
      const auto deadline = std::chrono::steady_clock::now() +
                            std::chrono::milliseconds(force ? 20 : 300);
      while (std::chrono::steady_clock::now() < deadline) {
        detail::UpdatePosixProcessState_(&runtime_);
        if (runtime_.process_exited) {
          break;
        }
        usleep(10000);
      }
      if (!runtime_.process_exited && runtime_.child_pid > 0) {
        (void)kill(runtime_.child_pid, force ? SIGKILL : SIGTERM);
        const auto kill_deadline =
            std::chrono::steady_clock::now() + std::chrono::milliseconds(300);
        while (std::chrono::steady_clock::now() < kill_deadline) {
          detail::UpdatePosixProcessState_(&runtime_);
          if (runtime_.process_exited) {
            break;
          }
          usleep(10000);
        }
      }
      if (!runtime_.process_exited && runtime_.child_pid > 0) {
        (void)kill(runtime_.child_pid, SIGKILL);
        detail::UpdatePosixProcessState_(&runtime_);
      }
    }
    if (runtime_.master_fd >= 0) {
      (void)close(runtime_.master_fd);
      runtime_.master_fd = -1;
    }
#endif
    runtime_.eof = true;
    runtime_.process_exited = true;
  }

  void SignalLoopStateChanged_() {
#ifdef _WIN32
    if (loop_events_.state_wait_handle != nullptr) {
      (void)SetEvent(loop_events_.state_wait_handle);
    }
#endif
  }

  void CloseStateWaitHandle_() {
#ifdef _WIN32
    if (loop_events_.state_wait_handle != nullptr) {
      (void)CloseHandle(loop_events_.state_wait_handle);
      loop_events_.state_wait_handle = nullptr;
    }
#endif
  }

  void RequestStop_() {
    stop_requested_.store(true, std::memory_order_release);
    SignalLoopStateChanged_();
  }

  void JoinLoop_() {
    if (!loop_thread_.joinable()) {
      return;
    }
    if (std::this_thread::get_id() == loop_thread_id_) {
      return;
    }
    loop_thread_.join();
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    loop_started_ = false;
    loop_running_ = false;
    loop_thread_id_ = std::thread::id{};
    SignalLoopStateChanged_();
  }

  [[nodiscard]] bool DrainKeyInput_() {
    AMAtomic<std::vector<char>> *key_cache = nullptr;
    {
      std::lock_guard<std::recursive_mutex> lock(mutex_);
      if (!foreground_.foreground_bound || foreground_.key_cache == nullptr ||
          foreground_.closed) {
        return false;
      }
      key_cache = foreground_.key_cache;
    }

    std::vector<char> keys = {};
    {
      auto guard = key_cache->lock();
      if (guard->empty()) {
        return false;
      }
      keys.swap(*guard);
    }

    bool changed = false;
    bool detach = false;
    {
      std::lock_guard<std::recursive_mutex> lock(mutex_);
      for (char ch : keys) {
        if (!key_ctrl_state_.load(std::memory_order_acquire)) {
          if (ch == '\x1d') {
            key_ctrl_state_.store(true, std::memory_order_release);
            continue;
          }
          foreground_.send_buffer.push_back(ch);
          changed = true;
          continue;
        }
        if (ch == 'q' || ch == 'Q') {
          detach = true;
          key_ctrl_state_.store(false, std::memory_order_release);
          continue;
        }
        key_ctrl_state_.store(false, std::memory_order_release);
        foreground_.send_buffer.push_back(ch);
        changed = true;
      }
    }

    if (detach) {
      (void)RequestForegroundDetach();
      return true;
    }
    return changed;
  }

  [[nodiscard]] bool FlushSend_() {
    std::string chunk = {};
    {
      std::lock_guard<std::recursive_mutex> lock(mutex_);
      if (foreground_.send_buffer.empty() || !foreground_.foreground_bound ||
          foreground_.closed) {
        return false;
      }
      const size_t n =
          std::min<size_t>(foreground_.send_buffer.size(), 32U * 1024U);
      chunk.assign(foreground_.send_buffer.data(), n);
    }

    auto write_result = WriteRaw({chunk}, {});
    if (!(write_result.rcm)) {
      std::lock_guard<std::recursive_mutex> lock(mutex_);
      foreground_.last_error = write_result.rcm;
      if (detail::IsConnectionBrokenCode_(write_result.rcm.code)) {
        foreground_.closed = true;
      }
      if (foreground_.closed) {
        stop_requested_.store(true, std::memory_order_release);
      }
      SignalLoopStateChanged_();
      return false;
    }

    const size_t consumed = std::min(
        chunk.size(), static_cast<size_t>(write_result.data.bytes_written));
    if (consumed == 0U) {
      return false;
    }
    {
      std::lock_guard<std::recursive_mutex> lock(mutex_);
      if (consumed <= foreground_.send_buffer.size()) {
        foreground_.send_buffer.erase(0, consumed);
      } else {
        foreground_.send_buffer.clear();
      }
    }
    return true;
  }

  void RunLoop_() {
    {
      std::lock_guard<std::recursive_mutex> lock(mutex_);
      loop_thread_id_ = std::this_thread::get_id();
      loop_running_ = true;
      loop_started_ = true;
      SignalLoopStateChanged_();
    }

    while (!stop_requested_.load(std::memory_order_acquire)) {
      bool active_foreground = false;
      bool is_closed = false;
      {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        active_foreground = foreground_.foreground_bound;
        is_closed = foreground_.closed;
      }
      if (is_closed) {
        break;
      }

      bool progressed = false;
      if (active_foreground) {
        if (DrainKeyInput_()) {
          progressed = true;
        }
        if (FlushSend_()) {
          progressed = true;
        }

        auto read_result = ReadWrapped({32U * 1024U}, {});
        if (!(read_result.rcm)) {
          std::lock_guard<std::recursive_mutex> lock(mutex_);
          foreground_.last_error = read_result.rcm;
          foreground_.closed = true;
          stop_requested_.store(true, std::memory_order_release);
          SignalLoopStateChanged_();
          break;
        }

        if (!read_result.data.output.empty()) {
          progressed = true;
        }

        if (!(read_result.data.last_error)) {
          std::lock_guard<std::recursive_mutex> lock(mutex_);
          foreground_.last_error = read_result.data.last_error;
          SignalLoopStateChanged_();
        }

        if (read_result.data.hard_limit_hit || read_result.data.eof) {
          std::lock_guard<std::recursive_mutex> lock(mutex_);
          foreground_.closed = true;
          if (!(read_result.data.last_error)) {
            foreground_.last_error = read_result.data.last_error;
          }
          stop_requested_.store(true, std::memory_order_release);
          SignalLoopStateChanged_();
          break;
        }
      }

      if (!progressed) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
      }
    }

    {
      std::lock_guard<std::recursive_mutex> lock(mutex_);
      loop_running_ = false;
      loop_started_ = false;
      foreground_.foreground_bound = false;
      foreground_.key_event_handle = -1;
      foreground_.key_cache = nullptr;
      key_ctrl_state_.store(false, std::memory_order_release);
      loop_thread_id_ = std::thread::id{};
      SignalLoopStateChanged_();
    }
  }

  [[nodiscard]] ECMData<AMT::ChannelReadResult>
  RawRead_(const AMT::ChannelReadArgs &read_args,
           const ControlComponent &control) {
    ECMData<AMT::ChannelReadResult> out = {};
    out.data.channel_name = identity_.channel_name;

    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (control.IsInterrupted()) {
      out.rcm = Err(EC::Terminate, "terminal.channel.read",
                    identity_.channel_name, "Interrupted by user");
      out.data.eof = true;
      return out;
    }
    if (control.IsTimeout()) {
      out.rcm = Err(EC::OperationTimeout, "terminal.channel.read",
                    identity_.channel_name, "Operation timed out");
      out.data.eof = true;
      return out;
    }
    if (!RuntimeOpenedUnlocked_()) {
      runtime_.state = Err(EC::NoConnection, "terminal.channel.read",
                           identity_.channel_name, "Channel is closed");
      out.rcm = runtime_.state;
      out.data.eof = true;
      return out;
    }

    UpdateProcessStateUnlocked_();
    size_t const max_bytes =
        (read_args.max_bytes == 0U ? static_cast<size_t>(32U * AMKB)
                                   : read_args.max_bytes);
#ifdef _WIN32
    bool wrote =
        detail::DrainWindowsOutput_(&runtime_, &out.data.output, max_bytes);
#else
    bool wrote =
        detail::DrainPosixOutput_(&runtime_, &out.data.output, max_bytes);
#endif
    if (!wrote && !runtime_.eof && control.RemainingTimeMs().has_value()) {
      bool timed_out = false;
#ifdef _WIN32
      bool const wait_ok =
          detail::WaitReadableWindows_(&runtime_, control, &timed_out);
#else
      bool const wait_ok =
          detail::WaitReadablePosix_(&runtime_, control, &timed_out);
#endif
      if (!wait_ok) {
        if (control.IsInterrupted()) {
          out.rcm = Err(EC::Terminate, "terminal.channel.read",
                        identity_.channel_name,
                        "Interrupted while waiting terminal output");
        } else if (timed_out || control.IsTimeout()) {
          out.rcm = Err(EC::OperationTimeout, "terminal.channel.read",
                        identity_.channel_name,
                        "Timed out while waiting terminal output");
        } else if (runtime_.eof || runtime_.process_exited) {
          out.rcm = OK;
        } else {
          out.rcm = Err(EC::NoConnection, "terminal.channel.read",
                        identity_.channel_name,
                        "Failed while waiting terminal output");
          runtime_.state = out.rcm;
        }
        out.data.eof = runtime_.eof || runtime_.process_exited;
        return out;
      }
#ifdef _WIN32
      (void)detail::DrainWindowsOutput_(&runtime_, &out.data.output, max_bytes);
#else
      (void)detail::DrainPosixOutput_(&runtime_, &out.data.output, max_bytes);
#endif
    }

    UpdateProcessStateUnlocked_();
    out.data.eof = runtime_.eof;
    out.rcm = OK;
    return out;
  }

  [[nodiscard]] ECMData<AMT::ChannelWriteResult>
  RawWrite_(const AMT::ChannelWriteArgs &write_args,
            const ControlComponent &control) {
    ECMData<AMT::ChannelWriteResult> out = {};
    out.data.channel_name = identity_.channel_name;
    out.data.bytes_written = 0U;

    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (write_args.input.empty()) {
      out.rcm = OK;
      return out;
    }
    if (control.IsInterrupted()) {
      out.rcm = Err(EC::Terminate, "terminal.channel.write",
                    identity_.channel_name, "Interrupted by user");
      return out;
    }
    if (control.IsTimeout()) {
      out.rcm = Err(EC::OperationTimeout, "terminal.channel.write",
                    identity_.channel_name, "Operation timed out");
      return out;
    }
    if (!RuntimeOpenedUnlocked_()) {
      runtime_.state = Err(EC::NoConnection, "terminal.channel.write",
                           identity_.channel_name, "Channel is closed");
      out.rcm = runtime_.state;
      return out;
    }

    UpdateProcessStateUnlocked_();
    if (runtime_.process_exited || runtime_.eof) {
      runtime_.state = Err(EC::NoConnection, "terminal.channel.write",
                           identity_.channel_name, "Target channel is closed");
      out.rcm = runtime_.state;
      return out;
    }

#ifdef _WIN32
    if (runtime_.input_write == INVALID_HANDLE_VALUE) {
      runtime_.state =
          Err(EC::InvalidHandle, "terminal.channel.write",
              identity_.channel_name, "Terminal input handle is unavailable");
      out.rcm = runtime_.state;
      return out;
    }
    DWORD wrote = 0;
    const BOOL write_ok =
        WriteFile(runtime_.input_write, write_args.input.data(),
                  static_cast<DWORD>(write_args.input.size()), &wrote, nullptr);
    out.data.bytes_written = static_cast<size_t>(wrote);
    out.rcm = write_ok
                  ? OK
                  : Err(EC::SocketSendError, "terminal.channel.write",
                        identity_.channel_name, "Failed to write to terminal");
    runtime_.state = out.rcm;
    return out;
#else
    if (runtime_.master_fd < 0) {
      runtime_.state = Err(EC::InvalidHandle, "terminal.channel.write",
                           identity_.channel_name, "PTY handle is unavailable");
      out.rcm = runtime_.state;
      return out;
    }

    auto deadline = std::chrono::steady_clock::time_point::max();
    const auto remain_opt = control.RemainingTimeMs();
    if (remain_opt.has_value()) {
      deadline = std::chrono::steady_clock::now() +
                 std::chrono::milliseconds(*remain_opt);
    }

    while (out.data.bytes_written < write_args.input.size()) {
      ssize_t const rc = write(
          runtime_.master_fd, write_args.input.data() + out.data.bytes_written,
          write_args.input.size() - out.data.bytes_written);
      if (rc > 0) {
        out.data.bytes_written += static_cast<size_t>(rc);
        continue;
      }
      if (rc < 0 && errno == EINTR) {
        continue;
      }
      if (rc < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
        if (control.IsInterrupted()) {
          out.rcm = Err(EC::Terminate, "terminal.channel.write",
                        identity_.channel_name,
                        "Interrupted while waiting terminal write");
          runtime_.state = out.rcm;
          return out;
        }
        if (control.IsTimeout()) {
          out.rcm = Err(EC::OperationTimeout, "terminal.channel.write",
                        identity_.channel_name,
                        "Timed out while waiting terminal write");
          runtime_.state = out.rcm;
          return out;
        }
        if (deadline != std::chrono::steady_clock::time_point::max() &&
            std::chrono::steady_clock::now() >= deadline) {
          out.rcm = Err(EC::OperationTimeout, "terminal.channel.write",
                        identity_.channel_name,
                        "Timed out while waiting terminal write");
          runtime_.state = out.rcm;
          return out;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
        continue;
      }
      out.rcm = Err(fec(std::error_code(errno, std::generic_category())),
                    "terminal.channel.write", identity_.channel_name,
                    std::strerror(errno));
      runtime_.state = out.rcm;
      return out;
    }
    out.rcm = OK;
    runtime_.state = out.rcm;
    return out;
#endif
  }

  [[nodiscard]] ECMData<AMT::ChannelResizeResult>
  RawResize_(const AMT::ChannelResizeArgs &resize_args,
             const ControlComponent &control) {
    (void)control;
    ECMData<AMT::ChannelResizeResult> out = {};
    out.data.channel_name = identity_.channel_name;

    std::lock_guard<std::recursive_mutex> lock(mutex_);
    runtime_.window_cols = resize_args.cols;
    runtime_.window_rows = resize_args.rows;
    runtime_.window_width = resize_args.width;
    runtime_.window_height = resize_args.height;

    if (!RuntimeOpenedUnlocked_() || runtime_.eof || runtime_.process_exited) {
      out.data.resized = false;
      out.rcm = OK;
      return out;
    }

#ifdef _WIN32
    const auto &api = detail::ConPTYApiInstance_();
    if (runtime_.pseudo_console == nullptr || !api.IsAvailable() ||
        api.resize == nullptr) {
      out.data.resized = false;
      out.rcm = OK;
      return out;
    }
    COORD size = {};
    size.X = static_cast<SHORT>(std::max(1, resize_args.cols));
    size.Y = static_cast<SHORT>(std::max(1, resize_args.rows));
    const HRESULT hr = api.resize(runtime_.pseudo_console, size);
    if (FAILED(hr)) {
      out.data.resized = false;
      out.rcm = Err(EC::OperationUnsupported, "terminal.channel.resize",
                    identity_.channel_name, "ConPTY resize failed");
      runtime_.state = out.rcm;
      return out;
    }
    out.data.resized = true;
    out.rcm = OK;
    runtime_.state = out.rcm;
    return out;
#else
    if (runtime_.master_fd < 0) {
      out.data.resized = false;
      out.rcm = OK;
      return out;
    }
    winsize ws = {};
    ws.ws_col = static_cast<unsigned short>(std::max(1, resize_args.cols));
    ws.ws_row = static_cast<unsigned short>(std::max(1, resize_args.rows));
    ws.ws_xpixel = static_cast<unsigned short>(std::max(0, resize_args.width));
    ws.ws_ypixel = static_cast<unsigned short>(std::max(0, resize_args.height));
    if (ioctl(runtime_.master_fd, TIOCSWINSZ, &ws) != 0) {
      out.data.resized = false;
      out.rcm = Err(fec(std::error_code(errno, std::generic_category())),
                    "terminal.channel.resize", identity_.channel_name,
                    std::strerror(errno));
      runtime_.state = out.rcm;
      return out;
    }
    out.data.resized = true;
    out.rcm = OK;
    runtime_.state = out.rcm;
    return out;
#endif
  }

public:
  LocalChannelPort(std::string terminal_key, std::string channel_name,
                   AMT::BufferExceedCallback buffer_exceed_callback = {},
                   AMT::TerminalManagerArg terminal_manager_arg = {})
      : identity_(std::move(terminal_key), AMStr::Strip(channel_name)),
        cache_(identity_.terminal_key, identity_.channel_name,
               std::move(buffer_exceed_callback),
               std::move(terminal_manager_arg)) {}

  ~LocalChannelPort() override {
    RequestStop_();
    JoinLoop_();
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    CloseRuntimeUnlocked_(true);
    CloseStateWaitHandle_();
  }

  [[nodiscard]] std::string GetTerminalKey() const override {
    return identity_.terminal_key;
  }

  [[nodiscard]] std::string GetChannelName() const override {
    return identity_.channel_name;
  }

  [[nodiscard]] ECMData<SOCKET> GetWaitHandle() const override {
    ECMData<SOCKET> out = {};
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (!RuntimeOpenedUnlocked_()) {
      out.data = INVALID_SOCKET;
      out.rcm = Err(EC::NoConnection, "terminal.channel.wait_handle",
                    identity_.channel_name, "Channel is closed");
      return out;
    }
#ifdef _WIN32
    if (runtime_.output_read == INVALID_HANDLE_VALUE) {
      out.data = INVALID_SOCKET;
      out.rcm =
          Err(EC::NoConnection, "terminal.channel.wait_handle",
              identity_.channel_name, "Channel output handle is unavailable");
      return out;
    }
    out.data = static_cast<SOCKET>(
        reinterpret_cast<std::intptr_t>(runtime_.output_read));
#else
    if (runtime_.master_fd < 0) {
      out.data = INVALID_SOCKET;
      out.rcm = Err(EC::NoConnection, "terminal.channel.wait_handle",
                    identity_.channel_name, "Channel PTY fd is unavailable");
      return out;
    }
    out.data = static_cast<SOCKET>(runtime_.master_fd);
#endif
    out.rcm = OK;
    return out;
  }

  ECM Init(const AMT::ChannelInitArgs &init_args,
           const ControlComponent &control = {}) override {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (identity_.channel_name.empty()) {
      runtime_.state = Err(EC::InvalidArg, "terminal.channel.init",
                           identity_.channel_name, "channel_name is empty");
      foreground_.last_error = runtime_.state;
      foreground_.closed = true;
      return runtime_.state;
    }
    if (control.IsInterrupted()) {
      runtime_.state = Err(EC::Terminate, "terminal.channel.init",
                           identity_.channel_name, "Interrupted by user");
      foreground_.last_error = runtime_.state;
      foreground_.closed = true;
      return runtime_.state;
    }
    if (control.IsTimeout()) {
      runtime_.state = Err(EC::OperationTimeout, "terminal.channel.init",
                           identity_.channel_name, "Operation timed out");
      foreground_.last_error = runtime_.state;
      foreground_.closed = true;
      return runtime_.state;
    }
    if (RuntimeOpenedUnlocked_() && !foreground_.closed) {
      return Err(EC::TargetAlreadyExists, "terminal.channel.init",
                 identity_.channel_name, "Channel is already initialized");
    }

    CloseRuntimeUnlocked_(true);
    runtime_.window_cols = std::max(1, init_args.cols);
    runtime_.window_rows = std::max(1, init_args.rows);
    runtime_.window_width = std::max(0, init_args.width);
    runtime_.window_height = std::max(0, init_args.height);
    runtime_.term = init_args.term.empty() ? "xterm-256color" : init_args.term;
    cache_.ResizeViewport(runtime_.window_cols, runtime_.window_rows);
    runtime_.eof = false;
    runtime_.process_exited = false;
    runtime_.exit_status = -1;
    runtime_.state = OK;

#ifdef _WIN32
    runtime_.state = detail::OpenChannelWindows_(&runtime_, init_args);
#else
    runtime_.state = detail::OpenChannelPosix_(&runtime_, init_args);
#endif
    foreground_.closed = !(runtime_.state);
    foreground_.last_error = runtime_.state;
    return runtime_.state;
  }

  ECM Rename(const std::string &new_channel_name) override {
    const std::string renamed = AMStr::Strip(new_channel_name);
    if (renamed.empty()) {
      return Err(EC::InvalidArg, "terminal.channel.rename",
                 identity_.channel_name, "new channel name is empty");
    }
    identity_.channel_name = renamed;
    cache_.SetChannelName(identity_.channel_name);
    return OK;
  }

  [[nodiscard]] ECMData<AMT::ChannelCacheReplayResult>
  AttachConsumer(AMT::ChannelOutputProcessor processor) override {
    return cache_.AttachConsumer(std::move(processor));
  }

  ECM DetachConsumer() override { return cache_.DetachConsumer(); }

  [[nodiscard]] ECMData<AMT::ChannelReadWrappedResult>
  ReadWrapped(const AMT::ChannelReadArgs &read_args,
              const ControlComponent &control = {}) override {
    auto raw_read = RawRead_(read_args, control);
    return cache_.WrapReadResultFromRaw(raw_read);
  }

  [[nodiscard]] ECMData<AMT::ChannelWriteResult>
  WriteRaw(const AMT::ChannelWriteArgs &write_args,
           const ControlComponent &control = {}) override {
    return RawWrite_(write_args, control);
  }

  [[nodiscard]] ECMData<AMT::ChannelResizeResult>
  Resize(const AMT::ChannelResizeArgs &resize_args,
         const ControlComponent &control = {}) override {
    auto out = RawResize_(resize_args, control);
    if ((out.rcm)) {
      cache_.ResizeViewport(resize_args.cols, resize_args.rows);
    }
    return out;
  }

  [[nodiscard]] ECMData<AMT::ChannelCloseResult>
  Close(bool force, int grace_period_ms = 1500,
        const ControlComponent &control = {}) override {
    (void)control;
    (void)grace_period_ms;
    RequestStop_();
    JoinLoop_();

    ECMData<AMT::ChannelCloseResult> out = {};
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    out.data.channel_name = identity_.channel_name;
    out.data.exit_code = runtime_.exit_status;
    if (RuntimeOpenedUnlocked_()) {
      CloseRuntimeUnlocked_(force);
      out.data.exit_code = runtime_.exit_status;
    }
    foreground_.closed = true;
    foreground_.foreground_bound = false;
    foreground_.detach_requested = false;
    foreground_.key_event_handle = -1;
    foreground_.key_cache = nullptr;
    foreground_.send_buffer.clear();
    key_ctrl_state_.store(false, std::memory_order_release);
    runtime_.state = Err(EC::NoConnection, "terminal.channel.state",
                         identity_.channel_name, "Channel is closed");
    foreground_.last_error = OK;
    out.data.closed = true;
    out.rcm = OK;
    cache_.MarkChannelClosed(OK);
    SignalLoopStateChanged_();
    return out;
  }

  [[nodiscard]] AMT::ChannelPortState GetState() const override {
    auto state = cache_.GetState();
    auto &self = const_cast<LocalChannelPort &>(*this);
    std::lock_guard<std::recursive_mutex> lock(self.mutex_);
    self.UpdateProcessStateUnlocked_();
    state.closed = foreground_.closed || runtime_.eof ||
                   runtime_.process_exited || !RuntimeOpenedUnlocked_();
    if (!(foreground_.last_error)) {
      state.last_error = foreground_.last_error;
    } else if (!(runtime_.state)) {
      state.last_error = runtime_.state;
    }
    return state;
  }

  [[nodiscard]] ECMData<AMT::ChannelCacheCopyResult>
  GetCacheCopy() const override {
    return cache_.GetCacheCopy();
  }

  [[nodiscard]] ECMData<AMT::ChannelRenderFrameResult>
  GetRenderFrame() const override {
    return cache_.GetRenderFrame();
  }

  ECM ClearCache() override { return cache_.ClearCache(); }

  [[nodiscard]] ECMData<AMT::ChannelCacheTruncateResult> TruncateCache(
      const AMT::ChannelCacheTruncateArgs &truncate_args = {}) override {
    return cache_.TruncateCache(truncate_args);
  }

  ECM EnsureLoopStarted(
      const AMT::ChannelLoopStartArgs &start_args = {}) override {
    (void)start_args;
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (foreground_.closed || !RuntimeOpenedUnlocked_()) {
      foreground_.last_error =
          Err(EC::NoConnection, "terminal.channel.loop.start",
              identity_.channel_name, "Channel is closed");
      return foreground_.last_error;
    }
#ifdef _WIN32
    if (loop_events_.state_wait_handle == nullptr) {
      loop_events_.state_wait_handle =
          CreateEventW(nullptr, FALSE, FALSE, nullptr);
      if (loop_events_.state_wait_handle == nullptr) {
        foreground_.last_error =
            Err(EC::CommonFailure, "terminal.channel.loop.start",
                identity_.channel_name,
                "Failed to create local loop state wait handle");
        return foreground_.last_error;
      }
    }
#endif
    if (loop_started_ && loop_thread_.joinable()) {
      loop_running_ = true;
      foreground_.last_error = OK;
      return OK;
    }
    stop_requested_.store(false, std::memory_order_release);
    loop_started_ = true;
    loop_running_ = true;
    foreground_.detach_requested = false;
    foreground_.last_error = OK;
    try {
      loop_thread_ = std::thread([this]() { RunLoop_(); });
    } catch (...) {
      loop_started_ = false;
      loop_running_ = false;
      foreground_.last_error =
          Err(EC::CommonFailure, "terminal.channel.loop.start",
              identity_.channel_name, "Failed to create local loop thread");
      return foreground_.last_error;
    }
    SignalLoopStateChanged_();
    return OK;
  }

  [[nodiscard]] ECMData<AMT::ChannelCacheReplayResult>
  BindForeground(const AMT::ChannelForegroundBindArgs &bind_args) override {
    if (!bind_args.processor || bind_args.key_cache == nullptr) {
      const ECM rcm =
          Err(EC::InvalidArg, "terminal.channel.bind", identity_.channel_name,
              "Foreground binding arguments are invalid");
      std::lock_guard<std::recursive_mutex> lock(mutex_);
      foreground_.last_error = rcm;
      return {AMT::ChannelCacheReplayResult{}, rcm};
    }

    const ECM loop_rcm =
        EnsureLoopStarted({bind_args.control, bind_args.write_kick_timeout_ms});
    if (!(loop_rcm)) {
      return {AMT::ChannelCacheReplayResult{}, loop_rcm};
    }

    auto result = AttachConsumer(bind_args.processor);
    {
      std::lock_guard<std::recursive_mutex> lock(mutex_);
      if (result.rcm) {
        foreground_.foreground_bound = true;
        foreground_.detach_requested = false;
        foreground_.key_event_handle = bind_args.key_event_handle;
        foreground_.key_cache = bind_args.key_cache;
        key_ctrl_state_.store(false, std::memory_order_release);
        foreground_.last_error = OK;
      } else {
        foreground_.last_error = result.rcm;
      }
      SignalLoopStateChanged_();
    }
    return result;
  }

  ECM UnbindForeground() override {
    {
      std::lock_guard<std::recursive_mutex> lock(mutex_);
      foreground_.foreground_bound = false;
      foreground_.detach_requested = false;
      foreground_.key_event_handle = -1;
      foreground_.key_cache = nullptr;
      key_ctrl_state_.store(false, std::memory_order_release);
      SignalLoopStateChanged_();
    }
    RequestStop_();
    JoinLoop_();
    return DetachConsumer();
  }

  ECM RequestForegroundDetach() override {
    {
      std::lock_guard<std::recursive_mutex> lock(mutex_);
      foreground_.foreground_bound = false;
      foreground_.detach_requested = true;
      foreground_.key_event_handle = -1;
      foreground_.key_cache = nullptr;
      key_ctrl_state_.store(false, std::memory_order_release);
      SignalLoopStateChanged_();
    }
    RequestStop_();
    JoinLoop_();
    return DetachConsumer();
  }

  [[nodiscard]] AMT::ChannelLoopState GetLoopState() const override {
    AMT::ChannelLoopState state = {};
    AMT::ChannelPortState const port_state = GetState();
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    state.closed = foreground_.closed || port_state.closed;
    state.loop_running = loop_running_ && !state.closed;
    state.foreground_bound = foreground_.foreground_bound;
    state.detach_requested = foreground_.detach_requested;
#ifdef _WIN32
    state.state_wait_handle =
        loop_events_.state_wait_handle != nullptr
            ? reinterpret_cast<std::intptr_t>(loop_events_.state_wait_handle)
            : static_cast<std::intptr_t>(-1);
#else
    state.state_wait_handle = static_cast<std::intptr_t>(-1);
#endif
    state.last_error = foreground_.last_error;
    if (!(state.last_error) && port_state.last_error) {
      state.last_error = port_state.last_error;
    }
    state.has_error = !(state.last_error);
    return state;
  }

private:
  detail::ChannelIdentity_ identity_ = {};
  ChannelCacheStore cache_;
  detail::ChannelRuntimeAttrs_ runtime_ = {};
  detail::ChannelForegroundAttrs_ foreground_ = {};

  mutable std::recursive_mutex mutex_ = {};
  std::thread loop_thread_ = {};
  std::thread::id loop_thread_id_ = {};
  std::atomic<bool> stop_requested_ = false;
  std::atomic<bool> key_ctrl_state_ = false;
  bool loop_running_ = false;
  bool loop_started_ = false;

#ifdef _WIN32
  detail::ChannelLoopEvents_ loop_events_ = {};
#endif
};

} // namespace AMInfra::client::LOCAL::terminal
