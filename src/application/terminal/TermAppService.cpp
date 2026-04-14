#include "application/terminal/TermAppService.hpp"

#include "domain/host/HostDomainService.hpp"
#include "foundation/tools/string.hpp"
#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstring>
#include <memory>
#include <thread>
#include <utility>
#include <vector>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#else
#include <cerrno>
#include <fcntl.h>
#include <poll.h>
#include <unistd.h>
#endif

namespace AMApplication::terminal {
namespace {
using EC = ErrorCode;
constexpr const char *kDefaultTerminalChannelName = "default";
constexpr int kTerminalRemoveCloseTimeoutMs = 1500;
constexpr size_t kDefaultStreamCacheBytes = 16U * 1024U * 1024U;
constexpr size_t kStreamReadChunkBytes = 32U * 1024U;
constexpr size_t kStreamWriteChunkBytes = 32U * 1024U;
constexpr int kStreamWaitTimeoutMs = 50;
constexpr int kStreamBurstLimit = 8;
constexpr size_t kTerminalCacheSoftLimitBytes = 32U * 1024U * 1024U;
constexpr size_t kTerminalCacheHardLimitBytes = 128U * 1024U * 1024U;
constexpr size_t kMaxEscapeTailBytes = 16U;

enum class ScreenKind { Main, Alternate };

struct OutputBlock {
  ScreenKind screen = ScreenKind::Main;
  std::string data = {};
};

struct TerminalCache {
  std::vector<OutputBlock> blocks = {};
  bool in_alternate_screen = false;
};

struct ScreenToggleMatch_ {
  bool matched = false;
  bool partial = false;
  bool to_alternate = false;
  size_t length = 0;
};

struct ParsedScreenChunk_ {
  std::vector<OutputBlock> blocks = {};
  bool in_alternate_screen = false;
  std::string pending_escape_tail = {};
  size_t appended_bytes = 0;
};

struct CacheAppendOutcome_ {
  size_t appended_bytes = 0;
  bool soft_limit_hit_now = false;
  bool hard_limit_hit = false;
};

[[nodiscard]] bool StartsWith_(std::string_view full, std::string_view prefix) {
  return full.size() >= prefix.size() &&
         full.compare(0, prefix.size(), prefix.data(), prefix.size()) == 0;
}

[[nodiscard]] ScreenToggleMatch_ TryMatchScreenToggle_(std::string_view data,
                                                       size_t pos) {
  static constexpr std::array<std::pair<std::string_view, bool>, 6>
      kScreenToggles = {{{"\x1b[?1049h", true},
                         {"\x1b[?1049l", false},
                         {"\x1b[?1047h", true},
                         {"\x1b[?1047l", false},
                         {"\x1b[?47h", true},
                         {"\x1b[?47l", false}}};

  if (pos >= data.size() || data[pos] != '\x1b') {
    return {};
  }
  const std::string_view remain = data.substr(pos);
  ScreenToggleMatch_ out = {};
  for (const auto &entry : kScreenToggles) {
    const std::string_view seq = entry.first;
    if (remain.size() >= seq.size()) {
      if (remain.compare(0, seq.size(), seq.data(), seq.size()) == 0) {
        out.matched = true;
        out.to_alternate = entry.second;
        out.length = seq.size();
        return out;
      }
      continue;
    }
    if (StartsWith_(seq, remain)) {
      out.partial = true;
      return out;
    }
  }
  return out;
}

[[nodiscard]] ParsedScreenChunk_
ParseScreenChunk_(bool in_alternate_screen, std::string_view pending_tail,
                  std::string_view chunk) {
  ParsedScreenChunk_ out = {};
  out.in_alternate_screen = in_alternate_screen;

  std::string combined = {};
  combined.reserve(pending_tail.size() + chunk.size());
  combined.append(pending_tail.data(), pending_tail.size());
  combined.append(chunk.data(), chunk.size());
  const std::string_view data(combined);

  auto append_block = [&](ScreenKind screen, const std::string &payload) {
    if (payload.empty()) {
      return;
    }
    if (!out.blocks.empty() && out.blocks.back().screen == screen) {
      out.blocks.back().data.append(payload);
    } else {
      out.blocks.push_back(OutputBlock{screen, payload});
    }
    out.appended_bytes += payload.size();
  };

  ScreenKind current_screen =
      out.in_alternate_screen ? ScreenKind::Alternate : ScreenKind::Main;
  std::string payload = {};
  payload.reserve(data.size());

  size_t i = 0;
  bool ended_with_partial = false;
  while (i < data.size()) {
    const char ch = data[i];
    if (ch != '\x1b') {
      payload.push_back(ch);
      ++i;
      continue;
    }

    const ScreenToggleMatch_ match = TryMatchScreenToggle_(data, i);
    if (match.partial) {
      ended_with_partial = true;
      break;
    }
    if (!match.matched) {
      payload.push_back(ch);
      ++i;
      continue;
    }

    append_block(current_screen, payload);
    payload.clear();
    out.in_alternate_screen = match.to_alternate;
    current_screen =
        out.in_alternate_screen ? ScreenKind::Alternate : ScreenKind::Main;
    i += match.length;
  }

  append_block(current_screen, payload);
  if (ended_with_partial) {
    const size_t tail_size = std::min(kMaxEscapeTailBytes, data.size() - i);
    out.pending_escape_tail.assign(data.substr(data.size() - tail_size));
  } else {
    out.pending_escape_tail.clear();
  }
  return out;
}

enum class StreamWaitStatus_ { Ready, Interrupted, Timeout, Error };

struct StreamWaitResult_ {
  StreamWaitStatus_ status = StreamWaitStatus_::Ready;
  bool read_ready = false;
  bool write_ready = false;
  bool wake_ready = false;
  std::string error = {};
};

class StreamRemoteWaiter_ final {
public:
  StreamRemoteWaiter_(AMDomain::terminal::ITerminalPort *terminal,
                      AMDomain::client::amf control_token,
                      const std::atomic<unsigned long long> *wake_seq)
      : terminal_(terminal), control_token_(std::move(control_token)),
        wake_seq_(wake_seq) {}

  ~StreamRemoteWaiter_() { Shutdown_(); }

  StreamRemoteWaiter_(const StreamRemoteWaiter_ &) = delete;
  StreamRemoteWaiter_ &operator=(const StreamRemoteWaiter_ &) = delete;
  StreamRemoteWaiter_(StreamRemoteWaiter_ &&) = delete;
  StreamRemoteWaiter_ &operator=(StreamRemoteWaiter_ &&) = delete;

  [[nodiscard]] ECM Init() {
    if (initialized_) {
      return OK;
    }
    if (terminal_ == nullptr) {
      return Err(EC::InvalidHandle, "terminal.stream.wait.init", "<terminal>",
                 "Terminal handle is null");
    }

    auto handle_result = terminal_->GetRemoteSocketHandle();
    if (!(handle_result.rcm) || handle_result.data < 0) {
      return (handle_result.rcm)
                 ? Err(EC::NoConnection, "terminal.stream.wait.init", "<remote>",
                       "Remote handle is invalid")
                 : handle_result.rcm;
    }

    remote_handle_ = handle_result.data;
    const auto request = terminal_->GetRequest();
    remote_is_socket_ =
        (request.protocol == AMDomain::host::ClientProtocol::SFTP);

#ifdef _WIN32
    ECM init_rcm = InitWindows_();
#else
    ECM init_rcm = InitPosix_();
#endif
    if (!(init_rcm)) {
      Shutdown_();
      return init_rcm;
    }

    initialized_ = true;
    return OK;
  }

  [[nodiscard]] StreamWaitResult_ Wait(bool watch_read, bool watch_write,
                                       int timeout_ms,
                                       unsigned long long wake_snapshot) {
    if (!initialized_) {
      return {StreamWaitStatus_::Error, false, false, false,
              "Stream waiter is not initialized"};
    }
    if (control_token_ && control_token_->IsInterrupted()) {
      return {StreamWaitStatus_::Interrupted, false, false, false, {}};
    }
    if (IsWakeTriggered_(wake_snapshot)) {
      return {StreamWaitStatus_::Ready, false, false, true, {}};
    }
    if (!watch_read && !watch_write) {
      return {StreamWaitStatus_::Ready, false, false, true, {}};
    }

#ifdef _WIN32
    return WaitWindows_(watch_read, watch_write, timeout_ms, wake_snapshot);
#else
    return WaitPosix_(watch_read, watch_write, timeout_ms, wake_snapshot);
#endif
  }

private:
  [[nodiscard]] bool IsWakeTriggered_(unsigned long long wake_snapshot) const {
    return wake_seq_ != nullptr && wake_seq_->load(std::memory_order_acquire) !=
                                       wake_snapshot;
  }

#ifdef _WIN32
  static constexpr DWORD kInvalidIndex_ = static_cast<DWORD>(-1);

  void PushWaitHandle_(HANDLE handle, DWORD *index_slot) {
    if (index_slot == nullptr || handle == nullptr ||
        handle == INVALID_HANDLE_VALUE || wait_count_ >= wait_handles_.size()) {
      return;
    }
    *index_slot = wait_count_;
    wait_handles_[wait_count_++] = handle;
  }

  [[nodiscard]] ECM InitWindows_() {
    if (control_token_) {
      wake_event_ = CreateEventW(nullptr, FALSE, FALSE, nullptr);
      if (wake_event_ != nullptr) {
        wake_guard_ =
            std::make_unique<AMDomain::client::ControlTokenWakeupSafeGaurd>(
                control_token_,
                [wake_event = wake_event_]() { (void)SetEvent(wake_event); });
        PushWaitHandle_(wake_event_, &wake_index_);
      }
    }

    if (remote_is_socket_) {
      remote_sock_ = static_cast<SOCKET>(remote_handle_);
      if (remote_sock_ == INVALID_SOCKET) {
        return Err(EC::SocketCreateError, "terminal.stream.wait.init",
                   "<remote>", "Socket handle is invalid");
      }
      return OK;
    }

    PushWaitHandle_(reinterpret_cast<HANDLE>(remote_handle_), &remote_index_);
    if (remote_index_ == kInvalidIndex_) {
      return Err(EC::InvalidArg, "terminal.stream.wait.init", "<remote>",
                 "Invalid remote wait handle");
    }
    return OK;
  }

  [[nodiscard]] StreamWaitResult_
  WaitWindows_(bool watch_read, bool watch_write, int timeout_ms,
               unsigned long long wake_snapshot) {
    if (remote_is_socket_) {
      return WaitWindowsSocket_(watch_read, watch_write, timeout_ms,
                                wake_snapshot);
    }

    if (wait_count_ == 0) {
      return {StreamWaitStatus_::Ready, false, false, false, {}};
    }
    if (IsWakeTriggered_(wake_snapshot)) {
      return {StreamWaitStatus_::Ready, false, false, true, {}};
    }
    const DWORD timeout =
        timeout_ms < 0 ? INFINITE : static_cast<DWORD>(timeout_ms);
    const DWORD wait_rc =
        WaitForMultipleObjects(wait_count_, wait_handles_.data(), FALSE, timeout);
    if (wait_rc == WAIT_TIMEOUT) {
      return IsWakeTriggered_(wake_snapshot)
                 ? StreamWaitResult_{StreamWaitStatus_::Ready, false, false,
                                     true, {}}
                 : StreamWaitResult_{StreamWaitStatus_::Timeout, false, false,
                                     false, {}};
    }
    if (wait_rc == WAIT_FAILED) {
      return {StreamWaitStatus_::Error, false, false, false,
              AMStr::fmt("WaitForMultipleObjects failed: {}",
                         static_cast<unsigned long>(GetLastError()))};
    }

    const DWORD index = wait_rc - WAIT_OBJECT_0;
    if (wake_index_ != kInvalidIndex_ && index == wake_index_) {
      return {control_token_ && control_token_->IsInterrupted()
                  ? StreamWaitStatus_::Interrupted
                  : StreamWaitStatus_::Ready,
              false, false, true, {}};
    }
    if (remote_index_ != kInvalidIndex_ && index == remote_index_) {
      return {StreamWaitStatus_::Ready, watch_read, watch_write, false, {}};
    }
    return {StreamWaitStatus_::Ready, false, false, false, {}};
  }

  [[nodiscard]] StreamWaitResult_
  WaitWindowsSocket_(bool watch_read, bool watch_write, int timeout_ms,
                     unsigned long long wake_snapshot) {
    if (remote_sock_ == INVALID_SOCKET) {
      return {StreamWaitStatus_::Error, false, false, false,
              "Socket handle is invalid"};
    }

    const auto start = std::chrono::steady_clock::now();
    while (true) {
      if (control_token_ && control_token_->IsInterrupted()) {
        return {StreamWaitStatus_::Interrupted, false, false, false, {}};
      }
      if (IsWakeTriggered_(wake_snapshot)) {
        return {StreamWaitStatus_::Ready, false, false, true, {}};
      }
      if (!watch_read && !watch_write) {
        return {StreamWaitStatus_::Ready, false, false, false, {}};
      }

      int slice_ms = 50;
      if (timeout_ms >= 0) {
        const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - start);
        const int remain_ms = timeout_ms - static_cast<int>(elapsed.count());
        if (remain_ms <= 0) {
          return IsWakeTriggered_(wake_snapshot)
                     ? StreamWaitResult_{StreamWaitStatus_::Ready, false, false,
                                         true, {}}
                     : StreamWaitResult_{StreamWaitStatus_::Timeout, false,
                                         false, false, {}};
        }
        slice_ms = std::max(1, std::min(slice_ms, remain_ms));
      }

      fd_set readfds;
      fd_set writefds;
      FD_ZERO(&readfds);
      FD_ZERO(&writefds);
      if (watch_read) {
        FD_SET(remote_sock_, &readfds);
      }
      if (watch_write) {
        FD_SET(remote_sock_, &writefds);
      }
      timeval tv = {};
      tv.tv_sec = static_cast<long>(slice_ms / 1000);
      tv.tv_usec = static_cast<long>((slice_ms % 1000) * 1000);

      const int rc = select(0, watch_read ? &readfds : nullptr,
                            watch_write ? &writefds : nullptr, nullptr, &tv);
      if (rc > 0) {
        return {StreamWaitStatus_::Ready,
                watch_read && FD_ISSET(remote_sock_, &readfds),
                watch_write && FD_ISSET(remote_sock_, &writefds), false, {}};
      }
      if (rc == 0) {
        if (timeout_ms < 0) {
          continue;
        }
        const auto elapsed =
            std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - start);
        if (elapsed.count() >= timeout_ms) {
          return IsWakeTriggered_(wake_snapshot)
                     ? StreamWaitResult_{StreamWaitStatus_::Ready, false, false,
                                         true, {}}
                     : StreamWaitResult_{StreamWaitStatus_::Timeout, false,
                                         false, false, {}};
        }
        continue;
      }

      const int wsa_error = WSAGetLastError();
      if (wsa_error == WSAEINTR || wsa_error == WSAEWOULDBLOCK) {
        continue;
      }
      return {StreamWaitStatus_::Error, false, false, false,
              AMStr::fmt("select failed: {}", wsa_error)};
    }
  }

  void ShutdownWindows_() {
    wake_guard_.reset();
    if (wake_event_ != nullptr) {
      (void)CloseHandle(wake_event_);
      wake_event_ = nullptr;
    }
    remote_sock_ = INVALID_SOCKET;
    wait_count_ = 0;
    wait_handles_ = {};
    wake_index_ = kInvalidIndex_;
    remote_index_ = kInvalidIndex_;
  }
#else
  [[nodiscard]] ECM InitPosix_() {
    remote_fd_ = static_cast<int>(remote_handle_);
    if (remote_fd_ < 0) {
      return Err(EC::InvalidArg, "terminal.stream.wait.init", "<remote>",
                 "Remote fd is invalid");
    }

    if (control_token_ && pipe(wake_pipe_) == 0) {
      const int read_flags = fcntl(wake_pipe_[0], F_GETFL, 0);
      const int write_flags = fcntl(wake_pipe_[1], F_GETFL, 0);
      if (read_flags >= 0) {
        (void)fcntl(wake_pipe_[0], F_SETFL, read_flags | O_NONBLOCK);
      }
      if (write_flags >= 0) {
        (void)fcntl(wake_pipe_[1], F_SETFL, write_flags | O_NONBLOCK);
      }
      wake_guard_ =
          std::make_unique<AMDomain::client::ControlTokenWakeupSafeGaurd>(
              control_token_, [wake_write_fd = wake_pipe_[1]]() {
                const char c = 1;
                (void)write(wake_write_fd, &c, 1);
              });
    } else {
      wake_pipe_[0] = -1;
      wake_pipe_[1] = -1;
    }
    return OK;
  }

  [[nodiscard]] StreamWaitResult_
  WaitPosix_(bool watch_read, bool watch_write, int timeout_ms,
             unsigned long long wake_snapshot) {
    if (IsWakeTriggered_(wake_snapshot)) {
      return {StreamWaitStatus_::Ready, false, false, true, {}};
    }
    std::array<pollfd, 2> fds = {};
    nfds_t nfds = 0;
    fds[nfds].fd = remote_fd_;
    fds[nfds].events = POLLERR | POLLHUP;
    if (watch_read) {
      fds[nfds].events |= (POLLIN | POLLPRI);
    }
    if (watch_write) {
      fds[nfds].events |= POLLOUT;
    }
    ++nfds;

    int wake_index = -1;
    if (wake_pipe_[0] >= 0) {
      wake_index = static_cast<int>(nfds);
      fds[nfds].fd = wake_pipe_[0];
      fds[nfds].events = POLLIN | POLLERR | POLLHUP;
      ++nfds;
    }

    const int rc = poll(fds.data(), nfds, timeout_ms);
    if (rc == 0) {
      return IsWakeTriggered_(wake_snapshot)
                 ? StreamWaitResult_{StreamWaitStatus_::Ready, false, false,
                                     true, {}}
                 : StreamWaitResult_{StreamWaitStatus_::Timeout, false, false,
                                     false, {}};
    }
    if (rc < 0) {
      if (errno == EINTR) {
        return {control_token_ && control_token_->IsInterrupted()
                    ? StreamWaitStatus_::Interrupted
                    : StreamWaitStatus_::Ready,
                false, false, false, {}};
      }
      return {StreamWaitStatus_::Error, false, false, false,
              std::strerror(errno)};
    }

    bool wake_ready = false;
    if (wake_index >= 0 && (fds[static_cast<size_t>(wake_index)].revents != 0)) {
      std::array<char, 64> buffer = {};
      while (read(wake_pipe_[0], buffer.data(), buffer.size()) > 0) {
      }
      if (control_token_ && control_token_->IsInterrupted()) {
        return {StreamWaitStatus_::Interrupted, false, false, false, {}};
      }
      wake_ready = true;
    }
    return {StreamWaitStatus_::Ready,
            watch_read && (fds[0].revents & (POLLIN | POLLPRI)) != 0,
            watch_write && (fds[0].revents & POLLOUT) != 0,
            wake_ready || IsWakeTriggered_(wake_snapshot), {}};
  }

  void ShutdownPosix_() {
    wake_guard_.reset();
    if (wake_pipe_[0] >= 0) {
      (void)close(wake_pipe_[0]);
      wake_pipe_[0] = -1;
    }
    if (wake_pipe_[1] >= 0) {
      (void)close(wake_pipe_[1]);
      wake_pipe_[1] = -1;
    }
    remote_fd_ = -1;
  }
#endif

  void Shutdown_() {
    if (!initialized_) {
      return;
    }
#ifdef _WIN32
    ShutdownWindows_();
#else
    ShutdownPosix_();
#endif
    initialized_ = false;
  }

private:
  AMDomain::terminal::ITerminalPort *terminal_ = nullptr;
  AMDomain::client::amf control_token_ = nullptr;
  const std::atomic<unsigned long long> *wake_seq_ = nullptr;
  bool initialized_ = false;
  std::intptr_t remote_handle_ = -1;
  bool remote_is_socket_ = true;

#ifdef _WIN32
  std::array<HANDLE, 2> wait_handles_ = {nullptr, nullptr};
  DWORD wait_count_ = 0;
  DWORD wake_index_ = kInvalidIndex_;
  DWORD remote_index_ = kInvalidIndex_;
  HANDLE wake_event_ = nullptr;
  SOCKET remote_sock_ = INVALID_SOCKET;
  std::unique_ptr<AMDomain::client::ControlTokenWakeupSafeGaurd> wake_guard_ =
      nullptr;
#else
  int remote_fd_ = -1;
  int wake_pipe_[2] = {-1, -1};
  std::unique_ptr<AMDomain::client::ControlTokenWakeupSafeGaurd> wake_guard_ =
      nullptr;
#endif
};
}

struct TermAppService::ChannelStreamRuntime {
  std::string terminal_key = {};
  std::string channel_name = {};
  TerminalHandle terminal = nullptr;
  AMDomain::client::amf control_token = AMDomain::client::CreateClientControlToken();
  std::thread read_thread = {};
  std::atomic<unsigned long long> wake_seq = 0;
  mutable std::mutex mutex = {};
  TerminalCache cache = {};
  std::string pending_escape_tail = {};
  std::string send_buffer = {};
  std::string latest_output = {};
  size_t cached_bytes = 0;
  size_t max_cache_bytes = kDefaultStreamCacheBytes;
  bool overflowed = false;
  bool soft_limit_hit = false;
  bool hard_limit_hit = false;
  bool attached = false;
  bool stop_requested = false;
  bool closed = false;
  ChannelStreamProcessor processor = {};
  ECM last_error = OK;
};

TermAppService::~TermAppService() { StopAllChannelStreams_(); }

std::string TermAppService::BuildTerminalKey_(const ClientHandle &client,
                                              const char *action) {
  if (!client) {
    return "";
  }
  const std::string raw =
      AMStr::Strip(client->ConfigPort().GetNickname().empty()
                       ? client->ConfigPort().GetRequest().nickname
                       : client->ConfigPort().GetNickname());
  if (raw.empty()) {
    return "";
  }
  (void)action;
  return AMDomain::host::HostService::NormalizeNickname(raw);
}

std::string TermAppService::NormalizeTerminalKey_(const std::string &nickname) {
  std::string key =
      AMDomain::host::HostService::NormalizeNickname(AMStr::Strip(nickname));
  if (AMDomain::host::HostService::IsLocalNickname(key)) {
    key = "local";
  }
  return key;
}

std::string
TermAppService::BuildChannelStreamKey_(const std::string &terminal_key,
                                       const std::string &channel_name) {
  return terminal_key + "@" + channel_name;
}

ECMData<TerminalHandle>
TermAppService::QueryTerminal_(const std::string &terminal_key) const {
  if (terminal_key.empty()) {
    return {nullptr, Err(EC::InvalidArg, "terminal.query", "terminal_key",
                         "Terminal key is empty")};
  }

  std::lock_guard<std::mutex> lock(mutex_);
  auto it = terminals_.find(terminal_key);
  if (it == terminals_.end() || !it->second) {
    return {nullptr, Err(EC::ClientNotFound, "terminal.query", terminal_key,
                         "Terminal not found")};
  }
  return {it->second, OK};
}

ECMData<TerminalHandle>
TermAppService::CreateTerminal(const ClientHandle &client, bool detach) {
  if (!client) {
    return {nullptr, Err(EC::InvalidHandle, "terminal.create", "<client>",
                         "Client handle is null")};
  }

  const std::string terminal_key = BuildTerminalKey_(client, "terminal.create");
  if (terminal_key.empty()) {
    return {nullptr, Err(EC::InvalidArg, "terminal.create", "terminal_key",
                         "Failed to resolve terminal key from client")};
  }

  if (!detach) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = terminals_.find(terminal_key);
    if (it != terminals_.end() && it->second) {
      return {it->second, OK};
    }
  }

  auto create_result = AMDomain::terminal::CreateTerminalPort(client);
  if (!(create_result.rcm) || !create_result.data) {
    return create_result;
  }
  TerminalHandle created = create_result.data;

  auto open_result = created->OpenChannel({kDefaultTerminalChannelName}, {});
  if (!(open_result.rcm) && open_result.rcm.code != EC::TargetAlreadyExists) {
    return {nullptr, open_result.rcm};
  }

  auto active_result = created->ActiveChannel({kDefaultTerminalChannelName}, {});
  if (!(active_result.rcm) || !active_result.data.activated) {
    return {
        nullptr,
        active_result.rcm
            ? Err(EC::CommonFailure, "terminal.create.active_default",
                  terminal_key, "Failed to activate default terminal channel")
            : active_result.rcm};
  }

  if (detach) {
    return {created, OK};
  }
  return AddTerminal(client, created, false);
}

ECMData<TerminalHandle>
TermAppService::AddTerminal(const ClientHandle &client,
                            const TerminalHandle &terminal, bool force) {
  if (!client) {
    return {nullptr, Err(EC::InvalidHandle, "terminal.add", "<client>",
                         "Client handle is null")};
  }
  if (!terminal) {
    return {nullptr, Err(EC::InvalidHandle, "terminal.add", "<terminal>",
                         "Terminal handle is null")};
  }

  const std::string terminal_key = BuildTerminalKey_(client, "terminal.add");
  if (terminal_key.empty()) {
    return {nullptr, Err(EC::InvalidArg, "terminal.add", "terminal_key",
                         "Failed to resolve terminal key from client")};
  }

  TerminalHandle out = nullptr;
  bool replaced_terminal = false;
  {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = terminals_.find(terminal_key);
    if (it == terminals_.end()) {
      terminals_.emplace(terminal_key, terminal);
      out = terminal;
    } else {
      if (force || !it->second) {
        replaced_terminal =
            (it->second != nullptr && it->second.get() != terminal.get());
        it->second = terminal;
      }
      out = it->second;
    }
  }

  if (replaced_terminal) {
    // Existing stream pumps are bound to the old terminal handle.
    StopAllTerminalStreamsByKey_(terminal_key);
  }
  return {out, OK};
}

ECMData<TerminalHandle>
TermAppService::EnsureTerminal(const ClientHandle &client) {
  if (!client) {
    return {nullptr, Err(EC::InvalidHandle, "terminal.ensure", "<client>",
                         "Client handle is null")};
  }

  const std::string terminal_key = BuildTerminalKey_(client, "terminal.ensure");
  if (terminal_key.empty()) {
    return {nullptr, Err(EC::InvalidArg, "terminal.ensure", "terminal_key",
                         "Failed to resolve terminal key from client")};
  }

  {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = terminals_.find(terminal_key);
    if (it != terminals_.end() && it->second) {
      return {it->second, OK};
    }
  }

  return CreateTerminal(client, false);
}

ECMData<TerminalHandle>
TermAppService::GetTerminalByNickname(const std::string &nickname,
                                      bool case_sensitive) const {
  const std::string key = NormalizeTerminalKey_(nickname);
  if (key.empty()) {
    return {nullptr, Err(EC::InvalidArg, "terminal.get", nickname,
                         "Terminal nickname is empty")};
  }

  if (case_sensitive) {
    return QueryTerminal_(key);
  }

  const std::string lowered = AMStr::lowercase(key);
  std::vector<std::string> matched_names = {};
  TerminalHandle matched_terminal = nullptr;

  {
    std::lock_guard<std::mutex> lock(mutex_);
    for (const auto &entry : terminals_) {
      if (!entry.second) {
        continue;
      }
      if (AMStr::lowercase(entry.first) != lowered) {
        continue;
      }
      matched_names.push_back(entry.first);
      matched_terminal = entry.second;
    }
  }

  if (matched_names.size() == 1 && matched_terminal) {
    return {matched_terminal, OK};
  }
  if (matched_names.size() > 1) {
    return {nullptr, Err(EC::ClientNotFound, "terminal.get", nickname,
                         AMStr::fmt("Ambiguous nickname, candidates: {}",
                                    AMStr::join(matched_names, ", ")))};
  }
  return {nullptr, Err(EC::ClientNotFound, "terminal.get", nickname,
                       "Terminal not found")};
}

std::vector<std::string> TermAppService::ListTerminalNames() const {
  std::vector<std::string> names = {};
  std::lock_guard<std::mutex> lock(mutex_);
  names.reserve(terminals_.size());
  for (const auto &entry : terminals_) {
    if (entry.second) {
      names.push_back(entry.first);
    }
  }
  return names;
}

void TermAppService::StreamReadLoop_(const ChannelStreamRuntimeHandle &runtime) {
  if (!runtime || !runtime->terminal) {
    return;
  }

  auto parse_chunk_locked = [&](std::string_view chunk) -> ParsedScreenChunk_ {
    if (chunk.empty()) {
      return {};
    }
    auto parsed = ParseScreenChunk_(runtime->cache.in_alternate_screen,
                                    runtime->pending_escape_tail, chunk);
    runtime->cache.in_alternate_screen = parsed.in_alternate_screen;
    runtime->pending_escape_tail = parsed.pending_escape_tail;
    return parsed;
  };

  auto append_cache_locked = [&](std::string_view chunk) -> CacheAppendOutcome_ {
    CacheAppendOutcome_ out = {};
    if (chunk.empty()) {
      return out;
    }
    auto parsed = parse_chunk_locked(chunk);
    out.appended_bytes = parsed.appended_bytes;

    for (auto &block : parsed.blocks) {
      if (block.data.empty()) {
        continue;
      }
      if (!runtime->cache.blocks.empty() &&
          runtime->cache.blocks.back().screen == block.screen) {
        runtime->cache.blocks.back().data.append(block.data);
      } else {
        runtime->cache.blocks.push_back(std::move(block));
      }
    }
    runtime->cached_bytes += out.appended_bytes;
    if (!runtime->soft_limit_hit &&
        runtime->cached_bytes >= kTerminalCacheSoftLimitBytes) {
      runtime->soft_limit_hit = true;
      out.soft_limit_hit_now = true;
    }
    if (runtime->cached_bytes >= kTerminalCacheHardLimitBytes) {
      runtime->hard_limit_hit = true;
      out.hard_limit_hit = true;
    }
    return out;
  };

  auto active_result =
      runtime->terminal->ActiveChannel({runtime->channel_name}, {});
  if (!(active_result.rcm) || !active_result.data.activated) {
    std::lock_guard<std::mutex> lock(runtime->mutex);
    runtime->last_error = active_result.rcm
                              ? Err(EC::NoConnection, "terminal.stream.active",
                                    runtime->channel_name,
                                    "Failed to activate target channel")
                              : active_result.rcm;
    runtime->closed = true;
    return;
  }

  StreamRemoteWaiter_ remote_waiter(runtime->terminal.get(),
                                    runtime->control_token, &runtime->wake_seq);
  const ECM waiter_init_rcm = remote_waiter.Init();
  if (!(waiter_init_rcm)) {
    std::lock_guard<std::mutex> lock(runtime->mutex);
    runtime->last_error = waiter_init_rcm;
    runtime->closed = true;
    return;
  }

  const ClientControlComponent io_control(runtime->control_token, -1);
  auto close_with_error = [&](const ECM &ecm) {
    std::lock_guard<std::mutex> lock(runtime->mutex);
    runtime->last_error = ecm;
    runtime->closed = true;
  };

  while (true) {
    bool has_pending_write = false;
    unsigned long long wake_snapshot = 0;
    {
      std::lock_guard<std::mutex> lock(runtime->mutex);
      if (runtime->stop_requested) {
        break;
      }
      wake_snapshot = runtime->wake_seq.load(std::memory_order_acquire);
      has_pending_write = !runtime->send_buffer.empty();
    }

    const StreamWaitResult_ wait_result =
        remote_waiter.Wait(true, has_pending_write, kStreamWaitTimeoutMs,
                           wake_snapshot);
    if (wait_result.status == StreamWaitStatus_::Timeout) {
      continue;
    }
    if (wait_result.status == StreamWaitStatus_::Interrupted) {
      bool should_exit = false;
      {
        std::lock_guard<std::mutex> lock(runtime->mutex);
        should_exit = runtime->stop_requested;
      }
      if (should_exit) {
        break;
      }
      continue;
    }
    if (wait_result.status == StreamWaitStatus_::Error) {
      close_with_error(Err(
          EC::SocketRecvError, "terminal.stream.wait", runtime->channel_name,
          wait_result.error.empty() ? "Failed while waiting remote output"
                                    : wait_result.error));
      break;
    }

    bool should_break = false;
    if (wait_result.read_ready) {
      for (int i = 0; i < kStreamBurstLimit; ++i) {
        auto read_result = runtime->terminal->ReadChannel(
            {std::optional<std::string>(runtime->channel_name),
             kStreamReadChunkBytes},
            io_control);
        if (!(read_result.rcm)) {
          bool should_exit = true;
          if (read_result.rcm.code == EC::Terminate) {
            std::lock_guard<std::mutex> lock(runtime->mutex);
            should_exit = runtime->stop_requested;
          }
          if (should_exit) {
            close_with_error(read_result.rcm.code == EC::Terminate ? OK
                                                                   : read_result.rcm);
            should_break = true;
            break;
          }
          break;
        }

        if (!read_result.data.output.empty()) {
          ChannelStreamProcessor output_processor = {};
          CacheAppendOutcome_ cache_outcome = {};
          {
            std::lock_guard<std::mutex> lock(runtime->mutex);
            runtime->latest_output = read_result.data.output;
            if (runtime->attached && runtime->processor) {
              output_processor = runtime->processor;
              (void)parse_chunk_locked(read_result.data.output);
            } else {
              cache_outcome = append_cache_locked(read_result.data.output);
            }
          }
          if (output_processor) {
            try {
              output_processor(read_result.data.output);
            } catch (...) {
            }
          }
          if (cache_outcome.hard_limit_hit) {
            close_with_error(Err(
                EC::FilesystemNoSpace, "terminal.stream.cache.limit",
                runtime->channel_name,
                "Terminal output cache hard limit exceeded (128MB); channel "
                "closed"));
            (void)runtime->terminal->CloseChannel({runtime->channel_name, true},
                                                  io_control);
            should_break = true;
            break;
          }
        }

        if (read_result.data.eof) {
          close_with_error(OK);
          should_break = true;
          break;
        }
        if (read_result.data.output.empty()) {
          break;
        }
      }
    }
    if (should_break) {
      break;
    }

    if (wait_result.write_ready) {
      for (int i = 0; i < kStreamBurstLimit; ++i) {
        std::string write_chunk = {};
        {
          std::lock_guard<std::mutex> lock(runtime->mutex);
          if (runtime->send_buffer.empty()) {
            break;
          }
          const size_t take_size =
              std::min(kStreamWriteChunkBytes, runtime->send_buffer.size());
          write_chunk.assign(runtime->send_buffer.data(), take_size);
        }

        auto write_result = runtime->terminal->WriteChannel(
            {std::optional<std::string>(runtime->channel_name), write_chunk},
            io_control);
        if (!(write_result.rcm)) {
          bool should_exit = true;
          if (write_result.rcm.code == EC::Terminate) {
            std::lock_guard<std::mutex> lock(runtime->mutex);
            should_exit = runtime->stop_requested;
          }
          if (should_exit) {
            close_with_error(write_result.rcm.code == EC::Terminate
                                 ? OK
                                 : write_result.rcm);
            should_break = true;
            break;
          }
          break;
        }

        const size_t consumed = std::min(
            write_chunk.size(), static_cast<size_t>(write_result.data.bytes_written));
        if (consumed == 0) {
          break;
        }
        {
          std::lock_guard<std::mutex> lock(runtime->mutex);
          if (consumed >= runtime->send_buffer.size()) {
            runtime->send_buffer.clear();
          } else {
            runtime->send_buffer.erase(0, consumed);
          }
        }
        if (consumed < write_chunk.size()) {
          break;
        }
      }
    }
    if (should_break) {
      break;
    }
  }
}

void TermAppService::StopChannelStreamRuntime_(ChannelStreamRuntimeHandle runtime) {
  if (!runtime) {
    return;
  }
  {
    std::lock_guard<std::mutex> lock(runtime->mutex);
    runtime->attached = false;
    runtime->processor = {};
    runtime->stop_requested = true;
    runtime->wake_seq.fetch_add(1, std::memory_order_release);
    if (runtime->control_token) {
      runtime->control_token->RequestInterrupt();
    }
  }
  if (runtime->read_thread.joinable()) {
    if (runtime->read_thread.get_id() == std::this_thread::get_id()) {
      runtime->read_thread.detach();
    } else {
      runtime->read_thread.join();
    }
  }
}

void TermAppService::StopAllChannelStreams_() {
  std::vector<ChannelStreamRuntimeHandle> runtimes = {};
  {
    std::lock_guard<std::mutex> lock(stream_mutex_);
    runtimes.reserve(channel_streams_.size());
    for (auto &entry : channel_streams_) {
      runtimes.push_back(entry.second);
    }
    channel_streams_.clear();
  }
  for (auto &runtime : runtimes) {
    StopChannelStreamRuntime_(runtime);
  }
}

void TermAppService::StopAllTerminalStreamsByKey_(
    const std::string &terminal_key) {
  if (terminal_key.empty()) {
    return;
  }
  std::vector<ChannelStreamRuntimeHandle> runtimes = {};
  {
    std::lock_guard<std::mutex> lock(stream_mutex_);
    for (auto it = channel_streams_.begin(); it != channel_streams_.end();) {
      if (!it->second || it->second->terminal_key != terminal_key) {
        ++it;
        continue;
      }
      runtimes.push_back(it->second);
      it = channel_streams_.erase(it);
    }
  }
  for (auto &runtime : runtimes) {
    StopChannelStreamRuntime_(runtime);
  }
}

ECMData<TermAppService::ChannelStreamAttachResult>
TermAppService::AttachChannelStream(const std::string &terminal_nickname,
                                    const std::string &channel_name,
                                    ChannelStreamProcessor processor,
                                    size_t max_cache_bytes) {
  ECMData<ChannelStreamAttachResult> out = {};
  const std::string terminal_key = NormalizeTerminalKey_(terminal_nickname);
  const std::string channel = AMStr::Strip(channel_name);
  if (terminal_key.empty()) {
    out.rcm = Err(EC::InvalidArg, "terminal.stream.attach", "terminal_key",
                  "Terminal nickname is empty");
    return out;
  }
  if (channel.empty()) {
    out.rcm = Err(EC::InvalidArg, "terminal.stream.attach", "channel_name",
                  "Channel name is empty");
    return out;
  }
  if (!processor) {
    out.rcm = Err(EC::InvalidArg, "terminal.stream.attach", channel,
                  "Processor callback is empty");
    return out;
  }
  if (max_cache_bytes == 0) {
    max_cache_bytes = kDefaultStreamCacheBytes;
  }

  auto terminal_result = QueryTerminal_(terminal_key);
  if (!(terminal_result.rcm) || !terminal_result.data) {
    out.rcm = terminal_result.rcm
                  ? Err(EC::InvalidHandle, "terminal.stream.attach", terminal_key,
                        "Terminal handle is null")
                  : terminal_result.rcm;
    return out;
  }

  const std::string stream_key = BuildChannelStreamKey_(terminal_key, channel);
  ChannelStreamRuntimeHandle runtime = nullptr;
  ChannelStreamRuntimeHandle stale_runtime = nullptr;
  {
    std::lock_guard<std::mutex> lock(stream_mutex_);
    auto it = channel_streams_.find(stream_key);
    if (it == channel_streams_.end() || !it->second) {
      runtime = std::make_shared<ChannelStreamRuntime>();
      runtime->terminal_key = terminal_key;
      runtime->channel_name = channel;
      runtime->terminal = terminal_result.data;
      runtime->max_cache_bytes = max_cache_bytes;
      runtime->read_thread =
          std::thread([this, runtime]() { StreamReadLoop_(runtime); });
      channel_streams_[stream_key] = runtime;
    } else {
      runtime = it->second;
      bool stale = false;
      {
        std::lock_guard<std::mutex> runtime_lock(runtime->mutex);
        stale = runtime->closed || runtime->stop_requested;
      }
      if (stale) {
        stale_runtime = runtime;
        runtime = std::make_shared<ChannelStreamRuntime>();
        runtime->terminal_key = terminal_key;
        runtime->channel_name = channel;
        runtime->terminal = terminal_result.data;
        runtime->max_cache_bytes = max_cache_bytes;
        runtime->read_thread =
            std::thread([this, runtime]() { StreamReadLoop_(runtime); });
        it->second = runtime;
      }
    }
  }
  if (stale_runtime) {
    StopChannelStreamRuntime_(stale_runtime);
  }
  if (!runtime) {
    out.rcm = Err(EC::InvalidHandle, "terminal.stream.attach", stream_key,
                  "Failed to resolve stream runtime");
    return out;
  }

  std::vector<OutputBlock> replay_blocks = {};
  std::string main_content = {};
  std::string latest_alternate_content = {};
  std::string fallback_output = {};
  {
    std::lock_guard<std::mutex> lock(runtime->mutex);
    runtime->max_cache_bytes = std::max<size_t>(1, max_cache_bytes);
    replay_blocks.swap(runtime->cache.blocks);
    fallback_output = runtime->latest_output;
    runtime->cached_bytes = 0;
    out.data.in_alternate_screen = runtime->cache.in_alternate_screen;
    out.data.soft_limit_hit = runtime->soft_limit_hit;
    out.data.hard_limit_hit = runtime->hard_limit_hit;
    out.data.overflowed = runtime->overflowed;
    runtime->overflowed = false;
    out.data.closed = runtime->closed;
    out.data.last_error = runtime->last_error;
    runtime->soft_limit_hit = false;
    runtime->processor = processor;
    runtime->attached = false;
  }

  for (const auto &block : replay_blocks) {
    if (block.data.empty()) {
      continue;
    }
    if (block.screen == ScreenKind::Main) {
      main_content.append(block.data);
      continue;
    }
    latest_alternate_content = block.data;
  }

  if (!main_content.empty()) {
    try {
      processor(main_content);
    } catch (...) {
    }
    out.data.replayed_bytes += main_content.size();
  }
  if (out.data.in_alternate_screen) {
    try {
      processor("\x1b[?1049h");
    } catch (...) {
    }
    if (!latest_alternate_content.empty()) {
      try {
        processor(latest_alternate_content);
      } catch (...) {
      }
      out.data.replayed_bytes += latest_alternate_content.size();
    }
  }

  if (out.data.replayed_bytes == 0 && !fallback_output.empty()) {
    try {
      processor(fallback_output);
    } catch (...) {
    }
    out.data.fallback_bytes = fallback_output.size();
  }
  {
    std::lock_guard<std::mutex> lock(runtime->mutex);
    runtime->attached = true;
  }
  out.rcm = OK;
  return out;
}

ECM TermAppService::DetachChannelStream(const std::string &terminal_nickname,
                                        const std::string &channel_name) {
  const std::string terminal_key = NormalizeTerminalKey_(terminal_nickname);
  const std::string channel = AMStr::Strip(channel_name);
  if (terminal_key.empty() || channel.empty()) {
    return Err(EC::InvalidArg, "terminal.stream.detach", "stream_key",
               "Terminal nickname or channel name is empty");
  }
  const std::string stream_key = BuildChannelStreamKey_(terminal_key, channel);
  ChannelStreamRuntimeHandle runtime = nullptr;
  {
    std::lock_guard<std::mutex> lock(stream_mutex_);
    auto it = channel_streams_.find(stream_key);
    if (it != channel_streams_.end()) {
      runtime = it->second;
    }
  }
  if (!runtime) {
    return OK;
  }
  std::lock_guard<std::mutex> lock(runtime->mutex);
  runtime->attached = false;
  runtime->processor = {};
  return OK;
}

ECM TermAppService::StopChannelStream(const std::string &terminal_nickname,
                                      const std::string &channel_name) {
  const std::string terminal_key = NormalizeTerminalKey_(terminal_nickname);
  const std::string channel = AMStr::Strip(channel_name);
  if (terminal_key.empty() || channel.empty()) {
    return Err(EC::InvalidArg, "terminal.stream.stop", "stream_key",
               "Terminal nickname or channel name is empty");
  }
  const std::string stream_key = BuildChannelStreamKey_(terminal_key, channel);
  ChannelStreamRuntimeHandle runtime = nullptr;
  {
    std::lock_guard<std::mutex> lock(stream_mutex_);
    auto it = channel_streams_.find(stream_key);
    if (it == channel_streams_.end()) {
      return OK;
    }
    runtime = it->second;
    channel_streams_.erase(it);
  }
  StopChannelStreamRuntime_(runtime);
  return OK;
}

ECM TermAppService::QueueChannelInput(const std::string &terminal_nickname,
                                      const std::string &channel_name,
                                      std::string input_bytes) {
  const std::string terminal_key = NormalizeTerminalKey_(terminal_nickname);
  const std::string channel = AMStr::Strip(channel_name);
  if (terminal_key.empty() || channel.empty()) {
    return Err(EC::InvalidArg, "terminal.stream.queue_input", "stream_key",
               "Terminal nickname or channel name is empty");
  }
  if (input_bytes.empty()) {
    return OK;
  }

  const std::string stream_key = BuildChannelStreamKey_(terminal_key, channel);
  ChannelStreamRuntimeHandle runtime = nullptr;
  {
    std::lock_guard<std::mutex> lock(stream_mutex_);
    auto it = channel_streams_.find(stream_key);
    if (it != channel_streams_.end()) {
      runtime = it->second;
    }
  }
  if (!runtime) {
    return Err(EC::ClientNotFound, "terminal.stream.queue_input", stream_key,
               "Terminal stream runtime is not available");
  }

  {
    std::lock_guard<std::mutex> lock(runtime->mutex);
    if (runtime->stop_requested || runtime->closed) {
      return Err(EC::NoConnection, "terminal.stream.queue_input", stream_key,
                 "Terminal stream is closed");
    }
    runtime->send_buffer.append(input_bytes);
    runtime->wake_seq.fetch_add(1, std::memory_order_release);
  }
  return OK;
}

TermAppService::ChannelStreamState TermAppService::GetChannelStreamState(
    const std::string &terminal_nickname, const std::string &channel_name) const {
  ChannelStreamState out = {};
  const std::string terminal_key = NormalizeTerminalKey_(terminal_nickname);
  const std::string channel = AMStr::Strip(channel_name);
  if (terminal_key.empty() || channel.empty()) {
    return out;
  }
  const std::string stream_key = BuildChannelStreamKey_(terminal_key, channel);

  ChannelStreamRuntimeHandle runtime = nullptr;
  {
    std::lock_guard<std::mutex> lock(stream_mutex_);
    auto it = channel_streams_.find(stream_key);
    if (it != channel_streams_.end()) {
      runtime = it->second;
    }
  }
  if (!runtime) {
    return out;
  }

  std::lock_guard<std::mutex> lock(runtime->mutex);
  out.exists = true;
  out.attached = runtime->attached;
  out.closed = runtime->closed;
  out.overflowed = runtime->overflowed;
  out.in_alternate_screen = runtime->cache.in_alternate_screen;
  out.soft_limit_hit = runtime->soft_limit_hit;
  out.hard_limit_hit = runtime->hard_limit_hit;
  out.cached_bytes = runtime->cached_bytes;
  out.last_error = runtime->last_error;
  return out;
}

ECM TermAppService::RemoveTerminal(const std::string &nickname,
                                   const ClientControlComponent &control) {
  const std::string key = NormalizeTerminalKey_(nickname);
  if (key.empty()) {
    return Err(EC::InvalidArg, "terminal.remove", nickname,
               "Terminal nickname is empty");
  }

  TerminalHandle target = nullptr;
  {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = terminals_.find(key);
    if (it == terminals_.end()) {
      return OK;
    }
    target = it->second;
    terminals_.erase(it);
  }

  StopAllTerminalStreamsByKey_(key);

  if (!target) {
    return OK;
  }

  const auto session_state = target->GetSessionState();
  if (session_state.status != AMDomain::client::ClientStatus::OK) {
    // Disconnected sessions can fail or block during graceful channel close.
    // Terminal map entry is already removed, so best-effort cleanup stops here.
    return OK;
  }

  auto list_result = target->ListChannels({}, control);
  if (!(list_result.rcm)) {
    if (list_result.rcm.code == EC::NoConnection ||
        list_result.rcm.code == EC::ConnectionLost ||
        list_result.rcm.code == EC::NoSession) {
      return OK;
    }
    return list_result.rcm;
  }
  const AMDomain::client::ClientControlComponent close_control =
      control.RemainingTimeMs().has_value()
          ? control
          : AMDomain::client::ClientControlComponent(
                control.ControlToken(), kTerminalRemoveCloseTimeoutMs);
  ECM status = OK;
  for (const auto &name : list_result.data.channel_names) {
    auto close_result = target->CloseChannel({name, true}, close_control);
    if (!(close_result.rcm)) {
      if (close_result.rcm.code == EC::NoConnection ||
          close_result.rcm.code == EC::ConnectionLost ||
          close_result.rcm.code == EC::NoSession ||
          close_result.rcm.code == EC::ClientNotFound) {
        continue;
      }
      status = close_result.rcm;
    }
  }
  return status;
}

} // namespace AMApplication::terminal

