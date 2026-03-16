#pragma once
// standard library
#include "domain/host/HostModel.hpp"
#include "foundation/Enum.hpp"
#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <ctime>
#include <fcntl.h>
#include <fstream>
#include <functional>
#include <memory>
#include <mutex>
#include <regex>
#include <stdexcept>
#include <string>
#include <type_traits>
#include <unordered_map>
#include <vector>
#ifdef _WIN32
#define _WINSOCKAPI_
#include <shlobj.h>
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <cerrno>
#include <netinet/in.h>
#include <sys/socket.h>
#ifdef __linux__
#include <sys/eventfd.h>
#endif
#include <unistd.h>
#endif

// project headers
#include "foundation/DataClass.hpp"
#include "foundation/tools/auth.hpp"
#include "infrastructure/client/common/Base.hpp"
#include <curl/curl.h>
#include <libssh2.h>
#include <libssh2_sftp.h>
#include <magic_enum/magic_enum.hpp>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>

#ifndef _WIN32
using SOCKET = int;
constexpr SOCKET INVALID_SOCKET = -1;
constexpr int SOCKET_ERROR = -1;
inline int closesocket(SOCKET s) { return close(s); }
#endif

/*
class AMBaseTerminal {
public:
  using TerminalOutputCallback = std::function<void(const std::string &)>;
  virtual ~AMBaseTerminal() = default;

  virtual ECM Connect(bool force = false,
                      int timeout_ms = -1, int64_t start_time = -1) = 0;
  virtual ECM Check(int timeout_ms = -1,
                    int64_t start_time = -1) = 0;
  virtual void PauseReading() = 0;
  virtual void ResumeReading() = 0;
  virtual void
  SetTerminalOutputCallback(TerminalOutputCallback output_cb = {}) = 0;
  virtual ECM SetTerminalWindowInfo(const TerminalWindowInfo &window,
                                    int timeout_ms = -1,
                                    int64_t start_time = -1) = 0;
  virtual ECM TerminalWrite(const std::string &msg, int timeout_ms = -1,
                            int64_t start_time = -1) = 0;
  virtual ECM TerminalClose() = 0;
  virtual void SetReaderWaitTimeoutMs(int timeout_ms) = 0;
};

class AMSFTPTerminal : public SFTPSessionBase, public AMBaseTerminal {
public:
  using TerminalOutputCallback = AMBaseTerminal::TerminalOutputCallback;

private:
  std::unique_ptr<SafeChannel> terminal_channel;
  std::atomic<bool> reader_running{false};
  std::atomic<bool> reader_paused{false};
  std::atomic<int> reader_wait_timeout_ms{200};
  std::thread reader_thread;
  std::condition_variable reader_cv;
  std::mutex reader_cv_mtx;
  std::mutex terminal_cb_mtx;

  void StartReader() {
    if (reader_running.load(std::memory_order_relaxed)) {
      return;
    }
    bool has_cb = false;
    {
      std::lock_guard<std::mutex> lock(terminal_cb_mtx);
      has_cb = static_cast<bool>(terminal_output_cb);
    }
    reader_running.store(true, std::memory_order_relaxed);
    reader_paused.store(!has_cb, std::memory_order_relaxed);
    reader_thread = std::thread([this]() { ReaderLoop(); });
  }

  void StopReader() {
    if (!reader_running.load(std::memory_order_relaxed) &&
        !reader_thread.joinable()) {
      return;
    }
    reader_running.store(false, std::memory_order_relaxed);
    reader_paused.store(false, std::memory_order_relaxed);
    reader_cv.notify_all();
    if (reader_thread.joinable()) {
      reader_thread.join();
    }
  }

  bool IsTerminalAlive() {
    if (!terminal_channel || !terminal_channel->channel) {
      return false;
    }
    std::lock_guard<std::recursive_mutex> lock(mtx);
    if (libssh2_channel_eof(terminal_channel->channel) != 0) {
      return false;
    }
    return true;
  }

  void ReaderLoop() {
    std::array<char, 4096> buffer;
    while (reader_running.load(std::memory_order_relaxed)) {
      if (reader_paused.load(std::memory_order_relaxed)) {
        std::unique_lock<std::mutex> lock(reader_cv_mtx);
        reader_cv.wait(lock, [this]() {
          return !reader_paused.load(std::memory_order_relaxed) ||
                 !reader_running.load(std::memory_order_relaxed);
        });
        continue;
      }

      if (this->IsOperationInterrupted_(terminal_interrupt_flag)) {
        reader_running.store(false, std::memory_order_relaxed);
        break;
      }

      if (!terminal_channel || !terminal_channel->channel || !session) {
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
        continue;
      }

      int64_t start_time = AMTime::miliseconds();
      int wait_timeout = reader_wait_timeout_ms.load(std::memory_order_relaxed);
      WaitResult wr = wait_for_socket(SocketWaitType::Read, start_time,
                                      wait_timeout, terminal_interrupt_flag);
      if (wr == WaitResult::Timeout) {
        continue;
      }
      if (wr == WaitResult::Interrupted) {
        reader_running.store(false, std::memory_order_relaxed);
        break;
      }
      if (wr == WaitResult::Error) {
        continue;
      }

      std::string output;
      {
        std::lock_guard<std::recursive_mutex> lock(mtx);
        libssh2_session_set_blocking(session, 0);
        while (true) {
          ssize_t nbytes =
              libssh2_channel_read(terminal_channel->channel, buffer.data(),
                                   static_cast<size_t>(buffer.size()));
          if (nbytes > 0) {
            output.append(buffer.data(), static_cast<size_t>(nbytes));
            continue;
          }
          if (nbytes == 0) {
            terminal_channel->close();
            terminal_channel.reset();
            reader_running.store(false, std::memory_order_relaxed);
            break;
          }
          if (nbytes == LIBSSH2_ERROR_EAGAIN) {
            break;
          }
          terminal_channel->close();
          terminal_channel.reset();
          reader_running.store(false, std::memory_order_relaxed);
          break;
        }
      }

      if (!output.empty()) {
        TerminalOutputCallback cb;
        {
          std::lock_guard<std::mutex> lock(terminal_cb_mtx);
          cb = terminal_output_cb;
        }
        if (cb) {
          CallCallbackSafe(cb, output);
        }
      }
    }
  }

  ECM TerminalInitInternal(const TerminalWindowInfo &window,
                           TerminalOutputCallback output_cb = {}, int timeout_ms
= -1, int64_t start_time = -1) { std::lock_guard<std::recursive_mutex>
lock(mtx); if (!session) { return {EC::NoSession, "Session not initialized"};
    }

    terminal_window = window;
    if (output_cb) {
      std::lock_guard<std::mutex> cb_lock(terminal_cb_mtx);
      terminal_output_cb = std::move(output_cb);
    }

    amf flag = interrupt_flag ? interrupt_flag : terminal_interrupt_flag;
    start_time = start_time == -1 ? AMTime::miliseconds() : start_time;
    if (this->IsOperationInterrupted_(flag)) {
      terminal_channel.reset();
      return {EC::Terminate, "Terminal init interrupted"};
    }

    terminal_channel.reset();
    terminal_channel = std::make_unique<SafeChannel>();
    ECM init_rcm =
        terminal_channel->Init(session, flag, timeout_ms, start_time);
    if (init_rcm.first != EC::Success) {
      terminal_channel.reset();
      return {init_rcm.first, AMStr::fmt("Terminal channel not initialized: {}",
                                         init_rcm.second)};
    }

    libssh2_session_set_blocking(session, 0);

    int rc = 0;
    WaitResult wr = WaitResult::Ready;
    while ((rc = libssh2_channel_request_pty_ex(
                terminal_channel->channel, terminal_window.term.c_str(),
                static_cast<unsigned int>(terminal_window.term.size()), nullptr,
                0, terminal_window.cols, terminal_window.rows,
                terminal_window.width, terminal_window.height)) ==
           LIBSSH2_ERROR_EAGAIN) {
      wr = wait_for_socket(SocketWaitType::Auto, start_time, timeout_ms, flag);
      if (wr != WaitResult::Ready) {
        goto cleanup;
      }
    }
    if (rc != 0) {
      terminal_channel.reset();
      return {GetLastEC(),
              AMStr::fmt("Terminal request pty failed: {}", GetLastErrorMsg())};
    }

    while ((rc = libssh2_channel_shell(terminal_channel->channel)) ==
           LIBSSH2_ERROR_EAGAIN) {
      wr = wait_for_socket(SocketWaitType::Auto, start_time, timeout_ms, flag);
      if (wr != WaitResult::Ready) {
        goto cleanup;
      }
    }
    if (rc != 0) {
      terminal_channel.reset();
      return {GetLastEC(),
              AMStr::fmt("Terminal start shell failed: {}", GetLastErrorMsg())};
    }

    libssh2_session_set_blocking(session, 0);
    return {EC::Success, ""};

  cleanup:
    terminal_channel.reset();
    switch (wr) {
    case WaitResult::Timeout:
      return {EC::OperationTimeout, "Terminal init timed out"};
    case WaitResult::Interrupted:
      return {EC::Terminate, "Terminal init interrupted"};
    case WaitResult::Error:
      return {EC::SocketRecvError, "Socket error during terminal init"};
    default:
      return {EC::UnknownError, "Terminal init failed"};
    }
  }

public:
  TerminalWindowInfo terminal_window = {};
  amf terminal_interrupt_flag = std::make_shared<TaskControlToken>();
  TerminalOutputCallback terminal_output_cb = {};

  AMSFTPTerminal(AMDomain::client::IClientConfigPort *config_port,
                 AMDomain::client::IClientTaskControlPort *control_port,
                 const std::vector<std::string> &keys = {},
                 unsigned int tracer_capacity = 10, TraceCallback trace_cb = {},
                 AuthCallback auth_cb = {})
      : SFTPSessionBase(config_port, control_port, keys, tracer_capacity,
                  std::move(trace_cb), std::move(auth_cb)) {
    auto req = request_atomic_.lock();
    req->protocol = ClientProtocol::Base;
    res_data = req.load();
  }

  AMSFTPTerminal(const ConRequest &request,
                 const std::vector<std::string> &keys = {},
                 unsigned int tracer_capacity = 10, TraceCallback trace_cb = {},
                 AuthCallback auth_cb = {})
      : SFTPSessionBase(request, keys, tracer_capacity, std::move(trace_cb),
                  std::move(auth_cb)) {
    res_data.protocol = ClientProtocol::Base;
    StoreRequest_(res_data);
  }

  ~AMSFTPTerminal() override {
    StopReader();
    TerminalClose();
  }

  ECM Connect(bool force = false,
              int timeout_ms = -1, int64_t start_time = -1) override {
    start_time = start_time == -1 ? AMTime::miliseconds() : start_time;

    if (has_connected.load(std::memory_order_relaxed) && session && !force) {
      ECM chk = Check( timeout_ms, start_time);
      if (chk.first == EC::Success) {
        return chk;
      }
      if (session && !IsTerminalAlive()) {
        TerminalOutputCallback cb;
        {
          std::lock_guard<std::mutex> lock(terminal_cb_mtx);
          cb = terminal_output_cb;
        }
        ECM term_rcm = TerminalInitInternal(terminal_window, cb,
                                            timeout_ms, start_time);
        if (term_rcm.first == EC::Success) {
          StartReader();
        }
        return term_rcm;
      }
    }

    StopReader();
    TerminalClose();
    ECM ecm = BaseConnect(true,  start_time, timeout_ms);
    if (ecm.first != EC::Success) {
      return ecm;
    }
    TerminalOutputCallback cb;
    {
      std::lock_guard<std::mutex> lock(terminal_cb_mtx);
      cb = terminal_output_cb;
    }
    ECM term_rcm = TerminalInitInternal(terminal_window, cb,
                                        timeout_ms, start_time);
    if (term_rcm.first == EC::Success) {
      StartReader();
    }
    return term_rcm;
  }

  ECM Check(int timeout_ms = -1,
            int64_t start_time = -1) override {
    amf flag = interrupt_flag;
    if (this->IsOperationInterrupted_(flag)) {
      ECM rcm = {EC::Terminate, "Check interrupted"};
      SetState(rcm);
      return rcm;
    }
    (void)timeout_ms;
    (void)start_time;
    if (!session || sock == INVALID_SOCKET ||
        !has_connected.load(std::memory_order_relaxed)) {
      ECM rcm = {EC::NoConnection, "Session not connected"};
      SetState(rcm);
      return rcm;
    }

    if (!IsTerminalAlive()) {
      ECM rcm = {EC::NoConnection, "Terminal not initialized"};
      SetState(rcm);
      return rcm;
    }

    SetState({EC::Success, ""});
    return {EC::Success, ""};
  }

  void PauseReading() override {
    reader_paused.store(true, std::memory_order_relaxed);
  }

  void ResumeReading() override {
    reader_paused.store(false, std::memory_order_relaxed);
    reader_cv.notify_all();
  }

  void
  SetTerminalOutputCallback(TerminalOutputCallback output_cb = {}) override {
    {
      std::lock_guard<std::mutex> lock(terminal_cb_mtx);
      terminal_output_cb = std::move(output_cb);
    }
    if (terminal_output_cb) {
      ResumeReading();
    } else {
      PauseReading();
    }
  }

  void SetReaderWaitTimeoutMs(int timeout_ms) override {
    if (timeout_ms < 1) {
      timeout_ms = 1;
    }
    reader_wait_timeout_ms.store(timeout_ms, std::memory_order_relaxed);
  }

  ECM SetTerminalWindowInfo(const TerminalWindowInfo &window, int timeout_ms =
-1, int64_t start_time = -1) override { terminal_window = window; if
(!terminal_channel || !terminal_channel->channel) { return {EC::Success, ""};
    }

    amf flag = interrupt_flag ? interrupt_flag : terminal_interrupt_flag;
    start_time = start_time == -1 ? AMTime::miliseconds() : start_time;
    int rc = 0;
    WaitResult wr = WaitResult::Ready;

    PauseReading();
    {
      std::lock_guard<std::recursive_mutex> lock(mtx);
      libssh2_session_set_blocking(session, 0);
      while ((rc = libssh2_channel_request_pty_size_ex(
                  terminal_channel->channel, terminal_window.cols,
                  terminal_window.rows, terminal_window.width,
                  terminal_window.height)) == LIBSSH2_ERROR_EAGAIN) {
        wr =
            wait_for_socket(SocketWaitType::Auto, start_time, timeout_ms, flag);
        if (wr != WaitResult::Ready) {
          goto cleanup;
        }
      }
    }

    ResumeReading();
    if (rc != 0) {
      return {GetLastEC(),
              AMStr::fmt("Terminal resize failed: {}", GetLastErrorMsg())};
    }
    return {EC::Success, ""};

  cleanup:
    ResumeReading();
    switch (wr) {
    case WaitResult::Timeout:
      return {EC::OperationTimeout, "Terminal resize timed out"};
    case WaitResult::Interrupted:
      return {EC::Terminate, "Terminal resize interrupted"};
    case WaitResult::Error:
      return {EC::SocketRecvError, "Socket error during terminal resize"};
    default:
      return {EC::UnknownError, "Terminal resize failed"};
    }
  }

  ECM TerminalWrite(const std::string &msg,
                    int timeout_ms = -1, int64_t start_time = -1) override {
    std::lock_guard<std::recursive_mutex> lock(mtx);
    if (!terminal_channel || !terminal_channel->channel) {
      return {EC::NoConnection, "Terminal not initialized"};
    }

    amf flag = interrupt_flag ? interrupt_flag : this->terminal_interrupt_flag;
    start_time = start_time == -1 ? AMTime::miliseconds() : start_time;
    if (this->IsOperationInterrupted_(flag)) {
      return {EC::Terminate, "Terminal interrupted"};
    }

    libssh2_session_set_blocking(session, 0);
    size_t offset = 0;
    WaitResult wr = WaitResult::Ready;
    while (offset < msg.size()) {
      if (this->IsOperationInterrupted_(flag)) {
        wr = WaitResult::Interrupted;
        goto cleanup;
      }
      ssize_t rc =
          libssh2_channel_write(terminal_channel->channel, msg.data() + offset,
                                static_cast<int>(msg.size() - offset));
      if (rc > 0) {
        offset += static_cast<size_t>(rc);
        continue;
      }
      if (rc == LIBSSH2_ERROR_EAGAIN) {
        wr = wait_for_socket(SocketWaitType::Write, start_time, timeout_ms,
                             flag);
        if (wr != WaitResult::Ready) {
          goto cleanup;
        }
        continue;
      }
      return {GetLastEC(),
              AMStr::fmt("Terminal write failed: {}", GetLastErrorMsg())};
    }

    return {EC::Success, ""};

  cleanup:
    switch (wr) {
    case WaitResult::Timeout:
      return {EC::OperationTimeout, "Terminal write timed out"};
    case WaitResult::Interrupted:
      return {EC::Terminate, "Terminal interrupted"};
    case WaitResult::Error:
      return {EC::SocketRecvError, "Socket error during terminal write"};
    default:
      return {EC::UnknownError, "Terminal write failed"};
    }
  }

  ECM TerminalClose() override {
    StopReader();
    std::lock_guard<std::recursive_mutex> lock(mtx);
    if (!terminal_channel || !terminal_channel->channel) {
      return {EC::Success, ""};
    }
    libssh2_session_set_blocking(session, 1);
    terminal_channel->close();
    terminal_channel.reset();
    libssh2_session_set_blocking(session, 0);
    return {EC::Success, ""};
  }
};

class LocalTerminal : public AMBaseTerminal {
public:
  using TerminalOutputCallback = AMBaseTerminal::TerminalOutputCallback;

private:
  std::atomic<bool> paused{false};
  std::atomic<bool> closed{false};
  std::atomic<int> reader_wait_timeout_ms{200};
  TerminalOutputCallback terminal_output_cb = {};
  std::mutex terminal_cb_mtx;

#ifdef _WIN32
  static FILE *OpenPipe(const std::string &cmd) {
    return _popen(cmd.c_str(), "r");
  }
  static int ClosePipe(FILE *pipe) { return _pclose(pipe); }
#else
  static FILE *OpenPipe(const std::string &cmd) {
    return popen(cmd.c_str(), "r");
  }
  static int ClosePipe(FILE *pipe) { return pclose(pipe); }
#endif

public:
  ECM Connect(bool force = false,
              int timeout_ms = -1, int64_t start_time = -1) override {
    (void)force;
    (void)interrupt_flag;
    (void)timeout_ms;
    (void)start_time;
    closed.store(false, std::memory_order_relaxed);
    return {EC::Success, ""};
  }

  ECM Check(int timeout_ms = -1,
            int64_t start_time = -1) override {
    (void)timeout_ms;
    (void)start_time;
    if (this->IsOperationInterrupted_()) {
      return {EC::Terminate, "Check interrupted"};
    }
    if (closed.load(std::memory_order_relaxed)) {
      return {EC::NoConnection, "Terminal closed"};
    }
    return {EC::Success, ""};
  }

  void PauseReading() override {
    paused.store(true, std::memory_order_relaxed);
  }

  void ResumeReading() override {
    paused.store(false, std::memory_order_relaxed);
  }

  void
  SetTerminalOutputCallback(TerminalOutputCallback output_cb = {}) override {
    std::lock_guard<std::mutex> lock(terminal_cb_mtx);
    terminal_output_cb = std::move(output_cb);
  }

  ECM SetTerminalWindowInfo(const TerminalWindowInfo &window, int timeout_ms =
-1, int64_t start_time = -1) override { (void)window; (void)interrupt_flag;
    (void)timeout_ms;
    (void)start_time;
    return {EC::Success, ""};
  }

  void SetReaderWaitTimeoutMs(int timeout_ms) override {
    if (timeout_ms < 1) {
      timeout_ms = 1;
    }
    reader_wait_timeout_ms.store(timeout_ms, std::memory_order_relaxed);
  }

  ECM TerminalWrite(const std::string &msg,
                    int timeout_ms = -1, int64_t start_time = -1) override {
    if (closed.load(std::memory_order_relaxed)) {
      return {EC::NoConnection, "Terminal closed"};
    }
    if (msg.empty()) {
      return {EC::InvalidArg, "Empty command"};
    }

    std::string cmd = msg;
    while (!cmd.empty() && (cmd.back() == '\n' || cmd.back() == '\r')) {
      cmd.pop_back();
    }
    if (cmd.empty()) {
      return {EC::InvalidArg, "Empty command"};
    }

    if (timeout_ms <= 0) {
      timeout_ms = reader_wait_timeout_ms.load(std::memory_order_relaxed);
    }
    start_time = start_time == -1 ? AMTime::miliseconds() : start_time;

    if (this->IsOperationInterrupted_()) {
      return {EC::Terminate, "Terminal interrupted"};
    }

    FILE *pipe = OpenPipe(cmd);
    if (!pipe) {
      return {EC::LocalFileOpenError, "Local terminal pipe open failed"};
    }

    std::array<char, 4096> buffer;
    while (fgets(buffer.data(), static_cast<int>(buffer.size()), pipe)) {
      if (this->IsOperationInterrupted_()) {
        ClosePipe(pipe);
        return {EC::Terminate, "Terminal interrupted"};
      }
      if (timeout_ms > 0 && AMTime::miliseconds() - start_time >= timeout_ms) {
        ClosePipe(pipe);
        return {EC::OperationTimeout, "Terminal write timed out"};
      }

      if (!paused.load(std::memory_order_relaxed)) {
        TerminalOutputCallback cb;
        {
          std::lock_guard<std::mutex> lock(terminal_cb_mtx);
          cb = terminal_output_cb;
        }
        if (cb) {
          CallCallbackSafe(cb, std::string(buffer.data()));
        }
      }
    }

    int rc = ClosePipe(pipe);
    if (rc != 0) {
      return {EC::UnknownError, "Local command failed"};
    }
    return {EC::Success, ""};
  }

  ECM TerminalClose() override {
    closed.store(true, std::memory_order_relaxed);
    return {EC::Success, ""};
  }
};
*/

namespace {
// Socket wait direction
enum class SocketWaitType {
  Read,        // Wait for socket readable
  Write,       // Wait for socket writable
  ReadWrite,   // Wait for both readable and writable
  ReadOrWrite, // Wait for readable or writable, returns ReadReady/WriteReady
  Auto         // Determine from libssh2_session_block_directions
};

// Cross-platform socket connector
class SocketConnector {
public:
  SOCKET sock = INVALID_SOCKET;
  std::string error_msg = "";
  EC error_code = EC::Success;

  SocketConnector() = default;

  ~SocketConnector() {}

  /**
   * @brief Connect to the specified host with optional timeout and interrupt
   *        callback.
   *
   * @param hostname Target hostname or IP address.
   * @param port Target port.
   * @param timeout_ms Connection timeout in milliseconds; <=0 uses a default.
   * @param is_interrupted Optional callback to terminate connection flow.
   * @return True on successful connection, false otherwise. On failure,
   *         error_code and error_msg are updated.
   */
  bool Connect(const std::string &hostname, int port, int timeout_ms,
               std::function<bool()> is_interrupted = {}) {
    auto check_interrupted = [&]() {
      return static_cast<bool>(is_interrupted) && is_interrupted();
    };
    auto mark_interrupted = [&]() {
      error_code = EC::Terminate;
      error_msg = "Connection interrupted";
    };

    if (check_interrupted()) {
      mark_interrupted();
      return false;
    }

    // 1. DNS resolve - use AF_UNSPEC for IPv4/IPv6
    addrinfo hints{}, *result = nullptr;
    hints.ai_family = AF_UNSPEC; // support IPv4 and IPv6
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    int dns_err = getaddrinfo(hostname.c_str(), std::to_string(port).c_str(),
                              &hints, &result);
    if (dns_err != 0) {
#ifdef _WIN32
      const wchar_t *dns_err_w = gai_strerrorW(dns_err);
      auto dns_err_str =
          dns_err_w != nullptr ? AMStr::wstr(dns_err_w) : std::string{};
      error_msg = AMStr::fmt("DNS resolve failed: {} (hostname={})",
                             dns_err_str, hostname);
#else
      auto dns_err_str = gai_strerror(dns_err);
      error_msg = AMStr::fmt("DNS resolve failed: {} (hostname={})",
                             dns_err_str, hostname);
#endif
      error_code = EC::DNSResolveError;
      return false;
    }

    if (check_interrupted()) {
      mark_interrupted();
      freeaddrinfo(result);
      return false;
    }

    // 2. Try connecting all resolved addresses (IPv4/IPv6 dual-stack)
    addrinfo *rp = nullptr;
    for (rp = result; rp != nullptr; rp = rp->ai_next) {
      if (check_interrupted()) {
        mark_interrupted();
        freeaddrinfo(result);
        return false;
      }

      sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
      if (sock == INVALID_SOCKET) {
        continue; // Try next address
      }

      // 3. Set non-blocking mode
      if (!SetNonBlocking(true)) {
        closesocket(sock);
        sock = INVALID_SOCKET;
        continue;
      }

      if (check_interrupted()) {
        mark_interrupted();
        closesocket(sock);
        sock = INVALID_SOCKET;
        freeaddrinfo(result);
        return false;
      }

      // 4. Start connection
      int conn_result = connect(sock, rp->ai_addr, (int)rp->ai_addrlen);

#ifdef _WIN32
      bool in_progress =
          (conn_result == SOCKET_ERROR && WSAGetLastError() == WSAEWOULDBLOCK);
#else
      bool in_progress = (conn_result == -1 && errno == EINPROGRESS);
#endif

      if (conn_result == 0) {
        // Immediate success (can happen on local connection)
        if (check_interrupted()) {
          mark_interrupted();
          closesocket(sock);
          sock = INVALID_SOCKET;
          freeaddrinfo(result);
          return false;
        }
        SetNonBlocking(false);
        freeaddrinfo(result);
        return true;
      }

      if (!in_progress) {
        closesocket(sock);
        sock = INVALID_SOCKET;
        continue; // Try next address
      }

      // 5. Use select to wait for connection complete
      const int64_t total_timeout_ms = timeout_ms > 0 ? timeout_ms : 6000;
      const int64_t start_ms = AMTime::miliseconds();
      int64_t remaining_ms = total_timeout_ms;
      int select_result = 0;
      bool timed_out = false;

      while (remaining_ms > 0) {
        if (check_interrupted()) {
          mark_interrupted();
          closesocket(sock);
          sock = INVALID_SOCKET;
          freeaddrinfo(result);
          return false;
        }

        const int64_t wait_ms =
            remaining_ms > 100 ? static_cast<int64_t>(100) : remaining_ms;

        fd_set write_fds, error_fds;
        FD_ZERO(&write_fds);
        FD_ZERO(&error_fds);
        FD_SET(sock, &write_fds);
        FD_SET(sock, &error_fds);

        timeval timeout;
        timeout.tv_sec = static_cast<long>(wait_ms / 1000);
        timeout.tv_usec = static_cast<long>((wait_ms % 1000) * 1000);

        select_result =
            select((int)sock + 1, nullptr, &write_fds, &error_fds, &timeout);

        if (select_result > 0) {
          if (FD_ISSET(sock, &error_fds)) {
            select_result = -1;
          }
          break;
        }

        if (select_result < 0) {
          break;
        }

        remaining_ms = total_timeout_ms - (AMTime::miliseconds() - start_ms);
      }

      if (remaining_ms <= 0) {
        timed_out = true;
      }

      if (select_result <= 0 || timed_out) {
        closesocket(sock);
        sock = INVALID_SOCKET;
        continue; // Try next address
      }

      // 6. Check socket errors
      int sock_error = 0;
      socklen_t len = sizeof(sock_error);
      if (getsockopt(sock, SOL_SOCKET, SO_ERROR, (char *)&sock_error, &len) <
              0 ||
          sock_error != 0) {
        closesocket(sock);
        sock = INVALID_SOCKET;
        continue; // Try next address
      }

      // 7. Restore blocking mode, connection successful
      if (check_interrupted()) {
        mark_interrupted();
        closesocket(sock);
        sock = INVALID_SOCKET;
        freeaddrinfo(result);
        return false;
      }
      SetNonBlocking(false);
      freeaddrinfo(result);
      return true;
    }

    // All addresses failed
    freeaddrinfo(result);
    error_msg = "Socket connect failed for all addresses";
    error_code = EC::SocketConnectFailed;
    return false;
  }

private:
  bool SetNonBlocking(bool non_blocking) {
#ifdef _WIN32
    u_long mode = non_blocking ? 1 : 0;
    if (ioctlsocket(sock, FIONBIO, &mode) != 0) {
      error_msg = "Failed to set socket non-blocking mode";
      error_code = EC::SocketCreateError;
      return false;
    }
#else
    int flags = fcntl(sock, F_GETFL, 0);
    if (flags < 0) {
      error_msg = "Failed to get socket flags";
      error_code = EC::SocketCreateError;
      return false;
    }
    flags = non_blocking ? (flags | O_NONBLOCK) : (flags & ~O_NONBLOCK);
    if (fcntl(sock, F_SETFL, flags) < 0) {
      error_msg = "Failed to set socket non-blocking mode";
      error_code = EC::SocketCreateError;
      return false;
    }
#endif
    return true;
  }
};

struct TerminalWindowInfo {
  int cols = 80;
  int rows = 24;
  int width = 0;
  int height = 0;
  std::string term = "xterm-256color";
};

#ifdef _WIN32
inline static std::atomic<bool> is_wsa_initialized(false);
inline void cleanup_wsa() {
  // Cleanup WSA if initialized
  if (is_wsa_initialized.load(std::memory_order_relaxed)) {
    WSACleanup();
    is_wsa_initialized.store(false, std::memory_order_relaxed);
  }
}
inline void AMInitWSA() {
  if (is_wsa_initialized.load(std::memory_order_relaxed)) {
    return;
  }
  WSADATA wsaData;
  int result = WSAStartup(MAKEWORD(2, 2), &wsaData);
  if (result != 0) {
    throw std::runtime_error("WSAStartup failed");
  }
  is_wsa_initialized.store(true, std::memory_order_relaxed);
  std::atexit(cleanup_wsa);
}
#endif

inline std::string GetLibssh2Version() {
  return libssh2_version(LIBSSH2_VERSION_NUM);
}

inline std::string SSHCodeToString(int code) {
  static const std::unordered_map<int, std::string> SFTPMessage = {
      {LIBSSH2_FX_EOF, "End of file"},
      {LIBSSH2_FX_NO_SUCH_FILE, "File does not exist"},
      {LIBSSH2_FX_PERMISSION_DENIED, "Permission denied"},
      {LIBSSH2_FX_FAILURE, "Generic failure"},
      {LIBSSH2_FX_BAD_MESSAGE, "Bad message format"},
      {LIBSSH2_FX_NO_CONNECTION, "No connection exists"},
      {LIBSSH2_FX_CONNECTION_LOST, "Connection lost"},
      {LIBSSH2_FX_OP_UNSUPPORTED, "Operation not supported"},
      {LIBSSH2_FX_INVALID_HANDLE, "Invalid handle"},
      {LIBSSH2_FX_NO_SUCH_PATH, "No such path"},
      {LIBSSH2_FX_FILE_ALREADY_EXISTS, "File already exists"},
      {LIBSSH2_FX_WRITE_PROTECT, "Target is write protected"},
      {LIBSSH2_FX_NO_MEDIA, "Target Storage Media is not available"},
      {LIBSSH2_FX_NO_SPACE_ON_FILESYSTEM, "No space on filesystem"},
      {LIBSSH2_FX_QUOTA_EXCEEDED, "Space quota exceeded"},
      {LIBSSH2_FX_UNKNOWN_PRINCIPAL, "User not found in host"},
      {LIBSSH2_FX_LOCK_CONFLICT, "Path is locked by another process"},
      {LIBSSH2_FX_DIR_NOT_EMPTY, "Directory is not empty"},
      {LIBSSH2_FX_NOT_A_DIRECTORY, "Target is not a directory"},
      {LIBSSH2_FX_INVALID_FILENAME, "Filename is invalid"},
      {LIBSSH2_FX_LINK_LOOP, "Symbolic link loop"}};
  auto it = SFTPMessage.find(code);
  if (it != SFTPMessage.end()) {
    return it->second;
  }
  return "Unknown error code: " + std::to_string(code);
}

inline EC IntToEC(int code) {
  static const std::unordered_map<int, ErrorCode> Int2EC = [] {
    std::unordered_map<int, ErrorCode> map;
    for (auto [val, name] : magic_enum::enum_entries<ErrorCode>()) {
      map[static_cast<int>(val)] = val;
    }
    return map;
  }();
  auto it = Int2EC.find(code);
  if (it != Int2EC.end()) {
    return it->second;
  } else {
    return EC::UnknownError;
  }
}

inline bool IsValidKey(const std::string &key) {
  std::ifstream file(key);
  if (!file.is_open())
    return false;

  std::string line;
  std::getline(file, line);

  // Match standard header markers of all SSH private keys
  static const std::vector<std::string> private_key_headers = {
      "-----BEGIN OPENSSH PRIVATE KEY-----", "-----BEGIN RSA PRIVATE KEY-----",
      "-----BEGIN EC PRIVATE KEY-----", "-----BEGIN DSA PRIVATE KEY-----"};
  for (const auto &header : private_key_headers) {
    if (line.find(header) == 0) { // Prefix match
      return true;
    }
  }
  return false;
}
inline bool isdir(const LIBSSH2_SFTP_ATTRIBUTES &attrs) {
  return (attrs.flags & LIBSSH2_SFTP_ATTR_PERMISSIONS) &&
         (attrs.permissions & LIBSSH2_SFTP_S_IFDIR);
}
inline bool isreg(const LIBSSH2_SFTP_ATTRIBUTES &attrs) {
  return (attrs.flags & LIBSSH2_SFTP_ATTR_PERMISSIONS) &&
         (attrs.permissions & LIBSSH2_SFTP_S_IFREG);
}

using AuthCallback =
    std::function<std::optional<std::string>(const AuthCBInfo &)>;
using TraceLevel = AMDomain::client::TraceLevel;
using KnownHostQuery = AMDomain::host::KnownHostQuery;
using KnownHostCallback = AMDomain::client::KnownHostCallback;

inline bool IsWouldBlockSocketError_() {
#ifdef _WIN32
  return WSAGetLastError() == WSAEWOULDBLOCK;
#else
  return errno == EWOULDBLOCK || errno == EAGAIN;
#endif
}

inline void CloseSocketSafe_(SOCKET &fd) {
  if (fd == INVALID_SOCKET) {
    return;
  }
  closesocket(fd);
  fd = INVALID_SOCKET;
}

inline bool SetSocketNonBlocking_(SOCKET fd) {
#ifdef _WIN32
  u_long mode = 1;
  return ioctlsocket(fd, FIONBIO, &mode) == 0;
#else
  int flags = fcntl(fd, F_GETFL, 0);
  if (flags < 0) {
    return false;
  }
  return fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0;
#endif
}

class InterruptWakeBridge {
public:
  enum class Backend { None, SocketPair, Pipe, EventFd };

  bool Ensure() {
    std::lock_guard<std::mutex> lock(mtx_);
    if (read_sock_ != INVALID_SOCKET && write_sock_ != INVALID_SOCKET) {
      return true;
    }
    CloseUnlocked_();
    return CreateUnlocked_();
  }

  [[nodiscard]] SOCKET ReadSocket() const {
    std::lock_guard<std::mutex> lock(mtx_);
    return read_sock_;
  }

  void Close() {
    std::lock_guard<std::mutex> lock(mtx_);
    CloseUnlocked_();
  }

  void Signal() {
    SOCKET wake_sock = INVALID_SOCKET;
    Backend backend = Backend::None;
    {
      std::lock_guard<std::mutex> lock(mtx_);
      wake_sock = write_sock_;
      backend = backend_;
    }
    if (wake_sock == INVALID_SOCKET) {
      return;
    }

#ifdef _WIN32
    const char c = 1;
    int rc = send(wake_sock, &c, 1, 0);
    if (rc == SOCKET_ERROR && !IsWouldBlockSocketError_()) {
      return;
    }
#else
    if (backend == Backend::EventFd) {
      uint64_t one = 1;
      ssize_t rc = ::write(wake_sock, &one, sizeof(one));
      if (rc < 0 && !IsWouldBlockSocketError_()) {
        return;
      }
      return;
    }
    const char c = 1;
    ssize_t rc = ::write(wake_sock, &c, 1);
    if (rc < 0 && !IsWouldBlockSocketError_()) {
      return;
    }
#endif
  }

  void Drain() {
    SOCKET wake_sock = INVALID_SOCKET;
    Backend backend = Backend::None;
    {
      std::lock_guard<std::mutex> lock(mtx_);
      wake_sock = read_sock_;
      backend = backend_;
    }
    if (wake_sock == INVALID_SOCKET) {
      return;
    }

#ifdef _WIN32
    char buffer[64];
    while (true) {
      int rc = recv(wake_sock, buffer, sizeof(buffer), 0);
      if (rc > 0) {
        if (rc < static_cast<int>(sizeof(buffer))) {
          return;
        }
        continue;
      }
      if (rc == 0) {
        return;
      }
      if (rc == SOCKET_ERROR && IsWouldBlockSocketError_()) {
        return;
      }
      return;
    }
#else
    if (backend == Backend::EventFd) {
      uint64_t value = 0;
      while (true) {
        ssize_t rc = ::read(wake_sock, &value, sizeof(value));
        if (rc == static_cast<ssize_t>(sizeof(value))) {
          continue;
        }
        if (rc < 0 && IsWouldBlockSocketError_()) {
          return;
        }
        return;
      }
    }
    char buffer[64];
    while (true) {
      ssize_t rc = ::read(wake_sock, buffer, sizeof(buffer));
      if (rc > 0) {
        if (rc < static_cast<ssize_t>(sizeof(buffer))) {
          return;
        }
        continue;
      }
      if (rc == 0) {
        return;
      }
      if (rc < 0 && IsWouldBlockSocketError_()) {
        return;
      }
      return;
    }
#endif
  }

private:
  bool CreateUnlocked_() {
    SOCKET read_sock = INVALID_SOCKET;
    SOCKET write_sock = INVALID_SOCKET;
    Backend backend = Backend::None;
#ifdef _WIN32
    SOCKET listen_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listen_sock == INVALID_SOCKET) {
      return false;
    }

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;

    if (bind(listen_sock, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) ==
        SOCKET_ERROR) {
      CloseSocketSafe_(listen_sock);
      return false;
    }
    if (listen(listen_sock, 1) == SOCKET_ERROR) {
      CloseSocketSafe_(listen_sock);
      return false;
    }

    int addr_len = sizeof(addr);
    if (getsockname(listen_sock, reinterpret_cast<sockaddr *>(&addr),
                    &addr_len) == SOCKET_ERROR) {
      CloseSocketSafe_(listen_sock);
      return false;
    }

    write_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (write_sock == INVALID_SOCKET) {
      CloseSocketSafe_(listen_sock);
      return false;
    }
    if (connect(write_sock, reinterpret_cast<sockaddr *>(&addr),
                sizeof(addr)) == SOCKET_ERROR) {
      CloseSocketSafe_(listen_sock);
      CloseSocketSafe_(write_sock);
      return false;
    }

    read_sock = accept(listen_sock, nullptr, nullptr);
    CloseSocketSafe_(listen_sock);
    if (read_sock == INVALID_SOCKET) {
      CloseSocketSafe_(write_sock);
      return false;
    }
    backend = Backend::SocketPair;
#else
#ifdef __linux__
    int efd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    if (efd >= 0) {
      read_sock = static_cast<SOCKET>(efd);
      write_sock = static_cast<SOCKET>(efd);
      backend = Backend::EventFd;
    }
#endif
    if (backend == Backend::None) {
      int pfd[2] = {-1, -1};
      if (::pipe(pfd) != 0) {
        return false;
      }
      read_sock = static_cast<SOCKET>(pfd[0]);
      write_sock = static_cast<SOCKET>(pfd[1]);
      backend = Backend::Pipe;
    }
#endif

    if (!SetSocketNonBlocking_(read_sock) ||
        !SetSocketNonBlocking_(write_sock)) {
      CloseSocketSafe_(read_sock);
      if (write_sock != read_sock) {
        CloseSocketSafe_(write_sock);
      }
      return false;
    }

    read_sock_ = read_sock;
    write_sock_ = write_sock;
    backend_ = backend;
    return true;
  }

  void CloseUnlocked_() {
    if (backend_ == Backend::EventFd && read_sock_ != INVALID_SOCKET) {
      CloseSocketSafe_(read_sock_);
      write_sock_ = INVALID_SOCKET;
      backend_ = Backend::None;
      return;
    }
    CloseSocketSafe_(read_sock_);
    CloseSocketSafe_(write_sock_);
    backend_ = Backend::None;
  }

  mutable std::mutex mtx_;
  SOCKET read_sock_ = INVALID_SOCKET;
  SOCKET write_sock_ = INVALID_SOCKET;
  Backend backend_ = Backend::None;
};

inline std::string Base64Encode(const unsigned char *data, size_t len) {
  static const char kBase64Alphabet[] =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  if (!data || len == 0) {
    return "";
  }
  std::string out;
  out.reserve(((len + 2) / 3) * 4);
  for (size_t i = 0; i < len; i += 3) {
    uint32_t chunk = static_cast<uint32_t>(data[i]) << 16;
    const size_t remain = len - i;
    if (remain > 1) {
      chunk |= static_cast<uint32_t>(data[i + 1]) << 8;
    }
    if (remain > 2) {
      chunk |= static_cast<uint32_t>(data[i + 2]);
    }
    out.push_back(kBase64Alphabet[(chunk >> 18) & 0x3F]);
    out.push_back(kBase64Alphabet[(chunk >> 12) & 0x3F]);
    out.push_back(remain > 1 ? kBase64Alphabet[(chunk >> 6) & 0x3F] : '=');
    out.push_back(remain > 2 ? kBase64Alphabet[chunk & 0x3F] : '=');
  }
  return out;
}

inline std::string HostKeyTypeToProtocol(int type) {
  switch (type) {
  case LIBSSH2_HOSTKEY_TYPE_RSA:
    return "ssh-rsa";
  case LIBSSH2_HOSTKEY_TYPE_DSS:
    return "ssh-dss";
  case LIBSSH2_HOSTKEY_TYPE_ECDSA_256:
    return "ecdsa-sha2-nistp256";
  case LIBSSH2_HOSTKEY_TYPE_ECDSA_384:
    return "ecdsa-sha2-nistp384";
  case LIBSSH2_HOSTKEY_TYPE_ECDSA_521:
    return "ecdsa-sha2-nistp521";
  case LIBSSH2_HOSTKEY_TYPE_ED25519:
    return "ssh-ed25519";
  default:
    return "";
  }
}
} // namespace

class SafeChannel {
public:
  LIBSSH2_CHANNEL *channel = nullptr;
  bool closed = false; // Mark whether it has been closed normally
  bool is_init = false;
  std::function<bool()> init_is_interrupted_cb;
  int64_t init_start_time = -1;
  int init_timeout_ms = -1;

private:
  /**
   * @brief Persist initialization context used by retryable operations.
   */
  void StoreInitContext_(std::function<bool()> is_interrupted_cb,
                         int timeout_ms, int64_t start_time) {
    init_is_interrupted_cb = std::move(is_interrupted_cb);
    init_timeout_ms = timeout_ms;
    init_start_time = start_time == -1 ? AMTime::miliseconds() : start_time;
  }

  /**
   * @brief Check interruption/timeout state for retry operations.
   */
  ECM CheckControlState_(const std::string &action) const {
    if (init_is_interrupted_cb && init_is_interrupted_cb()) {
      return {EC::Terminate, AMStr::fmt("{} interrupted", action)};
    }
    if (init_timeout_ms >= 0 && init_start_time >= 0 &&
        (AMTime::miliseconds() - init_start_time) >= init_timeout_ms) {
      return {EC::OperationTimeout, AMStr::fmt("{} timed out", action)};
    }
    return {EC::Success, ""};
  }

public:
  ~SafeChannel() {
    if (channel) {
      if (!closed) {
        // Best-effort graceful stop before releasing the channel handle.
        (void)graceful_exit(true, 50, true);
      }
      libssh2_channel_free(channel);
      channel = nullptr;
    }
    is_init = false;
  }

  // Close channel normally (blocking mode)
  // Return true on success, false on failure
  bool close() {
    if (!channel || closed) {
      is_init = false;
      return closed;
    }
    if (libssh2_channel_close(channel) == 0 &&
        libssh2_channel_wait_closed(channel) == 0) {
      closed = true;
      is_init = false;
    }
    return closed;
  }

  // Send exit signal (do not wait for close)
  void request_exit() {
    if (!channel) {
      return;
    }
    libssh2_channel_send_eof(channel);
    libssh2_channel_signal(channel, "TERM");
  }

  // Non-blocking close; use with wait_for_socket
  // Return values: 0=success, EAGAIN=wait required, <0=error
  int close_nonblock() {
    if (!channel)
      return -1;
    if (closed)
      return 0;

    int rc = libssh2_channel_close(channel);
    if (rc == 0) {
      rc = libssh2_channel_wait_closed(channel);
      if (rc == 0) {
        closed = true;
        is_init = false;
      }
    }
    return rc;
  }

  SafeChannel() = default;

  /**
   * @brief Construct with an existing channel and operation context.
   */
  explicit SafeChannel(LIBSSH2_CHANNEL *existing_channel,
                       std::function<bool()> is_interrupted_cb = {},
                       int timeout_ms = -1, int64_t start_time = -1) {
    channel = existing_channel;
    closed = false;
    is_init = existing_channel != nullptr;
    StoreInitContext_(std::move(is_interrupted_cb), timeout_ms, start_time);
  }

  /**
   * @brief Initialize SSH channel with retry support in non-blocking sessions.
   *
   * @param session Active libssh2 session.
   * @param is_interrupted_cb Optional interruption callback.
   * @param timeout_ms Timeout in milliseconds; negative waits forever.
   * @param start_time Start timestamp for timeout budget; -1 uses now.
   * @return ECM status describing initialization result.
   */
  ECM Init(LIBSSH2_SESSION *session,
           std::function<bool()> is_interrupted_cb = {}, int timeout_ms = -1,
           int64_t start_time = -1) {
    StoreInitContext_(std::move(is_interrupted_cb), timeout_ms, start_time);
    if (!session) {
      is_init = false;
      return {EC::NoSession, "Session is null"};
    }
    if (channel) {
      if (!closed) {
        (void)graceful_exit(true, 50, true);
      }
      libssh2_channel_free(channel);
      channel = nullptr;
      closed = false;
      is_init = false;
    }

    while (true) {
      ECM control_retry = CheckControlState_("Channel init");
      if (control_retry.first != EC::Success) {
        is_init = false;
        return control_retry;
      }

      channel =
          libssh2_channel_open_ex(session, "session", sizeof("session") - 1,
                                  4 * AMMB, 32 * AMKB, nullptr, 0);
      if (channel) {
        closed = false;
        is_init = true;
        return {EC::Success, ""};
      }

      const int err = libssh2_session_last_errno(session);
      if (err != LIBSSH2_ERROR_EAGAIN) {
        is_init = false;
        return {EC::NoConnection,
                AMStr::fmt("Channel init failed with libssh2 error {}", err)};
      }
      ECM control = CheckControlState_("Channel init");
      if (control.first != EC::Success) {
        is_init = false;
        return control;
      }
      std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
  }

  /**
   * @brief Gracefully terminate a running channel and close it.
   *
   * @param send_exit Whether to send EOF/TERM before closing.
   * @param term_wait_ms Delay after TERM signal before close attempts.
   * @param force_kill Whether to send KILL if close fails after TERM.
   * @return ECM status describing exit result.
   */
  ECM graceful_exit(bool send_exit = true, int term_wait_ms = 50,
                    bool force_kill = true) {
    if (!channel || closed) {
      is_init = false;
      return {EC::Success, ""};
    }

    auto run_nonblocking_op = [&](auto &&op, const std::string &action) -> ECM {
      while (true) {
        const int rc = op();
        if (rc == 0) {
          return {EC::Success, ""};
        }
        if (rc != LIBSSH2_ERROR_EAGAIN) {
          return {EC::NoConnection,
                  AMStr::fmt("{} failed with libssh2 error {}", action, rc)};
        }
        ECM control = CheckControlState_(action);
        if (control.first != EC::Success) {
          return control;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
      }
    };

    if (send_exit) {
      ECM eof_rcm = run_nonblocking_op(
          [this]() { return libssh2_channel_send_eof(channel); },
          "channel send eof");
      if (eof_rcm.first != EC::Success && eof_rcm.first != EC::Terminate &&
          eof_rcm.first != EC::OperationTimeout) {
        return eof_rcm;
      }

      ECM term_rcm = run_nonblocking_op(
          [this]() { return libssh2_channel_signal(channel, "TERM"); },
          "channel signal TERM");
      if (term_rcm.first != EC::Success && term_rcm.first != EC::Terminate &&
          term_rcm.first != EC::OperationTimeout) {
        return term_rcm;
      }

      if (term_wait_ms > 0) {
        std::this_thread::sleep_for(std::chrono::milliseconds(term_wait_ms));
      }
    }

    ECM close_rcm = run_nonblocking_op([this]() { return close_nonblock(); },
                                       "channel close");
    if (close_rcm.first == EC::Success) {
      return close_rcm;
    }

    if (force_kill && send_exit && channel && !closed) {
      (void)run_nonblocking_op(
          [this]() { return libssh2_channel_signal(channel, "KILL"); },
          "channel signal KILL");
      close_rcm = run_nonblocking_op([this]() { return close_nonblock(); },
                                     "channel close");
    }
    return close_rcm;
  }
};

class SFTPSessionBase : public ClientIOBase {
protected:
  AMAtomic<ConRequest> &request_atomic_;
  AMAtomic<AMDomain::client::ClientState> &state_atomic_;
  mutable std::recursive_mutex mtx;
  InterruptWakeBridge interrupt_wake_;
  SOCKET sock = INVALID_SOCKET;

  [[nodiscard]] bool
  IsOperationInterrupted_(const amf &interrupt_flag = nullptr) const {
    return this->IsOperationInterruptedByToken_(interrupt_flag);
  }

  size_t RegisterInterruptWakeup_(std::function<void()> wake_cb) {
    if (!wake_cb || !control_part_) {
      return 0;
    }
    return control_part_->RegisterWakeup(std::move(wake_cb));
  }

  size_t RegisterInterruptWakeup_(const amf &interrupt_flag,
                                  std::function<void()> wake_cb) {
    if (!wake_cb) {
      return 0;
    }
    if (interrupt_flag) {
      return this->RegisterTokenWakeupBridge_(interrupt_flag, std::move(wake_cb));
    }
    return RegisterInterruptWakeup_(std::move(wake_cb));
  }

  void UnregisterInterruptWakeup_(size_t token) {
    if (token == 0 || !control_part_) {
      return;
    }
    control_part_->UnregisterWakeup(token);
  }

  void UnregisterInterruptWakeup_(const amf &interrupt_flag, size_t token) {
    if (token == 0) {
      return;
    }
    if (interrupt_flag) {
      this->UnregisterTokenWakeupBridge_(interrupt_flag, token);
      return;
    }
    UnregisterInterruptWakeup_(token);
  }

  void trace(TraceLevel level, EC error_code, const std::string &target = "",
             const std::string &action = "",
             const std::string &msg = "") const {
    ClientIOBase::trace(TraceInfo(
        level, error_code, config_part_->GetNickname(), target, action, msg,
        config_part_->GetRequest(), AMDomain::client::TraceSource::Client));
  }

  void SetState(const AMDomain::client::ClientState &state) {
    state_atomic_.lock().store(state);
  }

  [[nodiscard]] AMDomain::client::ClientState GetState() const {
    return state_atomic_.lock().load();
  }

  [[nodiscard]] OS_TYPE GetCachedOSType_() const {
    return config_part_ ? config_part_->GetOSType() : OS_TYPE::Uncertain;
  }

  void SetCachedOSType_(OS_TYPE os_type) {
    if (config_part_) {
      config_part_->SetOSType(os_type);
    }
  }

  [[nodiscard]] std::string GetCachedHomeDir_() const {
    return config_part_ ? config_part_->GetHomeDir() : std::string{};
  }

  void SetCachedHomeDir_(const std::string &home_dir) {
    if (config_part_) {
      config_part_->SetHomeDir(home_dir);
    }
  }

  bool EnsureInterruptWakeSocketPair_() { return interrupt_wake_.Ensure(); }

  [[nodiscard]] SOCKET GetInterruptWakeReadSocket_() const {
    return interrupt_wake_.ReadSocket();
  }

  void CloseInterruptWakeSocketPair_() { interrupt_wake_.Close(); }

  void SignalInterruptWakeSocket_() { interrupt_wake_.Signal(); }

  void DrainInterruptWakeSocket_() { interrupt_wake_.Drain(); }

  ECM ErrorRecord(int code, TraceLevel level, const std::string &taregt,
                  const std::string &action, std::string prompt = "") {
    if (code >= 0) {
      return {EC::Success, ""};
    }
    auto ec = GetLastEC();
    auto msg = GetLastErrorMsg();
    if (prompt.empty()) {
      prompt = action + " on " + taregt + " error:" + msg;
    } else {
      AMStr::vreplace(prompt, "{action}", action);
      AMStr::vreplace(prompt, "{target}", taregt);
      AMStr::vreplace(prompt, "{error}", msg);
    }
    trace(level, ec, taregt, action, prompt);
    return {ec, prompt};
  }

  template <typename T>
  ECM ErrorRecord(const NBResult<T> &result, TraceLevel level,
                  const std::string &target, const std::string &action,
                  std::string prompt = "") {
    // 1. Timeout
    if (result.is_timeout()) {
      std::string msg = AMStr::fmt("{} on {} timeout", action, target);
      trace(level, EC::OperationTimeout, target, action, msg);
      return {EC::OperationTimeout, msg};
    }

    // 2. Terminate
    if (result.is_interrupted()) {
      std::string msg =
          AMStr::fmt("{} on {} interrupted by user", action, target);
      trace(level, EC::Terminate, target, action, msg);
      return {EC::Terminate, msg};
    }

    // 3. Socket error
    if (result.is_error()) {
      std::string msg = AMStr::fmt("Encountered socket error during {} on {}",
                                   action, target);
      trace(level, EC::SocketRecvError, target, action, msg);
      return {EC::SocketRecvError, msg};
    }

    // 4 & 5. Execution finished - check return value for errors
    // For int/ssize_t: <0 means failure (while LIBSSH2 uses 0 as success)
    // For pointers: nullptr means failure
    if constexpr (std::is_same_v<T, int> || std::is_same_v<T, ssize_t>) {
      if (result.value < 0) {
        // Execution finished but failed
        auto ec = GetLastEC();
        auto errmsg = GetLastErrorMsg();
        std::string msg = prompt.empty() ? AMStr::fmt("{} on {} error: {}",
                                                      action, target, errmsg)
                                         : prompt;
        AMStr::vreplace(msg, "{action}", action);
        AMStr::vreplace(msg, "{target}", target);
        AMStr::vreplace(msg, "{error}", errmsg);
        trace(level, ec, target, action, msg);
        return {ec, msg};
      }
    } else if constexpr (std::is_pointer_v<T>) {
      if (result.value == nullptr) {
        auto ec = GetLastEC();
        auto errmsg = GetLastErrorMsg();
        std::string msg = prompt.empty() ? AMStr::fmt("{} on {} error: {}",
                                                      action, target, errmsg)
                                         : prompt;
        AMStr::vreplace(msg, "{action}", action);
        AMStr::vreplace(msg, "{target}", target);
        AMStr::vreplace(msg, "{error}", errmsg);
        trace(level, ec, target, action, msg);
        return {ec, msg};
      }
    }

    // 5. Success
    return {EC::Success, ""};
  }

private:
  bool password_auth_cb = false;
  std::vector<std::string> private_keys = {};
  AuthCallback auth_cb = {}; // optional<string>(AuthCBInfo)

  /**
   * @brief Verify the remote host key using an external callback when set.
   */
  ECM VerifyKnownHostFingerprint(const ConRequest &request) {
    auto known_host_cb = known_host_callback_.lock().load();
    if (!known_host_cb) {
      return {EC::Success, ""};
    }

    size_t key_len = 0;
    int key_type = LIBSSH2_HOSTKEY_TYPE_UNKNOWN;
    const char *key_ptr = libssh2_session_hostkey(session, &key_len, &key_type);
    if (!key_ptr || key_len == 0) {
      return {EC::HostkeyInitFailed, "Failed to read host key from session"};
    }

    const std::string actual_protocol = HostKeyTypeToProtocol(key_type);
    if (actual_protocol.empty()) {
      return {EC::AlgorithmUnsupported, "Unsupported host key algorithm"};
    }

    auto *key_bytes = reinterpret_cast<const unsigned char *>(key_ptr);

    std::array<unsigned char, SHA256_DIGEST_LENGTH> digest;
    std::string actual_sha = "";
    if (SHA256(key_bytes, key_len, digest.data())) {
      actual_sha = Base64Encode(digest.data(), SHA256_DIGEST_LENGTH);
    }

    KnownHostQuery entry{request.nickname, request.hostname, (int)request.port,
                         actual_protocol,  request.username, actual_sha};
    return known_host(entry);
  }

  void LoadDefaultPrivateKeys() {
    trace(TraceLevel::Debug, EC::Success, "~/.ssh", "LoadDefaultPrivateKeys",
          "Shared private keys not provided, loading default private keys from "
          "~/.ssh");
    auto [error, listd] = AMFS::listdir(AMFS::abspath("~/.ssh"));
    for (auto &info : listd) {
      if (info.type == PathType::FILE) {
        if (IsValidKey(info.path)) {
          this->private_keys.push_back(info.path);
        }
      }
    }
  }

  void Disconnect() {
    std::lock_guard<std::recursive_mutex> lock(mtx);
    CloseInterruptWakeSocketPair_();
    if (sftp) {
      libssh2_sftp_shutdown(sftp);
      sftp = nullptr;
    }
    if (session) {
      libssh2_session_disconnect(session, "Normal Shutdown");
      libssh2_session_free(session);
      session = nullptr;
    }
    if (sock != INVALID_SOCKET) {
#ifdef _WIN32
      closesocket(sock);
#else
      close(sock);
#endif
      sock = INVALID_SOCKET;
    }
    state_atomic_.lock().store(
        {AMDomain::client::ClientStatus::NoConnection,
         {EC::NoConnection, "Connection not established"}});
  }

public:
  LIBSSH2_SESSION *session = nullptr;
  LIBSSH2_SFTP *sftp = nullptr;
  ~SFTPSessionBase() override { Disconnect(); }

  /**
   * @brief Expose the transfer serialization mutex for runtime transfer
   * execution helpers.
   */
  std::recursive_mutex &TransferMutex() { return mtx; }

  /**
   * @brief Expose the transfer serialization mutex for const runtime helpers.
   */
  const std::recursive_mutex &TransferMutex() const { return mtx; }

  SFTPSessionBase(AMDomain::client::IClientConfigPort *config_port,
                  AMDomain::client::IClientTaskControlPort *control_port,
                  const std::vector<std::string> &private_keys,
                  TraceCallback trace_cb = {}, AuthCallback auth_cb = {},
                  AMDomain::client::KnownHostCallback known_host_cb = {})
      : ClientIOBase(config_port, control_port),
        request_atomic_((config_port != nullptr)
                            ? config_port->RequestAtomic()
                            : throw std::invalid_argument(
                                  "SFTPSessionBase requires non-null config "
                                  "port")),
        state_atomic_((config_port != nullptr)
                          ? config_port->StateAtomic()
                          : throw std::invalid_argument(
                                "SFTPSessionBase requires non-null config "
                                "port")),
        private_keys(private_keys), auth_cb(std::move(auth_cb)) {
    if (control_port == nullptr) {
      throw std::invalid_argument(
          "SFTPSessionBase requires non-null task control port");
    }
    RegisterTraceCallback(std::move(trace_cb));
    RegisterAuthCallback(this->auth_cb);
    RegisterKnownHostCallback(std::move(known_host_cb));
    if (this->auth_cb) {
      this->password_auth_cb = true;
    }
    if (private_keys.empty()) {
      LoadDefaultPrivateKeys();
    }
  }

  ssize_t TransferRingBufferSize(ssize_t buffer_size = -1) {
    if (buffer_size <= 0) {
      return request_atomic_.lock()->buffer_size;
    }
    auto req = request_atomic_.lock();
    req->buffer_size = buffer_size;
    return req->buffer_size;
  }

  void RequestInterrupt() {
    if (control_part_) {
      control_part_->RequestInterrupt();
    }
  }

  void ClearInterrupt() {
    if (control_part_) {
      control_part_->ClearInterrupt();
    }
  }

  template <typename Func>
  auto nb_call(int64_t timeout_ms, int64_t start_time, Func &&func,
               amf interrupt_flag = nullptr)
      -> NBResult<decltype(func())> {
    using RetType = decltype(func());
    start_time = start_time == -1 ? AMTime::miliseconds() : start_time;

    RetType rc;
    while (true) {
      rc = func();

      bool should_retry = false;
      if constexpr (std::is_same_v<RetType, int> ||
                    std::is_same_v<RetType, ssize_t>) {
        should_retry = (rc == LIBSSH2_ERROR_EAGAIN);
      } else if constexpr (std::is_pointer_v<RetType>) {
        should_retry =
            (rc == nullptr && session != nullptr &&
             libssh2_session_last_errno(session) == LIBSSH2_ERROR_EAGAIN);
      }

      if (!should_retry) {
        return {rc, WaitResult::Ready};
      }

      WaitResult wr = wait_for_socket(SocketWaitType::Auto, start_time,
                                      timeout_ms, interrupt_flag);
      if (wr != WaitResult::Ready) {
        return {rc, wr};
      }
    }
  }

  inline WaitResult wait_for_socket(SocketWaitType wait_dir,
                                    int64_t start_time = -1,
                                    int64_t timeout_ms = -1,
                                    amf interrupt_flag = nullptr) {
    if (!session || sock == INVALID_SOCKET) {
      return WaitResult::Error;
    }

    auto is_interrupted = [&]() -> bool {
      return this->IsOperationInterrupted_(interrupt_flag);
    };

    if (is_interrupted()) {
      return WaitResult::Interrupted;
    }
    if (timeout_ms > 0) {
      start_time = start_time == -1 ? AMTime::miliseconds() : start_time;
      if (AMTime::miliseconds() - start_time >= timeout_ms) {
        return WaitResult::Timeout;
      }
    }

    if (wait_dir == SocketWaitType::Auto &&
        libssh2_session_block_directions(session) == 0) {
      return WaitResult::Ready;
    }

    bool wait_read = false;
    bool wait_write = false;
    const bool is_auto = (wait_dir == SocketWaitType::Auto);
    const bool is_read_or_write = (wait_dir == SocketWaitType::ReadOrWrite);

    if (!is_auto) {
      switch (wait_dir) {
      case SocketWaitType::Read:
        wait_read = true;
        break;
      case SocketWaitType::Write:
        wait_write = true;
        break;
      case SocketWaitType::ReadWrite:
      case SocketWaitType::ReadOrWrite:
        wait_read = true;
        wait_write = true;
        break;
      default:
        break;
      }
    }

    fd_set readfds;
    fd_set writefds;
    FD_ZERO(&readfds);
    FD_ZERO(&writefds);

    if (is_auto) {
      const int dir = libssh2_session_block_directions(session);
      if (dir == 0) {
        return WaitResult::Ready;
      }
      if (dir & LIBSSH2_SESSION_BLOCK_INBOUND) {
        FD_SET(sock, &readfds);
      }
      if (dir & LIBSSH2_SESSION_BLOCK_OUTBOUND) {
        FD_SET(sock, &writefds);
      }
    } else {
      if (wait_read) {
        FD_SET(sock, &readfds);
      }
      if (wait_write) {
        FD_SET(sock, &writefds);
      }
    }

    size_t wake_token = 0;
    auto cleanup_wakeup = [&]() {
      if (wake_token != 0) {
        this->UnregisterInterruptWakeup_(interrupt_flag, wake_token);
        wake_token = 0;
      }
    };

    SOCKET wake_read_sock = INVALID_SOCKET;
    if (EnsureInterruptWakeSocketPair_()) {
      DrainInterruptWakeSocket_();
      wake_read_sock = GetInterruptWakeReadSocket_();
      if (wake_read_sock != INVALID_SOCKET) {
        wake_token = this->RegisterInterruptWakeup_(
            interrupt_flag, [this]() { SignalInterruptWakeSocket_(); });
        FD_SET(wake_read_sock, &readfds);
      }
    }

    const bool watch_socket =
        FD_ISSET(sock, &readfds) || FD_ISSET(sock, &writefds);
    const bool watch_wakeup = wake_read_sock != INVALID_SOCKET;
    if (!watch_socket && !watch_wakeup) {
      cleanup_wakeup();
      return WaitResult::Ready;
    }

    timeval tv{};
    timeval *timeout_ptr = nullptr;
    bool interrupt_poll_fallback = false;
    if (timeout_ms > 0) {
      const int64_t remaining =
          timeout_ms - (AMTime::miliseconds() - start_time);
      if (remaining <= 0) {
        cleanup_wakeup();
        return WaitResult::Timeout;
      }
      tv.tv_sec = static_cast<long>(remaining / 1000);
      tv.tv_usec = static_cast<long>((remaining % 1000) * 1000);
      timeout_ptr = &tv;
    } else if (wake_read_sock == INVALID_SOCKET) {
      // Fallback path: when wake socket backend is unavailable, wake select
      // periodically so Ctrl+C can still be observed for unbounded waits.
      tv.tv_sec = 0;
      tv.tv_usec = 100 * 1000; // 100ms
      timeout_ptr = &tv;
      interrupt_poll_fallback = true;
    }

#ifdef _WIN32
    const int rc = select(0, &readfds, &writefds, nullptr, timeout_ptr);
#else
    int nfds = static_cast<int>(sock) + 1;
    if (wake_read_sock != INVALID_SOCKET) {
      nfds = std::max(nfds, static_cast<int>(wake_read_sock) + 1);
    }
    const int rc = select(nfds, &readfds, &writefds, nullptr, timeout_ptr);
#endif

    cleanup_wakeup();

    if (rc < 0) {
      return is_interrupted() ? WaitResult::Interrupted : WaitResult::Error;
    }
    if (rc == 0) {
      if (interrupt_poll_fallback) {
        return is_interrupted() ? WaitResult::Interrupted : WaitResult::Ready;
      }
      return is_interrupted() ? WaitResult::Interrupted : WaitResult::Timeout;
    }

    if (wake_read_sock != INVALID_SOCKET &&
        FD_ISSET(wake_read_sock, &readfds)) {
      DrainInterruptWakeSocket_();
      if (is_interrupted()) {
        return WaitResult::Interrupted;
      }
    }
    if (is_interrupted()) {
      return WaitResult::Interrupted;
    }

    if (is_read_or_write) {
      if (FD_ISSET(sock, &readfds)) {
        return WaitResult::ReadReady;
      }
      if (FD_ISSET(sock, &writefds)) {
        return WaitResult::WriteReady;
      }
    }
    return WaitResult::Ready;
  }

  std::vector<std::string> GetKeys() { return this->private_keys; }

  void SetKeys(const std::vector<std::string> &keys) {
    this->private_keys = keys;
  }

  ECM Check(int timeout_ms = -1, int64_t start_time = -1,
            amf interrupt_flag = nullptr) override {
    auto rcm = stat(".", false, timeout_ms, start_time, interrupt_flag).first;
    AMDomain::client::ClientStatus status =
        rcm.first == EC::Success
            ? AMDomain::client::ClientStatus::OK
            : (rcm.first == EC::NotInitialized
                   ? AMDomain::client::ClientStatus::NotInitialized
                   : (rcm.first == EC::NoConnection
                          ? AMDomain::client::ClientStatus::NoConnection
                          : AMDomain::client::ClientStatus::ConnectionBroken));
    SetState({status, rcm});
    return rcm;
  }

  ECM BaseConnect(bool force = false, int timeout_ms = -1,
                  int64_t start_time = -1,
                  amf interrupt_flag = nullptr) {
    start_time = start_time == -1 ? AMTime::miliseconds() : start_time;
    std::lock_guard<std::recursive_mutex> lock(mtx);
    ConRequest request = request_atomic_.lock().load();
    const AMDomain::client::ClientState current_state = GetState();
    const bool connected =
        (current_state.first == AMDomain::client::ClientStatus::OK) &&
        session != nullptr && sftp != nullptr;
    if (connected) {
      if (!force) {
        return current_state.second;
      }
      Disconnect();
    }

    ECM rcm = {EC::Success, ""};
    int rcr = 0;
    WaitResult wr = WaitResult::Ready;
    bool password_auth = false;
    std::string password_tmp;
    std::string stored_password_enc = request.password;
    const char *auth_list = nullptr;

    auto NotifyAuth = [&](bool need_password, const std::string &password_enc,
                          bool password_correct) {
      if (!auth_cb) {
        return;
      }
      ConRequest callback_request = request;
      callback_request.password = password_correct ? password_enc : "";
      CallCallbackSafe(auth_cb,
                       AuthCBInfo(need_password, std::move(callback_request),
                                  password_enc, password_correct));
    };

    SocketConnector connector;
    if (!connector.Connect(request.hostname, static_cast<int>(request.port),
                           timeout_ms,
                           [this, interrupt_flag]() {
                             return this->IsOperationInterrupted_(
                                 interrupt_flag);
                           })) {
      trace(TraceLevel::Critical, connector.error_code,
            AMStr::fmt("{}", std::to_string(connector.sock)),
            "SocketConnector.Connect", connector.error_msg);
      return {connector.error_code, connector.error_msg};
    }
    sock = connector.sock;

    if (IsOperationInterrupted_(interrupt_flag)) {
      return {EC::Terminate, "Connection interrupted"};
    }
    if (timeout_ms > 0 && AMTime::miliseconds() - start_time >= timeout_ms) {
      return {EC::OperationTimeout, "Connection timed out"};
    }

    session = libssh2_session_init();
    if (!session) {
      trace(TraceLevel::Critical, EC::SessionCreateFailed, "",
            "libssh2_session_init", "Session initialization failed");
      return {EC::SessionCreateFailed, "Libssh2 Session initialization failed"};
    }
    libssh2_session_set_blocking(session, 0);

    if (request.compression) {
      libssh2_session_flag(session, LIBSSH2_FLAG_COMPRESS, 1);
      libssh2_session_method_pref(session, LIBSSH2_METHOD_COMP_CS,
                                  "zlib@openssh.com,zlib,none");
    }

    while (true) {
      rcr = libssh2_session_handshake(session, sock);
      if (rcr != LIBSSH2_ERROR_EAGAIN) {
        break;
      }
      wr = wait_for_socket(SocketWaitType::Auto, start_time, timeout_ms,
                           interrupt_flag);
      if (wr != WaitResult::Ready) {
        Disconnect();
        switch (wr) {
        case WaitResult::Timeout:
          return {EC::OperationTimeout,
                  "Connection timed out during handshake"};
        case WaitResult::Interrupted:
          return {EC::Terminate, "Connection interrupted during handshake"};
        case WaitResult::Error:
          return {EC::SocketRecvError, "Socket error during handshake"};
        default:
          return {EC::UnknownError, "Connection interrupted during handshake"};
        }
      }
    }

    rcm = ErrorRecord(
        rcr, TraceLevel::Critical,
        AMStr::fmt("socket {}", std::to_string(static_cast<size_t>(sock))),
        "libssh2_session_handshake");
    if (rcm.first != EC::Success) {
      Disconnect();
      return rcm;
    }

    rcm = VerifyKnownHostFingerprint(request);
    if (rcm.first != EC::Success) {
      trace(TraceLevel::Error, rcm.first, request.hostname,
            "VerifyKnownHostFingerprint", rcm.second);
      Disconnect();
      return rcm;
    }

    auto auth_list_res = nb_call(timeout_ms, start_time, [&]() {
      return libssh2_userauth_list(session, request.username.c_str(),
                                   request.username.length());
    }, interrupt_flag);
    rcm = ErrorRecord(auth_list_res, TraceLevel::Critical, request.username,
                      "libssh2_userauth_list", "Fail to {action} : {error}");
    if (rcm.first != EC::Success) {
      Disconnect();
      return rcm;
    }
    auth_list = auth_list_res.value;
    if (auth_list == nullptr) {
      rcm = {EC::AuthFailed, "Failed to query supported auth methods"};
      trace(TraceLevel::Critical, rcm.first, request.username,
            "libssh2_userauth_list", rcm.second);
      Disconnect();
      return rcm;
    }

    trace(TraceLevel::Debug, EC::Success, request.username,
          "libssh2_userauth_list",
          AMStr::fmt("Authentication methods: {}", auth_list));

    password_auth = (strstr(auth_list, "password") != nullptr);

    if (!request.keyfile.empty()) {
      if (IsOperationInterrupted_(interrupt_flag)) {
        return {EC::Terminate, "Authentication interrupted"};
      }
      auto auth_res = nb_call(-1, AMTime::miliseconds(), [&]() {
        return libssh2_userauth_publickey_fromfile(
            session, request.username.c_str(), nullptr, request.keyfile.c_str(),
            nullptr);
      }, interrupt_flag);
      if (!auth_res.ok()) {
        rcm = ErrorRecord(auth_res, TraceLevel::Error, request.username,
                          "libssh2_userauth_publickey_fromfile");
        Disconnect();
        return rcm;
      }
      rcr = auth_res.value;
      if (rcr == 0) {
        trace(TraceLevel::Info, EC::Success, "Success",
              "PrivatedKeyAuthorizeResult",
              AMStr::fmt("Dedicated private key \"{}\" authorize success",
                         request.keyfile));
        NotifyAuth(false, "", true);
        goto OK;
      }
      trace(TraceLevel::Error, EC::PublickeyAuthFailed, request.keyfile,
            "DedicatedPrivateKeyAuthorizeResult",
            AMStr::fmt("Dedicated private key \"{}\" authorize failed",
                       request.keyfile));
      NotifyAuth(false, "", false);
    }

    if (!stored_password_enc.empty() && password_auth) {
      if (IsOperationInterrupted_(interrupt_flag)) {
        return {EC::Terminate, "Authentication interrupted"};
      }
      std::string plain_password = AMAuth::DecryptPassword(stored_password_enc);
      auto auth_res = nb_call(-1, AMTime::miliseconds(), [&]() {
        return libssh2_userauth_password(session, request.username.c_str(),
                                         plain_password.c_str());
      }, interrupt_flag);
      AMAuth::SecureZero(plain_password);
      if (!auth_res.ok()) {
        rcm = ErrorRecord(auth_res, TraceLevel::Error, request.username,
                          "libssh2_userauth_password");
        Disconnect();
        return rcm;
      }
      rcr = auth_res.value;
      if (rcr == 0) {
        trace(TraceLevel::Info, EC::Success, "Success",
              "PasswordAuthorizeResult", "Password authorize success");
        request.password = stored_password_enc;
        request_atomic_.lock().store(request);
        NotifyAuth(false, stored_password_enc, true);
        goto OK;
      }
      trace(TraceLevel::Error, EC::AuthFailed, "", "PasswordAuth",
            "Password authentication failed");
      NotifyAuth(false, stored_password_enc, false);
    }

    if (!private_keys.empty()) {
      for (const auto &private_key : private_keys) {
        if (IsOperationInterrupted_(interrupt_flag)) {
          return {EC::Terminate, "Authentication interrupted"};
        }
        if (private_key == request.keyfile) {
          continue;
        }
        auto auth_res = nb_call(-1, AMTime::miliseconds(), [&]() {
          return libssh2_userauth_publickey_fromfile(
              session, request.username.c_str(), nullptr, private_key.c_str(),
              nullptr);
        }, interrupt_flag);
        if (!auth_res.ok()) {
          rcm = ErrorRecord(auth_res, TraceLevel::Error, request.username,
                            "libssh2_userauth_publickey_fromfile");
          Disconnect();
          return rcm;
        }
        rcr = auth_res.value;
        if (rcr == 0) {
          trace(TraceLevel::Info, EC::Success, private_key,
                "PrivatedKeyAuthorizeResult",
                AMStr::fmt("Shared private key \"{}\" authorize success",
                           private_key));
          NotifyAuth(false, "", true);
          goto OK;
        }
        trace(TraceLevel::Error, EC::PrivateKeyAuthFailed, private_key,
              "PrivatedKeyAuthorizeResult", rcm.second);
        NotifyAuth(false, "", false);
      }
    }

    if (password_auth_cb && password_auth) {
      trace(TraceLevel::Debug, EC::Success, "Interactive", "PasswordAuthorize",
            "Using password authentication callback to get another password");
      int trial_times = 0;
      while (trial_times < 2) {
        if (IsOperationInterrupted_(interrupt_flag)) {
          return {EC::Terminate, "Authentication interrupted"};
        }
        auto [password_opt, cb_ecm] =
            CallCallbackSafeRet<std::optional<std::string>>(
                auth_cb, AuthCBInfo(true, request, "", false));
        if (cb_ecm.first != EC::Success) {
          trace(TraceLevel::Error, cb_ecm.first, "AuthCB", "Call",
                cb_ecm.second);
          break;
        }
        password_tmp = password_opt.has_value() ? *password_opt : "";
        if (password_tmp.empty()) {
          break;
        }
        const std::string password_enc = AMAuth::EncryptPassword(password_tmp);
        auto auth_res = nb_call(-1, AMTime::miliseconds(), [&]() {
          return libssh2_userauth_password(session, request.username.c_str(),
                                           password_tmp.c_str());
        }, interrupt_flag);
        AMAuth::SecureZero(password_tmp);
        if (!auth_res.ok()) {
          rcm = ErrorRecord(auth_res, TraceLevel::Error, request.username,
                            "libssh2_userauth_password");
          Disconnect();
          return rcm;
        }
        rcr = auth_res.value;
        ++trial_times;
        if (rcr == 0) {
          trace(TraceLevel::Info, EC::Success, "Success",
                "PasswordAuthorizeResult", "Password authorize success");
          request.password = password_enc;
          request_atomic_.lock().store(request);
          NotifyAuth(false, password_enc, true);
          goto OK;
        }
        trace(TraceLevel::Error, EC::AuthFailed, "", "PasswordAuthorizeResult",
              "Wrong password");
        NotifyAuth(false, password_enc, false);
      }
    }

    rcm.first = EC::AuthFailed;
    rcm.second = "All authorize methods failed";

  OK:
    if (rcm.first != EC::Success) {
      Disconnect();
      return rcm;
    }

    auto sftp_init_res =
        nb_call(-1, AMTime::miliseconds(),
                [&]() { return libssh2_sftp_init(session); }, interrupt_flag);
    rcm =
        ErrorRecord(sftp_init_res, TraceLevel::Critical, "",
                    "libssh2_sftp_init", "SFTP initialization failed: {error}");
    if (rcm.first != EC::Success) {
      Disconnect();
      return rcm;
    }
    sftp = sftp_init_res.value;

    SetState({AMDomain::client::ClientStatus::OK, {EC::Success, ""}});
    libssh2_session_set_blocking(session, 0);
    return {EC::Success, ""};
  }

  EC GetLastEC() {
    if (!session) {
      return EC::NoSession;
    }
    std::lock_guard<std::recursive_mutex> lock(mtx);
    int ori_code = libssh2_session_last_errno(session);
    if (ori_code != LIBSSH2_ERROR_SFTP_PROTOCOL) {
      return IntToEC(ori_code);
    } else {
      if (!sftp) {
        return EC::NoConnection;
      }
      int ori_code2 = libssh2_sftp_last_error(sftp);
      return IntToEC(ori_code2);
    }
  }

  std::string GetLastErrorMsg() {
    if (!session) {
      return "Session not initialized";
    }
    std::lock_guard<std::recursive_mutex> lock(mtx);
    int ori_code = libssh2_session_last_errno(session);
    if (ori_code != LIBSSH2_ERROR_SFTP_PROTOCOL) {
      char *errmsg = nullptr;
      int errmsg_len;
      libssh2_session_last_error(session, &errmsg, &errmsg_len, 0);
      if (!errmsg || errmsg_len <= 0) {
        return "Unknown SSH error";
      }
      return std::string(errmsg, static_cast<size_t>(errmsg_len));
    } else {
      if (!sftp) {
        return "SFTP not initialized";
      }
      return SSHCodeToString(libssh2_sftp_last_error(sftp));
    }
  }
};

class AMSFTPIOCore : public SFTPSessionBase, public BasePathMatch {
private:
  std::unordered_map<long, std::string> user_id_map;

  std::string GetPathOnwer(const std::string &path,
                           const LIBSSH2_SFTP_ATTRIBUTES &attrs) {

    if (config_part_->GetOSType() == OS_TYPE::Windows) {
      auto cmd_f = AMStr::fmt("powershell -NoProfile -Command \"(Get-Acl "
                              "-LiteralPath '{}').Owner \"",
                              path);
      auto [rcm, cr] = ConductCmd(cmd_f);
      if (!isok(rcm) || cr.second != 0) {
        return "unknown";
      }
      int pos = cr.first.find_last_of("\\");
      if (pos != std::string::npos && pos + 1 < cr.first.size()) {
        return cr.first.substr(pos + 1);
      } else {
        return cr.first;
      }
    } else if (attrs.flags & LIBSSH2_SFTP_ATTR_UIDGID) {
      long uid = attrs.uid;
      return StrUid(uid);
    } else {
      return "";
    }
  }

  PathInfo FormatStat(const std::string &path,
                      const LIBSSH2_SFTP_ATTRIBUTES &attrs) {
    PathInfo info;
    info.path = path;
    info.name = AMPathStr::basename(path);
    info.dir = AMPathStr::dirname(path);

    if (attrs.flags & LIBSSH2_SFTP_ATTR_SIZE) {
      info.size = attrs.filesize;
    }

    if (attrs.flags & LIBSSH2_SFTP_ATTR_ACMODTIME) {
      info.access_time = attrs.atime;
      info.modify_time = attrs.mtime;
    }

    if (UpdateOSTypeCache_() != OS_TYPE::Windows &&
        attrs.flags & LIBSSH2_SFTP_ATTR_UIDGID) {
      info.owner = StrUid(attrs.uid);
    } else {
      info.owner = "";
    }

    if (attrs.flags & LIBSSH2_SFTP_ATTR_PERMISSIONS) {
      const uint32_t mode = attrs.permissions;
      const uint32_t file_type = mode & LIBSSH2_SFTP_S_IFMT;
      switch (file_type) {
      case LIBSSH2_SFTP_S_IFDIR:
        info.type = PathType::DIR;
        break;
      case LIBSSH2_SFTP_S_IFLNK:
        info.type = PathType::SYMLINK;
        break;
      case LIBSSH2_SFTP_S_IFREG:
        info.type = PathType::FILE;
        break;
      case LIBSSH2_SFTP_S_IFBLK:
        info.type = PathType::BlockDevice;
        break;
      case LIBSSH2_SFTP_S_IFCHR:
        info.type = PathType::CharacterDevice;
        break;
      case LIBSSH2_SFTP_S_IFSOCK:
        info.type = PathType::Socket;
        break;
      case LIBSSH2_SFTP_S_IFIFO:
        info.type = PathType::FIFO;
        break;
      default:
        info.type = PathType::Unknown;
        break;
      }
      if (UpdateOSTypeCache_() != OS_TYPE::Windows) {
        info.mode_int = mode & 0777;
        info.mode_str = AMStr::ModeTrans(info.mode_int);
      }
    }
    return info;
  }

  std::pair<ECM, std::string> lib_realpath(const std::string &path,
                                           int timeout_ms = -1,
                                           int64_t start_time = -1,
                                           amf interrupt_flag = nullptr) {
    if (!sftp) {
      return {ECM{EC::NoConnection, "SFTP not initialized"}, ""};
    }
    char path_t[1024] = {0};
    auto nb_res = nb_call(timeout_ms, start_time, [&] {
      return libssh2_sftp_realpath(sftp, path.c_str(), path_t, sizeof(path_t));
    }, interrupt_flag);
    return {ErrorRecord(nb_res, TraceLevel::Error, path,
                        "libssh2_sftp_realpath",
                        "Realpath \"{target}\" failed: {error}"),
            std::string(path_t)};
  }

  ECM lib_rename(const std::string &src, const std::string &dst,
                 const bool &overwrite, int timeout_ms = -1,
                 int64_t start_time = -1, amf interrupt_flag = nullptr) {
    if (!sftp) {
      return std::make_pair(EC::NoConnection, "SFTP not initialized");
    }

    if (!overwrite) {
      auto nb_res = nb_call(timeout_ms, start_time, [&] {
        return libssh2_sftp_rename_ex(sftp, src.c_str(), src.size(),
                                      dst.c_str(), dst.size(),
                                      LIBSSH2_SFTP_RENAME_NATIVE);
      }, interrupt_flag);
      return ErrorRecord(
          nb_res, TraceLevel::Error, AMStr::fmt("{} -> {}", src, dst),
          "libssh2_sftp_rename_ex", "Rename {target} failed: {error}");
    } else {
      auto nb_res = nb_call(timeout_ms, start_time, [&] {
        return libssh2_sftp_rename_ex(
            sftp, src.c_str(), src.size(), dst.c_str(), dst.size(),
            LIBSSH2_SFTP_RENAME_OVERWRITE | LIBSSH2_SFTP_RENAME_NATIVE);
      }, interrupt_flag);
      return ErrorRecord(
          nb_res, TraceLevel::Error, AMStr::fmt("{} -> {}", src, dst),
          "libssh2_sftp_rename_ex", "Rename {target} failed: {error}");
    }
  }

  std::pair<ECM, LIBSSH2_SFTP_ATTRIBUTES> lib_getstat(const std::string &path,
                                                      bool trace_link = false,
                                                      int timeout_ms = -1,
                                                      int64_t start_time = -1,
                                                      amf interrupt_flag = nullptr) {
    if (!sftp) {
      return {ECM{EC::NoConnection, "SFTP not initialized"},
              LIBSSH2_SFTP_ATTRIBUTES()};
    }
    LIBSSH2_SFTP_ATTRIBUTES attrs;
    NBResult<int> nb_res;
    if (trace_link) {
      nb_res = nb_call(timeout_ms, start_time, [&] {
        return libssh2_sftp_stat(sftp, path.c_str(), &attrs);
      }, interrupt_flag);
    } else {
      nb_res = nb_call(timeout_ms, start_time, [&] {
        return libssh2_sftp_lstat(sftp, path.c_str(), &attrs);
      }, interrupt_flag);
    }
    ECM rcm = ErrorRecord(nb_res, TraceLevel::Error, path, "libssh2_sftp_stat",
                          "Get stat failed: {error}");
    return {rcm, attrs};
  }

  ECM lib_setstat(const std::string &path, LIBSSH2_SFTP_ATTRIBUTES &attrs,
                  int timeout_ms = -1, int64_t start_time = -1,
                  amf interrupt_flag = nullptr) {
    if (!sftp) {
      return {EC::NoConnection, "SFTP not initialized"};
    }

    auto nb_res = nb_call(timeout_ms, start_time, [&] {
      return libssh2_sftp_setstat(sftp, path.c_str(), &attrs);
    }, interrupt_flag);
    return ErrorRecord(nb_res, TraceLevel::Error, path, "libssh2_sftp_setstat",
                       "Set stat failed: {error}");
  }

  ECM lib_unlink(const std::string &path, int timeout_ms = -1,
                 int64_t start_time = -1,
                 amf interrupt_flag = nullptr) {
    if (!sftp) {
      return {EC::NoConnection, "SFTP not initialized"};
    }

    auto nb_res = nb_call(timeout_ms, start_time, [&] {
      return libssh2_sftp_unlink(sftp, path.c_str());
    }, interrupt_flag);
    return ErrorRecord(nb_res, TraceLevel::Error, path, "libssh2_sftp_unlink",
                       "Unlink \"{target}\" failed: {error}");
  }

  ECM lib_rmdir(const std::string &path, int timeout_ms = -1,
                int64_t start_time = -1,
                amf interrupt_flag = nullptr) {
    if (!sftp) {
      return {EC::NoConnection, "SFTP not initialized"};
    }

    auto nb_res = nb_call(timeout_ms, start_time, [&] {
      return libssh2_sftp_rmdir(sftp, path.c_str());
    }, interrupt_flag);
    return ErrorRecord(nb_res, TraceLevel::Error, path, "libssh2_sftp_rmdir",
                       "Remove directory failed: {error}");
  }

  ECM lib_mkdir(const std::string &path, int timeout_ms = -1,
                int64_t start_time = -1,
                amf interrupt_flag = nullptr) {
    if (!sftp) {
      return {EC::NoConnection, "SFTP not initialized"};
    }

    NBResult<int> nb_res = nb_call(timeout_ms, start_time, [&] {
      return libssh2_sftp_mkdir_ex(sftp, path.c_str(), path.size(), 0740);
    }, interrupt_flag);
    return ErrorRecord(nb_res, TraceLevel::Error, path, "libssh2_sftp_mkdir_ex",
                       "Create directory \"{target}\" failed: {error}");
  }

  std::pair<ECM, std::vector<std::pair<std::string, LIBSSH2_SFTP_ATTRIBUTES>>>
  lib_listdir(const std::string &path, int timeout_ms = -1,
              int64_t start_time = -1, amf interrupt_flag = nullptr) {
    if (!sftp) {
      return {ECM{EC::NoConnection, "SFTP not initialized"}, {}};
    }
    LIBSSH2_SFTP_ATTRIBUTES attrs;
    std::vector<std::pair<std::string, LIBSSH2_SFTP_ATTRIBUTES>> file_list = {};
    LIBSSH2_SFTP_HANDLE *sftp_handle = nullptr;
    std::string name;
    ECM rcm;
    const size_t buffer_size = 4096;
    std::vector<char> filename_buffer = std::vector<char>(buffer_size, 0);
    auto oepn_res = nb_call(timeout_ms, start_time, [&] {
      return libssh2_sftp_open_ex(sftp, path.c_str(), path.size(), 0,
                                  LIBSSH2_SFTP_OPENDIR, LIBSSH2_FXF_READ);
    }, interrupt_flag);
    rcm = ErrorRecord(oepn_res, TraceLevel::Error, path, "libssh2_sftp_open_ex",
                      "Open directory {target} failed: {error}");
    if (rcm.first != EC::Success) {
      return {rcm, {}};
    }
    sftp_handle = oepn_res.value;
    NBResult<int> read_res;

    while (true) {
      if (timeout_ms > 0 && AMTime::miliseconds() - start_time >= timeout_ms) {
        rcm = ECM{EC::OperationTimeout,
                  AMStr::fmt("Path: {} readdir timeout", path)};
        break;
      }
      if (this->IsOperationInterrupted_(interrupt_flag)) {
        rcm = ECM{EC::Terminate,
                  AMStr::fmt("Path: {} readdir interrupted by user", path)};
        break;
      }
      read_res = nb_call(timeout_ms, start_time, [&] {
        return libssh2_sftp_readdir_ex(sftp_handle, filename_buffer.data(),
                                       buffer_size, nullptr, 0, &attrs);
      }, interrupt_flag);
      if (read_res.value == 0) {
        break;
      }
      rcm = ErrorRecord(read_res, TraceLevel::Error, path,
                        "libssh2_sftp_readdir_ex",
                        "Path: {} readdir failed: {error}");
      if (rcm.first != EC::Success) {
        if (rcm.first == EC::PermissionDenied) {
          continue;
        }
        break;
      }

      name.assign(filename_buffer.data(), read_res.value);

      if (name == "." || name == ".." || name.empty()) {
        continue;
      }
      file_list.emplace_back(AMPathStr::join(path, name), attrs);
    }

    if (sftp_handle) {
      libssh2_sftp_close_handle(sftp_handle);
    }
    return {rcm, file_list};
  }

protected:
  void _iwalk(const std::string &path, const LIBSSH2_SFTP_ATTRIBUTES &attrs,
              WRV &result, RMR &errors, bool show_all = false,
              bool ignore_sepcial_file = true,
              AMFS::WalkErrorCallback error_callback = nullptr,
              int timeout_ms = -1, int64_t start_time = -1,
              amf interrupt_flag = nullptr) {
    // Find all deepest paths under directory for recursive transfer
    if (this->IsOperationInterrupted_(interrupt_flag)) {
      return;
    }

    const bool filter_hidden = !show_all;
    const bool filter_special = !show_all && ignore_sepcial_file;
    const auto is_hidden_name = [](const std::string &name) {
      return !name.empty() && name[0] == '.';
    };

    if (!isdir(attrs)) {
      // Add directly if not a directory
      if (filter_hidden && is_hidden_name(AMPathStr::basename(path))) {
        return;
      }
      if (!isreg(attrs) && filter_special) {
        return;
      }
      result.push_back(FormatStat(path, attrs));
      return;
    }

    auto [rcm2, attrs_list] =
        lib_listdir(path, timeout_ms, start_time, interrupt_flag);
    if (rcm2.first != EC::Success) {
      if (rcm2.first != EC::OperationTimeout) {
        if (error_callback && *error_callback) {
          (*error_callback)(path, rcm2);
        }
        errors.emplace_back(path, rcm2);
      }
      return;
    }

    if (attrs_list.empty()) {
      // Add leaf empty directory directly
      result.push_back(FormatStat(path, attrs));
      return;
    }
    for (auto &attrs : attrs_list) {
      if (this->IsOperationInterrupted_(interrupt_flag)) {
        return;
      }
      if (timeout_ms > 0 && AMTime::miliseconds() - start_time >= timeout_ms) {
        return;
      }
      const std::string base_name = AMPathStr::basename(attrs.first);
      if (filter_hidden && is_hidden_name(base_name)) {
        continue;
      }
      _iwalk(attrs.first, attrs.second, result, errors, show_all,
             ignore_sepcial_file, error_callback, timeout_ms, start_time,
             interrupt_flag);
    }
  }

  void _walk(const std::vector<std::string> &parts, WRD &result, RMR &errors,
             int cur_depth = 0, int max_depth = -1, bool show_all = false,
             bool ignore_sepcial_file = true,
             AMFS::WalkErrorCallback error_callback = nullptr,
             int timeout_ms = -1, int64_t start_time = -1,
             amf interrupt_flag = nullptr) {
    if (max_depth != -1 && cur_depth > max_depth) {
      return;
    }
    if (this->IsOperationInterrupted_(interrupt_flag)) {
      return;
    }
    std::string pathf = AMPathStr::join(parts);
    auto [rcm2, list_info] =
        lib_listdir(pathf, timeout_ms, start_time, interrupt_flag);
    if (rcm2.first != EC::Success) {
      if (rcm2.first != EC::OperationTimeout) {
        if (error_callback && *error_callback) {
          (*error_callback)(pathf, rcm2);
        }
        errors.emplace_back(pathf, rcm2);
      }
      return;
    }

    if (list_info.empty()) {
      result.push_back({parts, {}});
      return;
    }

    const bool filter_hidden = !show_all;
    const bool filter_special = !show_all && ignore_sepcial_file;
    const auto is_hidden_name = [](const std::string &name) {
      return !name.empty() && name[0] == '.';
    };
    std::vector<PathInfo> files_info = {};
    for (auto &[path, attrs] : list_info) {
      if (this->IsOperationInterrupted_(interrupt_flag)) {
        return;
      }
      if (timeout_ms > 0 && AMTime::miliseconds() - start_time >= timeout_ms) {
        return;
      }
      const std::string base_name = AMPathStr::basename(path);
      if (filter_hidden && is_hidden_name(base_name)) {
        continue;
      }
      if (isdir(attrs)) {
        auto new_parts = parts;
        new_parts.push_back(AMPathStr::basename(path));
        _walk(new_parts, result, errors, cur_depth + 1, max_depth, show_all,
              ignore_sepcial_file, error_callback, timeout_ms, start_time,
              interrupt_flag);
      } else {
        if (filter_special && !isreg(attrs)) {
          continue;
        }
        files_info.push_back(FormatStat(path, attrs));
      }
    }
    if (list_info.empty()) {
      return;
    }
    result.emplace_back(parts, files_info);
  }

  void _rm(const std::string &path, const LIBSSH2_SFTP_ATTRIBUTES &attrs,
           RMR &errors, AMFS::WalkErrorCallback error_callback = nullptr,
           int timeout_ms = -1, int64_t start_time = -1,
           amf interrupt_flag = nullptr) {
    if (this->IsOperationInterrupted_(interrupt_flag)) {
      return;
    }
    if (!isdir(attrs)) {
      ECM ecm = lib_unlink(path, timeout_ms, start_time, interrupt_flag);
      if (ecm.first != EC::Success) {
        if (error_callback && *error_callback) {
          (*error_callback)(path, ecm);
        }
        errors.emplace_back(path, ecm);
      }
      return;
    }

    auto [rcm2, file_list] =
        lib_listdir(path, timeout_ms, start_time, interrupt_flag);
    if (rcm2.first != EC::Success) {
      if (error_callback && *error_callback) {
        (*error_callback)(path, rcm2);
      }
      errors.emplace_back(path, rcm2);
      return;
    }

    if (this->IsOperationInterrupted_(interrupt_flag)) {
      return;
    }

    for (auto &file : file_list) {
      if (this->IsOperationInterrupted_(interrupt_flag)) {
        return;
      }
      _rm(file.first, file.second, errors, error_callback, timeout_ms,
          start_time, interrupt_flag);
    }

    ECM ecm = lib_rmdir(path, timeout_ms, start_time, interrupt_flag);
    if (ecm.first != EC::Success) {
      if (error_callback && *error_callback) {
        (*error_callback)(path, ecm);
      }
      errors.emplace_back(path, ecm);
    }
  }

  void _chmod(const std::string &path, size_t mode, bool recursive,
              std::unordered_map<std::string, ECM> &errors,
              LIBSSH2_SFTP_ATTRIBUTES attrs, int timeout_ms = -1,
              int64_t start_time = -1, amf interrupt_flag = nullptr) {
    if (this->IsOperationInterrupted_(interrupt_flag)) {
      return;
    }
    ECM rcm;
    if (!(attrs.flags & LIBSSH2_SFTP_ATTR_PERMISSIONS)) {
      errors[path] = {EC::NoPermissionAttribute,
                      "stat does not have permission attribute"};
      return;
    }

    if (!(attrs.flags & LIBSSH2_SFTP_ATTR_PERMISSIONS)) {
      errors[path] = {EC::NoPermissionAttribute,
                      "server didn't return permission attribute"};
      return;
    }

    size_t file_type = attrs.permissions & LIBSSH2_SFTP_S_IFMT;
    size_t new_mode_int = (mode & ~LIBSSH2_SFTP_S_IFMT) | file_type;

    attrs.permissions = new_mode_int;
    attrs.flags = LIBSSH2_SFTP_ATTR_PERMISSIONS;

    if (((size_t)attrs.permissions & 0777) != (mode & 0777)) {
      rcm = lib_setstat(path, attrs, timeout_ms, start_time, interrupt_flag);
      if (rcm.first != EC::Success) {
        errors[path] = rcm;
        return;
      }
    }

    if (recursive && file_type == LIBSSH2_SFTP_S_IFDIR) {
      auto [rcm2, list] = lib_listdir(path, timeout_ms, start_time, interrupt_flag);
      if (rcm2.first != EC::Success) {
        errors[path] = rcm2;
        return;
      }
      for (auto &item : list) {
        if (this->IsOperationInterrupted_(interrupt_flag)) {
          return;
        }
        if (timeout_ms > 0 &&
            AMTime::miliseconds() - start_time >= timeout_ms) {
          return;
        }
        _chmod(item.first, mode, recursive, errors, item.second, timeout_ms,
               start_time, interrupt_flag);
      }
    }
  }

  ECM _precheck(const std::string &path, amf interrupt_flag = nullptr) {
    if (path.empty()) {
      return {EC::InvalidArg, AMStr::fmt("Invalid path: {}", path)};
    }
    if (this->IsOperationInterrupted_(interrupt_flag)) {
      return {EC::Terminate, "Interrupted by user"};
    }
    if (!sftp) {
      return {EC::NoConnection, "SFTP not initialized"};
    }
    return {EC::Success, ""};
  }

public:
  AMSFTPIOCore(AMDomain::client::IClientConfigPort *config_port,
               AMDomain::client::IClientTaskControlPort *control_port,
               const std::vector<std::string> &keys = {},
               TraceCallback trace_cb = {}, AuthCallback auth_cb = {},
               AMDomain::client::KnownHostCallback known_host_cb = {})
      : SFTPSessionBase(config_port, control_port, keys, std::move(trace_cb),
                        std::move(auth_cb), std::move(known_host_cb)) {
    if (config_port == nullptr || control_port == nullptr) {
      throw std::invalid_argument(
          "AMSFTPIOCore requires non-null config and control ports");
    }
#ifdef _WIN32
    AMInitWSA();
#endif
    auto req = request_atomic_.lock();
    req->protocol = ClientProtocol::SFTP;
    if (req->trash_dir.empty()) {
      req->trash_dir = ".AMSFTP_Trash";
    }
  }

  // Get RTT (Round Trip Time), return average (ms)
  // Measure via a simple SFTP operation
  double GetRTT(ssize_t times = 5) override {
    if (times <= 0)
      times = 1;
    std::lock_guard<std::recursive_mutex> lock(mtx);

    if (!session || !sftp) {
      return -1.0;
    }

    std::vector<double> rtts;
    rtts.reserve(times);

    // Use libssh2_sftp_stat to measure RTT (minimal-overhead SFTP op)
    LIBSSH2_SFTP_ATTRIBUTES attrs;
    libssh2_session_set_blocking(session, 0);

    for (ssize_t i = 0; i < times; i++) {
      if (this->IsOperationInterrupted_()) {
        break;
      }

      double start = (static_cast<double>(AMTime::miliseconds()) / 1000.0);
      auto stat_res = nb_call(-1, AMTime::miliseconds(), [&] {
        return libssh2_sftp_stat(sftp, "/", &attrs);
      });
      if (stat_res.status != WaitResult::Ready) {
        break;
      }

      if (stat_res.value == 0) {
        double end = (static_cast<double>(AMTime::miliseconds()) / 1000.0);
        rtts.push_back(end - start);
      }
    }

    if (rtts.empty()) {
      return -1.0;
    }

    // Compute average
    double sum = 0.0;
    for (double rtt : rtts) {
      sum += rtt;
    }
    return sum * (double)1000.0 / static_cast<double>(rtts.size());
  }

  CR ConductCmd(const std::string &cmd, int max_time_ms = 3000,
                amf interrupt_flag = nullptr) override {
    std::lock_guard<std::recursive_mutex> lock(mtx);
    if (this->IsOperationInterrupted_(interrupt_flag)) {
      return {ECM{EC::Terminate, "Operation aborted before command sent"},
              {"", -1}};
    }

    enum class CmdStage { BeforeSend, AwaitOutput, ReadingOutput, AwaitExit };
    CmdStage stage = CmdStage::BeforeSend;

    int64_t time_start = AMTime::miliseconds();
    int exit_status = -1;
    bool has_output = false;
    std::string output;
    std::array<char, 32 * AMKB> buffer;
    WaitResult wr = WaitResult::Ready;
    ssize_t nbytes = 0;
    NBResult<int> exec_res{0, WaitResult::Ready};
    NBResult<ssize_t> read_res{0, WaitResult::Ready};
    NBResult<int> close_res{0, WaitResult::Ready};

    // Set non-blocking mode
    libssh2_session_set_blocking(session, 0);

    SafeChannel sf;
    ECM init_rcm =
        sf.Init(session,
                [this, interrupt_flag]() {
                  return this->IsOperationInterrupted_(interrupt_flag);
                },
                max_time_ms, time_start);
    if (init_rcm.first != EC::Success) {
      return {std::move(init_rcm), {"", -1}};
    }

    auto graceful_exit = [&](bool send_exit) {
      (void)sf.graceful_exit(send_exit, 50, true);
    };

    // 1. Execute command
    exec_res = nb_call(max_time_ms, time_start, [&] {
      return libssh2_channel_exec(sf.channel, cmd.c_str());
    }, interrupt_flag);
    if (!exec_res.ok()) {
      wr = exec_res.status;
      goto cleanup;
    }
    if (exec_res.value < 0) {
      return {ECM{GetLastEC(),
                  AMStr::fmt("Channel exec failed: {}", GetLastErrorMsg())},
              {"", -1}};
    }
    stage = CmdStage::AwaitOutput;
    // 2. Read output
    while (true) {
      read_res = nb_call(max_time_ms, time_start, [&] {
        return libssh2_channel_read(sf.channel, buffer.data(),
                                    buffer.size() - 1);
      }, interrupt_flag);
      if (!read_res.ok()) {
        wr = read_res.status;
        goto cleanup;
      }
      nbytes = read_res.value;

      if (nbytes > 0) {
        output.append(buffer.data(), static_cast<size_t>(nbytes));
        has_output = true;
        stage = CmdStage::ReadingOutput;
      } else if (nbytes == 0) {
        stage = CmdStage::AwaitExit;
        break; // EOF
      } else {
        return {ECM{GetLastEC(),
                    AMStr::fmt("Channel read failed: {}", GetLastErrorMsg())},
                {"", -1}};
      }
    }

    // 3. Trim trailing output whitespace
    while (!output.empty() &&
           (output.back() == '\n' || output.back() == '\r')) {
      output.pop_back();
    }

    // 4. Close channel non-blocking
    close_res = nb_call(max_time_ms, time_start,
                        [&] { return sf.close_nonblock(); }, interrupt_flag);

    if (!close_res.ok()) {
      wr = close_res.status;
      goto cleanup;
    }

    if (close_res.value < 0) {
      return {ECM{GetLastEC(),
                  AMStr::fmt("Channel close failed: {}", GetLastErrorMsg())},
              {output, -1}};
    }

    // 5. Get exit status
    exit_status = libssh2_channel_get_exit_status(sf.channel);

    return {ECM{EC::Success, ""}, {output, exit_status}};

  cleanup:
    switch (wr) {
    case WaitResult::Interrupted:
      if (stage == CmdStage::BeforeSend) {
        graceful_exit(false);
        return {ECM{EC::Terminate, "Operation aborted before command sent"},
                {output, -1}};
      }
      if (stage == CmdStage::AwaitOutput && !has_output) {
        graceful_exit(true);
        return {ECM{EC::Terminate,
                    AMStr::fmt("Command canceled before output: {}", cmd)},
                {output, -1}};
      }
      graceful_exit(true);
      return {
          ECM{EC::Terminate,
              AMStr::fmt("Command interrupted before exit status: {}", cmd)},
          {output, -1}};
    case WaitResult::Timeout:
      graceful_exit(true);
      return {ECM{EC::OperationTimeout,
                  AMStr::fmt("Command timed out (killed): {}", cmd)},
              {output, -1}};
    case WaitResult::Error:
      graceful_exit(true);
      return {ECM{EC::SocketRecvError,
                  AMStr::fmt("Socket error during command: {}", cmd)},
              {output, -1}};
    default:
      graceful_exit(true);
      return {ECM{EC::UnknownError, AMStr::fmt("Command aborted: {}", cmd)},
              {output, -1}};
    }
  }

  OS_TYPE UpdateOSTypeCache_(bool force_refresh = false) {
    OS_TYPE cached = GetCachedOSType_();
    if (!force_refresh && cached != OS_TYPE::Uncertain &&
        cached != OS_TYPE::Unknown) {
      return cached;
    }
    auto [rcm2, out2] =
        ConductCmd("powershell -NoProfile -Command "
                   "\"[System.Environment]::OSVersion.VersionString\"",
                   3000);
    int code = out2.second;
    std::string out_str = out2.first;
    if (out_str.find("Windows") != std::string::npos) {
      SetCachedOSType_(OS_TYPE::Windows);
      return OS_TYPE::Windows;
    }

    auto [rcm, out] = ConductCmd("uname -s", 3000);
    if (rcm.first != EC::Success) {
      SetCachedOSType_(OS_TYPE::Uncertain);
      return OS_TYPE::Uncertain;
    }
    code = out.second;
    if (code == 0) {
      out_str = AMStr::lowercase(out.first);
      if (out_str.find("cygwin") != std::string::npos) {
        cached = OS_TYPE::Windows;
      } else if (out_str.find("darwin") != std::string::npos) {
        cached = OS_TYPE::MacOS;
      } else if (out_str.find("linux") != std::string::npos) {
        cached = OS_TYPE::Linux;
      } else if (out_str.find("mingw") != std::string::npos) {
        cached = OS_TYPE::Windows;
      } else if (out_str.find("msys") != std::string::npos) {
        cached = OS_TYPE::Windows;
      } else if (out_str.find("freebsd") != std::string::npos) {
        cached = OS_TYPE::FreeBSD;
      } else {
        cached = OS_TYPE::Unix;
      }
      SetCachedOSType_(cached);
      return cached;
    }

    SetCachedOSType_(OS_TYPE::Unknown);
    return OS_TYPE::Unknown;
  }

  std::string StrUid(const long &uid) {
    if (user_id_map.find(uid) != user_id_map.end()) {
      return user_id_map[uid];
    }

    std::string cmd = AMStr::fmt("id -un {}", std::to_string(uid));
    auto [rcm, cr] = ConductCmd(cmd, 3000);
    if (rcm.first != EC::Success) {
      return "unknown";
    }
    if (cr.second != 0) {
      return "unknown";
    } else {
      user_id_map[uid] = cr.first;
      return cr.first;
    }
  }

  std::string UpdateHomeDirCache_() {
    std::string cached_home_dir = GetCachedHomeDir_();
    if (!cached_home_dir.empty()) {
      return cached_home_dir;
    }
    auto [rcm, path_obj] = realpath(".", 3000, -1);
    if (rcm.first == EC::Success) {
      SetCachedHomeDir_(path_obj);
      return path_obj;
    }
    const ConRequest request = request_atomic_.lock().load();
    switch (UpdateOSTypeCache_()) {
    case OS_TYPE::Windows:
      return "C:\\Users\\" + request.username;
    case OS_TYPE::Linux:
      return "/home/" + request.username;
    case OS_TYPE::MacOS:
      return "/Users/" + request.username;
    case OS_TYPE::FreeBSD:
      return "/usr/home/" + request.username;
    case OS_TYPE::Unix:
      return "/home/" + request.username;
    default:
      return "C:\\Users\\" + request.username;
    }
  }

  ECM Connect(bool force = false, int timeout_ms = -1,
              int64_t start_time = -1,
              amf interrupt_flag = nullptr) override {
    const AMDomain::client::ClientState prev_state = GetState();
    ECM ecm = BaseConnect(force, timeout_ms, start_time, interrupt_flag);
    if (isok(ecm) && prev_state.first != AMDomain::client::ClientStatus::OK) {
      (void)UpdateOSType(timeout_ms, start_time, interrupt_flag);
      (void)UpdateHomeDir(timeout_ms, start_time, interrupt_flag);
    }
    AMDomain::client::ClientStatus status =
        ecm.first == EC::Success
            ? AMDomain::client::ClientStatus::OK
            : (ecm.first == EC::NotInitialized
                   ? AMDomain::client::ClientStatus::NotInitialized
                   : (ecm.first == EC::NoConnection
                          ? AMDomain::client::ClientStatus::NoConnection
                          : AMDomain::client::ClientStatus::ConnectionBroken));
    SetState({status, ecm});
    return ecm;
  }

  // Parse and return absolute path,
  // ~ is resolved in client; .. and . are resolved by server; such symbols
  // require path to exist
  std::pair<ECM, std::string> realpath(const std::string &path,
                                       int timeout_ms = -1,
                                       int64_t start_time = -1,
                                       amf interrupt_flag = nullptr) override {
    auto pathf = path;
    ECM rcm = _precheck(path, interrupt_flag);
    if (rcm.first != EC::Success) {
      return {rcm, ""};
    }
    if (std::regex_search(path, std::regex("^~[\\\\/]"))) {
      // Resolve ~ symbol
      pathf = AMPathStr::join(UpdateHomeDirCache_(), pathf.substr(1),
                              SepType::Unix);
    } else if (path == "~") {
      return {ECM{EC::Success, ""}, UpdateHomeDirCache_()};
    }
    start_time = start_time == -1 ? AMTime::miliseconds() : start_time;

    auto [rcm2, path_t] = lib_realpath(path, timeout_ms, start_time, interrupt_flag);
    if (rcm2.first != EC::Success) {
      return {rcm2, ""};
    }
    if (UpdateOSTypeCache_() == OS_TYPE::Windows) {
      // Windows server may prepend / or \ to path; remove it
      return {rcm2, path_t.substr(1)};
    }
    return {rcm2, path_t};
  }

  std::pair<ECM, std::unordered_map<std::string, ECM>>
  chmod(const std::string &path, std::variant<std::string, size_t> mode,
        bool recursive = false, int timeout_ms = -1,
        int64_t start_time = -1, amf interrupt_flag = nullptr) override {
    if (static_cast<int>(UpdateOSTypeCache_()) <= 0) {
      return {ECM{EC::UnImplentedMethod, "Chmod only supported on Unix System"},
              {}};
    }
    start_time = start_time == -1 ? AMTime::miliseconds() : start_time;
    std::lock_guard<std::recursive_mutex> lock(mtx);
    auto [rcm, attrs] =
        lib_getstat(path, false, timeout_ms, start_time, interrupt_flag);
    if (rcm.first != EC::Success) {
      return {rcm, {}};
    }
    if (!(attrs.flags & LIBSSH2_SFTP_ATTR_PERMISSIONS)) {
      return {ECM{EC::NoPermissionAttribute,
                  "stat does not have permission attribute"},
              {}};
    }

    if (this->IsOperationInterrupted_(interrupt_flag)) {
      return {ECM{EC::Terminate, "Interrupted by user, no action conducted"},
              {}};
    }
    std::unordered_map<std::string, ECM> ecm_map{};
    size_t mode_int;
    if (std::holds_alternative<std::string>(mode)) {
      if (!AMStr::IsModeValid(std::get<std::string>(mode))) {
        return {ECM{EC::InvalidArg, AMStr::fmt("Invalid mode: {}",
                                               std::get<std::string>(mode))},
                {}};
      }
      mode_int = AMStr::ModeTrans(std::get<std::string>(mode));
    } else if (std::holds_alternative<size_t>(mode)) {
      if (!AMStr::IsModeValid(std::get<size_t>(mode))) {
        return {ECM{EC::InvalidArg,
                    AMStr::fmt("Invalid mode: {}",
                               std::to_string(std::get<size_t>(mode)))},
                {}};
      }
      mode_int = std::get<size_t>(mode);
    } else {
      return {ECM{EC::InvalidArg, AMStr::fmt("Invalid mode data type")}, {}};
    }
    _chmod(path, mode_int, recursive, ecm_map, attrs, timeout_ms, start_time,
           interrupt_flag);
    return {ECM{EC::Success, ""}, ecm_map};
  }

  // Get path info (with AMFS::abspath)
  SR stat(const std::string &path, bool trace_link = false, int timeout_ms = -1,
          int64_t start_time = -1,
          amf interrupt_flag = nullptr) override {
    ECM rcm = _precheck(path, interrupt_flag);
    if (rcm.first != EC::Success) {
      return {rcm, PathInfo()};
    }
    std::lock_guard<std::recursive_mutex> lock(mtx);
    start_time = start_time == -1 ? AMTime::miliseconds() : start_time;
    auto [rcm2, attrs] =
        lib_getstat(path, trace_link, timeout_ms, start_time, interrupt_flag);
    if (rcm2.first != EC::Success) {
      return {rcm2, PathInfo()};
    }
    return {rcm, FormatStat(path, attrs)};
  }

  std::pair<ECM, std::vector<PathInfo>>
  listdir(const std::string &path, int timeout_ms = -1,
          int64_t start_time = -1, amf interrupt_flag = nullptr) override {
    ECM rcm = _precheck(path, interrupt_flag);

    if (rcm.first != EC::Success) {
      return {rcm, {}};
    }
    std::lock_guard<std::recursive_mutex> lock(mtx);
    start_time = start_time == -1 ? AMTime::miliseconds() : start_time;
    auto [rcm2, attr_list] =
        lib_listdir(path, timeout_ms, start_time, interrupt_flag);
    if (rcm2.first != EC::Success) {
      return {rcm2, {}};
    }
    std::vector<PathInfo> file_list(attr_list.size());
    for (size_t i = 0; i < attr_list.size(); i++) {
      file_list[i] = FormatStat(attr_list[i].first, attr_list[i].second);
    }
    return {rcm2, file_list};
  }

  // Create one-level directory (with AMFS::abspath)
  ECM mkdir(const std::string &path, int timeout_ms = -1,
            int64_t start_time = -1, amf interrupt_flag = nullptr) override {
    ECM rcm = _precheck(path, interrupt_flag);
    if (rcm.first != EC::Success) {
      return rcm;
    }
    std::lock_guard<std::recursive_mutex> lock(mtx);
    start_time = start_time == -1 ? AMTime::miliseconds() : start_time;
    auto [rcm2, attrs] =
        lib_getstat(path, false, timeout_ms, start_time, interrupt_flag);
    if (rcm2.first == EC::Success) {
      if (isdir(attrs)) {
        return {EC::Success, ""};
      } else {
        return {EC::PathAlreadyExists,
                AMStr::fmt("Path exists and is not a directory: {}", path)};
      }
    }
    return lib_mkdir(path, timeout_ms, start_time, interrupt_flag);
  }

  // Recursively create nested directories until error (with AMFS::abspath)
  ECM mkdirs(const std::string &path, int timeout_ms = -1,
             int64_t start_time = -1, amf interrupt_flag = nullptr) override {
    ECM rcm = _precheck(path, interrupt_flag);
    if (rcm.first != EC::Success) {
      return rcm;
    }
    std::lock_guard<std::recursive_mutex> lock(mtx);
    start_time = start_time == -1 ? AMTime::miliseconds() : start_time;
    std::vector<std::string> parts = AMPathStr::split(path);
    if (parts.empty()) {
      return {EC::InvalidArg,
              AMStr::fmt("Path split failed, get empty parts: {}", path)};
    } else if (parts.size() == 1) {
      return lib_mkdir(path, timeout_ms, start_time, interrupt_flag);
    }

    std::string current_path = parts.front();
    for (size_t i = 1; i < parts.size(); i++) {
      current_path = AMPathStr::join(current_path, parts[i], SepType::Unix);
      auto [rcm2, attrs] =
          lib_getstat(current_path, false, timeout_ms, start_time,
                      interrupt_flag);
      if (rcm2.first == EC::Success) {
        if (isdir(attrs)) {
          continue;
        } else {
          return {EC::PathAlreadyExists,
                  AMStr::fmt("Path exists and is not a directory: {}",
                             current_path)};
        }
      }
      rcm = lib_mkdir(current_path, timeout_ms, start_time, interrupt_flag);
      if (rcm.first != EC::Success) {
        return rcm;
      }
    }
    return rcm;
  }

  ECM rmfile(const std::string &path, int timeout_ms = -1,
             int64_t start_time = -1, amf interrupt_flag = nullptr) override {
    ECM rcm = _precheck(path, interrupt_flag);
    if (rcm.first != EC::Success) {
      return rcm;
    }
    std::lock_guard<std::recursive_mutex> lock(mtx);
    start_time = start_time == -1 ? AMTime::miliseconds() : start_time;
    return lib_unlink(path, timeout_ms, start_time, interrupt_flag);
  }

  ECM rmdir(const std::string &path, int timeout_ms = -1,
            int64_t start_time = -1, amf interrupt_flag = nullptr) override {
    ECM rcm = _precheck(path, interrupt_flag);
    if (rcm.first != EC::Success) {
      return rcm;
    }
    std::lock_guard<std::recursive_mutex> lock(mtx);
    start_time = start_time == -1 ? AMTime::miliseconds() : start_time;
    return lib_rmdir(path, timeout_ms, start_time, interrupt_flag);
  }

  // Delete file or directory (with AMFS::abspath)
  std::pair<ECM, RMR> remove(const std::string &path,
                             AMFS::WalkErrorCallback error_callback = nullptr,
                             int timeout_ms = -1, int64_t start_time = -1,
                             amf interrupt_flag = nullptr) override {
    ECM rcm0 = _precheck(path, interrupt_flag);
    if (rcm0.first != EC::Success) {
      if (error_callback && *error_callback) {
        (*error_callback)(path, rcm0);
      }
      return {rcm0, {}};
    }
    std::lock_guard<std::recursive_mutex> lock(mtx);
    RMR errors = {};
    auto [rcm, sr] =
        lib_getstat(path, false, timeout_ms, start_time, interrupt_flag);
    if (rcm.first != EC::Success) {
      if (error_callback && *error_callback) {
        (*error_callback)(path, rcm);
      }
      return {rcm, {}};
    }
    _rm(path, sr, errors, error_callback, timeout_ms, start_time,
        interrupt_flag);
    return {ECM{EC::Success, ""}, errors};
  }

  // Rename original path to new path (with AMFS::abspath)
  ECM rename(const std::string &src, const std::string &dst, bool mkdir = true,
             bool overwrite = false, int timeout_ms = -1,
             int64_t start_time = -1,
             amf interrupt_flag = nullptr) override {
    ECM rcm0 = _precheck(src, interrupt_flag);
    if (rcm0.first != EC::Success) {
      return rcm0;
    }
    ECM rcm1 = _precheck(dst, interrupt_flag);
    if (rcm1.first != EC::Success) {
      return rcm1;
    }
    std::lock_guard<std::recursive_mutex> lock(mtx);
    start_time = start_time == -1 ? AMTime::miliseconds() : start_time;
    if (mkdir) {
      rcm0 = mkdirs(AMPathStr::dirname(dst), timeout_ms, start_time,
                    interrupt_flag);
      if (rcm0.first != EC::Success) {
        return rcm0;
      }
    }
    return lib_rename(src, dst, overwrite, timeout_ms, start_time,
                      interrupt_flag);
  }

  // Safely delete file/dir by moving into trash_dir
  ECM saferm(const std::string &path, int timeout_ms = -1,
             int64_t start_time = -1,
             amf interrupt_flag = nullptr) override {
    ECM rcm0 = _precheck(path, interrupt_flag);
    if (rcm0.first != EC::Success) {
      return rcm0;
    }
    std::lock_guard<std::recursive_mutex> lock(mtx);
    start_time = start_time == -1 ? AMTime::miliseconds() : start_time;
    ConRequest request = request_atomic_.lock().load();
    if (request.trash_dir.empty()) {
      return {EC::InvalidArg, "Trash directory not set"};
    }
    auto [rcm1, info] =
        lib_getstat(path, false, timeout_ms, start_time, interrupt_flag);
    if (rcm1.first != EC::Success) {
      return rcm1;
    }
    std::string base = AMPathStr::basename(path);
    std::string base_name = base;
    std::string base_ext = "";
    std::string target_path;

    if (!isdir(info)) {
      auto base_info = AMPathStr::split_basename(base);
      base_name = base_info.first;
      base_ext = base_info.second;
    }

    // Get current time in format 2026-01-01-19-06
    std::string current_time =
        FormatTime(std::time(nullptr), "%Y-%m-%d-%H-%M-%S");

    target_path = AMPathStr::join(request.trash_dir, current_time,
                                  base_name + "." + base_ext);
    size_t i = 1;
    std::string base_name_tmp = base_name;

    while (true) {
      auto [rcm, _] = stat(target_path, false, timeout_ms, start_time,
                           interrupt_flag);
      if (rcm.first == EC::PathNotExist) {
        break;
      }
      if (rcm.first != EC::Success) {
        return rcm;
      }
      base_name_tmp = base_name + "(" + std::to_string(i) + ")";
      target_path = AMPathStr::join(request.trash_dir, current_time,
                                    (base_name_tmp + ".") += base_ext);
      i++;
    }

    rcm0 = mkdirs(AMPathStr::join(request.trash_dir, current_time), timeout_ms,
                  start_time, interrupt_flag);
    if (rcm0.first != EC::Success) {
      return rcm0;
    }

    return lib_rename(path, target_path, false, timeout_ms, start_time,
                      interrupt_flag);
  }

  // Move source path to destination folder

  /*
  ECM copy(const std::string &src, const std::string &dst,
           bool need_mkdir = false, int timeout_ms = -1) override {
    if (!sftp) {
      return ECM{EC::NoConnection, "SFTP not initialized"};
    }
    std::string srcf = src;
    std::string dstf = dst;
    if (srcf.empty() || dstf.empty()) {
      return std::make_pair(EC::InvalidArg,
                            AMStr::fmt("Invalid path: {} or {}", srcf,
  dstf));
    }
    auto [rcm, br] = exists(srcf);
    if (rcm.first != EC::Success) {
      return rcm;
    }
    if (!br) {
      return {EC::PathNotExist, AMStr::fmt("Src not exists: {}", srcf)};
    }

    auto [rcm2, br2] = is_dir(dstf);
    if (rcm2.first != EC::Success) {
      if (rcm2.first == EC::PathNotExist) {
        if (need_mkdir) {
          ECM ecm = mkdirs(dstf);
          if (ecm.first != EC::Success) {
            return ecm;
          }
        } else {
          return {EC::ParentDirectoryNotExist,
                  AMStr::fmt("Dst dir not exists: {}", dstf)};
        }
      }
    } else if (!br2) {
      return {EC::NotADirectory,
              AMStr::fmt("Dst exists but not a directory: {}", dstf)};
    }

    std::string dst_path = AMPathStr::join(dstf, AMPathStr::basename(srcf));
    auto [rcm0, sbr0] = exists(dst_path);

    if (rcm0.first != EC::Success) {
      return rcm0;
    }
    if (sbr0) {
      return {EC::PathAlreadyExists,
              AMStr::fmt("Dst {} already has path named {}", dstf,
                          AMPathStr::basename(srcf))};
    }

    std::string command = "cp -r \"" + srcf + "\" \"" + dstf + "\"";

    auto [rcm3, resp] = ConductCmd(command);

    if (rcm3.first != EC::Success) {
      return rcm3;
    }

    if (resp.second != 0) {
      std::string msg =
          AMStr::fmt("Copy cmd conducted failed with exit code: {}, error:
  {}", resp.second, resp.first); trace(TraceLevel::Error,
  EC::InhostCopyFailed, AMStr::fmt("{}@{}->{}", res_data.nickname, srcf,
  dstf), "Copy", msg); return {EC::InhostCopyFailed, msg};
    }

    return {EC::Success, ""};
  }*/

  // Recursively walk all files and nested dirs under a path, return
  // vector<PathInfo>
  std::pair<ECM, WRI> iwalk(const std::string &path, bool show_all = false,
                            bool ignore_sepcial_file = true,
                            AMFS::WalkErrorCallback error_callback = nullptr,
                            int timeout_ms = -1, int64_t start_time = -1,
                            amf interrupt_flag = nullptr) override {
    ECM rcm = _precheck(path, interrupt_flag);
    RMR errors = {};
    if (rcm.first != EC::Success) {
      if (error_callback && *error_callback) {
        (*error_callback)(path, rcm);
      }
      return {rcm, {WRV{}, errors}};
    }
    std::lock_guard<std::recursive_mutex> lock(mtx);
    start_time = start_time == -1 ? AMTime::miliseconds() : start_time;
    auto [rcm2, attrs] =
        lib_getstat(path, false, timeout_ms, start_time, interrupt_flag);
    if (rcm2.first != EC::Success) {
      if (error_callback && *error_callback) {
        (*error_callback)(path, rcm2);
      }
      errors.emplace_back(path, rcm2);
      return {rcm2, {WRV{}, errors}};
    }
    if (!isdir(attrs)) {
      if (!show_all && ignore_sepcial_file && !isreg(attrs)) {
        return {ECM{EC::Success, ""}, {WRV{}, errors}};
      }
      return {ECM{EC::Success, ""}, {WRV{FormatStat(path, attrs)}, errors}};
    }
    // get all files and deepest folders
    WRV result = {};
    _iwalk(path, attrs, result, errors, show_all, ignore_sepcial_file,
           error_callback, timeout_ms, start_time, interrupt_flag);
    if (this->IsOperationInterrupted_(interrupt_flag)) {
      ECM out = {EC::Terminate, "Interrupted by user"};
      if (error_callback && *error_callback) {
        (*error_callback)(path, out);
      }
      return {out, {result, errors}};
    }
    return {ECM{EC::Success, ""}, {result, errors}};
  }

  // Actual walk function, returns vector of ([root_path, part1, part2, ...],
  // PathInfo)
  std::pair<ECM, WRDR> walk(const std::string &path, int max_depth = -1,
                            bool show_all = false,
                            bool ignore_special_file = false,
                            AMFS::WalkErrorCallback error_callback = nullptr,
                            int timeout_ms = -1, int64_t start_time = -1,
                            amf interrupt_flag = nullptr) override {
    ECM rcm0 = _precheck(path, interrupt_flag);
    RMR errors = {};
    if (rcm0.first != EC::Success) {
      if (error_callback && *error_callback) {
        (*error_callback)(path, rcm0);
      }
      return {rcm0, {WRD{}, errors}};
    }
    std::lock_guard<std::recursive_mutex> lock(mtx);
    start_time = start_time == -1 ? AMTime::miliseconds() : start_time;
    auto [rcm, br] = stat(path, false, timeout_ms, start_time, interrupt_flag);
    if (rcm.first != EC::Success) {
      if (error_callback && *error_callback) {
        (*error_callback)(path, rcm);
      }
      errors.emplace_back(path, rcm);
      return {rcm, {WRD{}, errors}};
    } else if (br.type != PathType::DIR) {
      ECM out = {EC::NotADirectory, "Path is not a directory"};
      if (error_callback && *error_callback) {
        (*error_callback)(path, out);
      }
      errors.emplace_back(path, out);
      return {out, {WRD{}, errors}};
    }
    WRD result_dict = {};
    std::vector<std::string> parts = {path};
    _walk(parts, result_dict, errors, 0, max_depth, show_all,
          ignore_special_file, error_callback, timeout_ms, start_time,
          interrupt_flag);
    // Print type of result_dict
    if (this->IsOperationInterrupted_(interrupt_flag)) {
      ECM out = {EC::Terminate, "Interrupted by user, no action conducted"};
      if (error_callback && *error_callback) {
        (*error_callback)(path, out);
      }
      return {out, {result_dict, errors}};
    }
    return {ECM{EC::Success, ""}, {result_dict, errors}};
  }

  [[nodiscard]] bool IsInterrupted() const override {
    return control_part_ ? control_part_->IsInterrupted() : false;
  }

  OS_TYPE UpdateOSType(int timeout_ms = -1, int64_t start_time = -1,
                       amf interrupt_flag = nullptr) override {
    (void)timeout_ms;
    (void)start_time;
    (void)interrupt_flag;
    return UpdateOSTypeCache_(true);
  }

  std::string UpdateHomeDir(int timeout_ms = -1, int64_t start_time = -1,
                            amf interrupt_flag = nullptr) override {
    (void)timeout_ms;
    (void)start_time;
    (void)interrupt_flag;
    const std::string home_dir = UpdateHomeDirCache_();
    SetCachedHomeDir_(home_dir);
    return home_dir;
  }

  [[nodiscard]] std::pair<ECM, WRV>
  listdir(const std::string &path, int timeout_ms = -1,
          int64_t start_time = -1) const override {
    return const_cast<AMSFTPIOCore *>(this)->listdir(path, timeout_ms,
                                                     start_time, nullptr);
  }

  ECM copy(const std::string &src, const std::string &dst,
           bool need_mkdir = false, int timeout_ms = -1,
           amf interrupt_flag = nullptr) override {
    (void)src;
    (void)dst;
    (void)need_mkdir;
    (void)timeout_ms;
    (void)interrupt_flag;
    return {EC::OperationUnsupported,
            "SFTP client does not support server-side copy"};
  }

  [[nodiscard]] std::pair<ECM, WRI>
  iwalk(const std::string &path, bool show_all = false,
        bool ignore_special_file = true,
        AMFS::WalkErrorCallback error_callback = nullptr, int timeout_ms = -1,
        int64_t start_time = -1) const override {
    return const_cast<AMSFTPIOCore *>(this)->iwalk(
        path, show_all, ignore_special_file, error_callback, timeout_ms,
        start_time, nullptr);
  }

  int64_t getsize(const std::string &path, bool ignore_special_file = true,
                  int timeout_ms = -1, int64_t start_time = -1,
                  amf interrupt_flag = nullptr) override {
    auto [rcm, pack] =
        iwalk(path, true, ignore_special_file, nullptr, timeout_ms, start_time,
              interrupt_flag);
    if (rcm.first != EC::Success || IsOperationInterrupted_(interrupt_flag)) {
      return -1;
    }
    int64_t size = 0;
    for (const auto &item : pack.first) {
      size += static_cast<int64_t>(item.size);
    }
    return size;
  }

  std::vector<PathInfo> find(const std::string &path,
                             SearchType type = SearchType::All,
                             int timeout_ms = -1,
                             int64_t start_time = -1,
                             amf interrupt_flag = nullptr) override {
    if (IsOperationInterrupted_(interrupt_flag)) {
      return {};
    }
    return BasePathMatch::find(path, type, timeout_ms, start_time);
  }
};
