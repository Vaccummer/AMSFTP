#pragma once
// 标准库
#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <ctime>
#include <deque>
#include <fcntl.h>
#include <filesystem>
#include <memory>
#include <mutex>
#include <optional>
#include <pybind11/pytypes.h>
#include <string>
#include <thread>
#include <vector>

// 标准库

// 自身依赖
#include "AMBaseClient.hpp"
#include "AMDataClass.hpp"
#include "AMEnum.hpp"
#include "AMFTPClient.hpp"
#include "AMLocalClient.hpp"
#include "AMPath.hpp"
#include "AMSFTPClient.hpp"

// 第三方库
#include <libssh2.h>
#include <libssh2_sftp.h>

#include <curl/curl.h>
#include <fmt/core.h>
#include <magic_enum/magic_enum.hpp>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <pybind11/functional.h>
#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
// 第三方库

#ifdef _WIN32
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#define SOCKET int
#define INVALID_SOCKET -1
#define SOCKET_ERROR -1
#define closesocket close
#endif

class UnionFileHandle {
public:
  // Local file handle
#ifdef _WIN32
  HANDLE file_handle = INVALID_HANDLE_VALUE;
#else
  int file_handle = -1;
#endif

  // SFTP file handle
  LIBSSH2_SFTP_HANDLE *sftp_handle = nullptr;
  std::shared_ptr<AMSFTPClient> client = nullptr;

  // Common members
  std::string path;
  bool is_write = false;
  size_t file_size = 0;
  size_t offset = 0;
  bool is_sftp = false;

  ~UnionFileHandle() { Close(); }

  void Close() {
    if (is_sftp) {
      if (sftp_handle) {
        libssh2_sftp_close_handle(sftp_handle);
        sftp_handle = nullptr;
      }
    } else {
#ifdef _WIN32
      if (file_handle != INVALID_HANDLE_VALUE) {
        CloseHandle(file_handle);
        file_handle = INVALID_HANDLE_VALUE;
      }
#else
      if (file_handle != -1) {
        close(file_handle);
        file_handle = -1;
      }
#endif
    }
  }

  ECM Init(const std::string &path, size_t file_size,
           std::shared_ptr<AMSFTPClient> client = nullptr,
           bool is_write = false, bool sequential = true) {
    this->path = path;
    this->is_write = is_write;
    this->file_size = file_size;
    this->client = client;
    this->is_sftp = (client != nullptr);

    if (is_sftp) {
      // SFTP file
      if (is_write) {
        sftp_handle = libssh2_sftp_open(
            client->sftp, path.c_str(),
            LIBSSH2_FXF_TRUNC | LIBSSH2_FXF_WRITE | LIBSSH2_FXF_CREAT, 0744);
      } else {
        sftp_handle = libssh2_sftp_open(client->sftp, path.c_str(),
                                        LIBSSH2_FXF_READ, 0400);
      }
      if (!sftp_handle) {
        EC rc = client->GetLastEC();
        std::string msg = client->GetLastErrorMsg();
        return {rc, fmt::format("Open sftp file \"{}\" failed: {}", path, msg)};
      }
    } else {
      // Local file
#ifdef _WIN32
      DWORD access = is_write ? (GENERIC_READ | GENERIC_WRITE) : GENERIC_READ;
      DWORD share = is_write ? 0 : FILE_SHARE_READ;
      DWORD creation = is_write ? CREATE_ALWAYS : OPEN_EXISTING;
      DWORD flags =
          sequential ? FILE_FLAG_SEQUENTIAL_SCAN : FILE_ATTRIBUTE_NORMAL;

      file_handle = CreateFileW(AMStr::wstr(path).c_str(), access, share,
                                nullptr, creation, flags, nullptr);

      if (file_handle == INVALID_HANDLE_VALUE) {
        return {EC::LocalFileOpenError,
                fmt::format("Failed to open local file \"{}\": error code {}",
                            path, GetLastError())};
      }
#else
      int flags = is_write ? (O_RDWR | O_CREAT | O_TRUNC) : O_RDONLY;
      file_handle = open(path.c_str(), flags, 0644);

      if (file_handle == -1) {
        return {EC::LocalFileOpenError,
                fmt::format("Failed to open local file \"{}\": {}", path,
                            strerror(errno))};
      }
#endif
    }

    return {EC::Success, ""};
  }

  bool IsValid() const {
    if (is_sftp) {
      return sftp_handle != nullptr;
    } else {
#ifdef _WIN32
      return file_handle != INVALID_HANDLE_VALUE;
#else
      return file_handle != -1;
#endif
    }
  }

  std::pair<ssize_t, ECM> Read(std::shared_ptr<StreamRingBuffer> ring_buffer) {
    if (!IsValid()) {
      return {-1, {EC::LocalFileOpenError, "File not initialized"}};
    }

    auto [write_ptr, max_write] = ring_buffer->get_write_ptr();
    ssize_t to_read =
        max_write > file_size - offset ? file_size - offset : max_write;
    ssize_t bytes_read;
    if (to_read > 0) {
      if (is_sftp) {
        // SFTP read
        bytes_read = libssh2_sftp_read(sftp_handle, write_ptr, to_read);
        if (bytes_read > 0) {
          ring_buffer->commit_write(bytes_read);
          offset += bytes_read;
          return {bytes_read, {EC::Success, ""}};
        } else if (bytes_read == 0) {
          return {0, {EC::EndOfFile, "End of file"}};
        } else if (bytes_read == LIBSSH2_ERROR_EAGAIN) {
          return {LIBSSH2_ERROR_EAGAIN, {EC::SSHEAGAIN, "SSH EAGAIN"}};
        } else {
          EC rc = client->GetLastEC();
          std::string msg = client->GetLastErrorMsg();
          return {
              bytes_read,
              {rc, fmt::format("Read sftp file \"{}\" failed: {}", path, msg)}};
        }
      } else {
        // Local file read
#ifdef _WIN32
        DWORD bytes_read = 0;
        if (!ReadFile(file_handle, write_ptr, static_cast<DWORD>(to_read),
                      &bytes_read, nullptr)) {
          return {-1,
                  {EC::LocalFileReadError,
                   fmt::format("Read local file \"{}\" failed: error code {}",
                               path, GetLastError())}};
        }
        if (bytes_read > 0) {
          ring_buffer->commit_write(bytes_read);
          offset += bytes_read;
          return {static_cast<int>(bytes_read), {EC::Success, ""}};
        } else {
          return {0, {EC::EndOfFile, "End of file"}};
        }
#else
        ssize_t bytes_read = read(file_handle, write_ptr, to_read);
        if (bytes_read > 0) {
          ring_buffer->commit_write(bytes_read);
          offset += bytes_read;
          return {static_cast<int>(bytes_read), {EC::Success, ""}};
        } else if (bytes_read == 0) {
          return {0, {EC::EndOfFile, "End of file"}};
        } else {
          return {-1,
                  {EC::LocalFileReadError,
                   fmt::format("Read local file \"{}\" failed: {}", path,
                               strerror(errno))}};
        }
#endif
      }
    }
    return {0, {EC::Success, ""}};
  }

  std::pair<ssize_t, ECM> Write(std::shared_ptr<StreamRingBuffer> ring_buffer) {
    if (!IsValid()) {
      return {-1, {EC::LocalFileOpenError, "File not initialized"}};
    }

    auto [read_ptr, max_read] = ring_buffer->get_read_ptr();
    ssize_t to_write =
        max_read > file_size - offset ? file_size - offset : max_read;
    ssize_t bytes_written;
    if (to_write > 0) {
      if (is_sftp) {
        // SFTP write
        std::lock_guard<std::recursive_mutex> lock(client->mtx);
        bytes_written = libssh2_sftp_write(sftp_handle, read_ptr, to_write);
        if (bytes_written > 0) {
          ring_buffer->commit_read(bytes_written);
          offset += bytes_written;
          return {bytes_written, {EC::Success, ""}};
        } else if (bytes_written == 0) {
          return {0, {EC::EndOfFile, "End of file"}};
        } else if (bytes_written == LIBSSH2_ERROR_EAGAIN) {
          return {LIBSSH2_ERROR_EAGAIN, {EC::SSHEAGAIN, "SSH EAGAIN"}};
        } else {
          EC rc = client->GetLastEC();
          std::string msg = client->GetLastErrorMsg();
          return {bytes_written,
                  {rc, fmt::format("Write sftp file \"{}\" failed: {}", path,
                                   msg)}};
        }
      } else {
        // Local file write
#ifdef _WIN32
        DWORD bytes_written = 0;
        if (!WriteFile(file_handle, read_ptr, static_cast<DWORD>(to_write),
                       &bytes_written, nullptr)) {
          return {-1,
                  {EC::LocalFileWriteError,
                   fmt::format("Write local file \"{}\" failed: error code {}",
                               path, GetLastError())}};
        }
        if (bytes_written > 0) {
          ring_buffer->commit_read(bytes_written);
          offset += bytes_written;
          return {static_cast<int>(bytes_written), {EC::Success, ""}};
        } else {
          return {0, {EC::EndOfFile, "End of file"}};
        }
#else
        ssize_t bytes_written = write(file_handle, read_ptr, to_write);
        if (bytes_written > 0) {
          ring_buffer->commit_read(bytes_written);
          offset += bytes_written;
          return {static_cast<int>(bytes_written), {EC::Success, ""}};
        } else if (bytes_written == 0) {
          return {0, {EC::EndOfFile, "End of file"}};
        } else {
          return {-1,
                  {EC::LocalFileWriteError,
                   fmt::format("Write local file \"{}\" failed: {}", path,
                               strerror(errno))}};
        }
#endif
      }
    }
    return {0, {EC::Success, ""}};
  }
};

using AMCilent =
    std::variant<std::shared_ptr<AMSFTPClient>, std::shared_ptr<AMFTPClient>,
                 std::shared_ptr<AMLocalClient>>;
using ECM = std::pair<ErrorCode, std::string>;
using EC = ErrorCode;

inline std::optional<AMCilent>
CreateClient(const ConRequst &requeset, ClientProtocol protocol,
             ssize_t trace_num = 10, py::object trace_cb = py::none(),
             ssize_t buffer_size = 8 * AMMB, std::vector<std::string> keys = {},
             py::object auth_cb = py::none()) {
  if (protocol == ClientProtocol::SFTP) {
    auto client = std::make_shared<AMSFTPClient>(requeset, keys, trace_num,
                                                 trace_cb, auth_cb);
    client->TransferRingBufferSize(buffer_size);
    return client;
  } else if (protocol == ClientProtocol::FTP) {
    auto client = std::make_shared<AMFTPClient>(requeset, trace_num, trace_cb);
    client->TransferRingBufferSize(buffer_size);
    return client;
  } else {
    return std::nullopt;
  }
}

class ClientMaintainer {
private:
  std::unordered_map<std::string, std::shared_ptr<BaseClient>> hosts;
  std::atomic<bool> is_heartbeat;
  std::thread heartbeat_thread;
  py::function disconnect_cb;
  bool is_disconnect_cb = false;
  std::recursive_mutex beat_mtx;

  void HeartbeatAct(int interval_s) {
    int millsecond = 0;
    ECM rcm;
    while (true) {
      // 遍历hosts字典
      {
        std::lock_guard<std::recursive_mutex> lock(beat_mtx);
        for (auto &host : hosts) {
          rcm = host.second->Check();
          if (rcm.first != EC::Success) {
            if (is_disconnect_cb) {
              py::gil_scoped_acquire acquire;
              disconnect_cb(host.second, rcm);
            }
          }
        }
      }
      while (millsecond < interval_s * 1000) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        millsecond += 100;
        if (!is_heartbeat.load()) {
          return;
        }
      }
      millsecond = 0;
    }
  }

public:
  std::shared_ptr<AMLocalClient> local_client;
  ~ClientMaintainer() {
    is_heartbeat.store(false);
    if (heartbeat_thread.joinable()) {
      heartbeat_thread.join();
    }
  }

  std::shared_ptr<BaseClient> GetHost(const std::string &nickname) {
    if (nickname.empty()) {
      return local_client;
    }

    if (hosts.find(nickname) == hosts.end()) {
      return nullptr;
    }
    return hosts[nickname];
  }

  ClientMaintainer(int heartbeat_interval_s = 60,
                   py::object disconnect_cb = py::none()) {
    // 初始化本地客户端
    this->local_client =
        std::make_shared<AMLocalClient>(ConRequst("local", "", ""));
    this->is_heartbeat.store(true);
    heartbeat_thread = std::thread(
        [this, heartbeat_interval_s]() { HeartbeatAct(heartbeat_interval_s); });
    if (!disconnect_cb.is_none()) {
      this->disconnect_cb = py::cast<py::function>(disconnect_cb);
      this->is_disconnect_cb = true;
    }
  }

  std::vector<std::string> get_nicknames() {
    std::vector<std::string> host_list;
    for (auto &host : hosts) {
      host_list.push_back(host.first);
    }
    return host_list;
  }

  std::optional<AMCilent> get_client(const std::string &nickname) {
    if (nickname.empty()) {
      return local_client;
    }
    if (hosts.find(nickname) == hosts.end()) {
      return std::nullopt;
    }
    auto client = hosts[nickname];
    if (client->GetProtocol() == ClientProtocol::SFTP) {
      return std::dynamic_pointer_cast<AMSFTPClient>(client);
    } else if (client->GetProtocol() == ClientProtocol::FTP) {
      return std::dynamic_pointer_cast<AMFTPClient>(client);
    } else if (client->GetProtocol() == ClientProtocol::LOCAL) {
      return std::dynamic_pointer_cast<AMLocalClient>(client);
    }
    return std::nullopt;
  }

  std::vector<AMCilent> get_clients() {
    std::vector<AMCilent> client_list;
    for (auto &host : hosts) {
      if (host.second->GetProtocol() == ClientProtocol::SFTP) {
        client_list.emplace_back(
            std::dynamic_pointer_cast<AMSFTPClient>(host.second));
      } else if (host.second->GetProtocol() == ClientProtocol::FTP) {
        client_list.emplace_back(
            std::dynamic_pointer_cast<AMFTPClient>(host.second));
      }
    }
    return client_list;
  }

  void add_client(const std::string &nickname,
                  std::shared_ptr<BaseClient> client, bool overwrite = false) {
    if (nickname.empty()) {
      return;
    }
    std::lock_guard<std::recursive_mutex> lock(beat_mtx);
    if (hosts.find(nickname) != hosts.end()) {
      if (!overwrite) {
        return;
      }
      hosts.erase(nickname);
    }
    hosts[nickname] = std::dynamic_pointer_cast<BaseClient>(client);
  }

  // void add_client(const std::string &nickname,
  //                 std::shared_ptr<AMFTPClient> client, bool overwrite =
  //                 false) {
  //   std::lock_guard<std::recursive_mutex> lock(beat_mtx);
  //   if (hosts.find(nickname) != hosts.end()) {
  //     if (!overwrite) {
  //       return;
  //     }
  //     hosts.erase(nickname);
  //   }
  //   hosts[nickname] = std::dynamic_pointer_cast<BaseClient>(client);
  // }

  void remove_client(const std::string &nickname) {
    if (nickname.empty()) {
      // 不允许删除默认本地客户端
      return;
    }
    std::lock_guard<std::recursive_mutex> lock(beat_mtx);
    if (hosts.find(nickname) != hosts.end()) {
      hosts.erase(nickname);
    }
  }

  std::pair<ECM, std::shared_ptr<BaseClient>>
  test_client(const std::string &nickname, bool update = false,
              amf interrupt_flag = nullptr, int timeout_ms = -1,
              int64_t start_time = -1) {
    if (nickname.empty()) {
      return {ECM{EC::Success, ""}, local_client};
    }
    start_time = start_time == -1 ? am_ms() : start_time;
    ;
    if (hosts.find(nickname) == hosts.end()) {
      return {ECM{EC::ClientNotFound,
                  fmt::format("Client not found: {}", nickname)},
              nullptr};
    }
    if (!update) {
      ECM rcm = hosts[nickname]->GetState();
      if (rcm.first != EC::Success) {
        return {hosts[nickname]->Check(interrupt_flag, timeout_ms, start_time),
                hosts[nickname]};
      } else {
        return {rcm, hosts[nickname]};
      }
    } else {
      return {hosts[nickname]->Check(interrupt_flag, timeout_ms, start_time),
              hosts[nickname]};
    }
  }

  void SetDisconnectCallback(py::object callback = py::none()) {
    std::lock_guard<std::recursive_mutex> lock(beat_mtx);
    if (callback.is_none()) {
      is_disconnect_cb = false;
      disconnect_cb = py::function();
    } else {
      is_disconnect_cb = true;
      disconnect_cb = py::cast<py::function>(callback);
    }
  };
};

// ============================================================================
// AMWorkManager - Enhanced worker with task queue and async transfer support
// ============================================================================
class AMWorkManager {
private:
  std::thread worker_thread;
  std::atomic<bool> running{true};
  std::mutex queue_mtx;
  std::condition_variable queue_cv;
  std::deque<std::shared_ptr<TaskInfo>> task_queue;
  std::mutex result_mtx;
  std::unordered_map<uint64_t, std::shared_ptr<TaskInfo>> results;
  std::mutex conducting_mtx;
  std::shared_ptr<TaskInfo> conducting_task; // Currently executing task
  size_t chunk_size = 256 * AMKB;

  // Internal progress callback wrapper
  void InnerCallback(std::shared_ptr<TaskInfo> task_info, WkProgressData &pd,
                     bool force = false) {
    if (task_info->callback.need_progress_cb && task_info->cur_task) {
      auto time_now = timenow();
      if (force ||
          ((time_now - pd.cb_time) > task_info->callback.cb_interval_s)) {
        pd.cb_time = time_now;
        ECM cb_error = {EC::Success, ""};
        auto ctrl_opt = task_info->callback.CallProgress(
            ProgressCBInfo(task_info->cur_task->src, task_info->cur_task->dst,
                           task_info->cur_task->src_host,
                           task_info->cur_task->dst_host,
                           task_info->cur_task->transferred,
                           task_info->cur_task->size,
                           task_info->total_transferred_size,
                           task_info->total_size),
            &cb_error);
        if (cb_error.first != EC::Success &&
            task_info->callback.need_error_cb) {
          task_info->callback.error_cb(ErrorCBInfo(
              cb_error, task_info->cur_task->src, task_info->cur_task->dst,
              task_info->cur_task->src_host, task_info->cur_task->dst_host));
        }
        if (ctrl_opt.has_value()) {
          switch (*ctrl_opt) {
          case TransferControl::Running:
            pd.set_running();
            break;
          case TransferControl::Pause:
            pd.set_pause();
            break;
          case TransferControl::Terminate:
            pd.set_terminate();
            break;
          default:
            break;
          }
        }
      }
    }
  }

  // Check if task should be skipped (terminated before conducting)
  bool ShouldSkipTask(std::shared_ptr<TaskInfo> task_info) {
    if (task_info->pd && task_info->pd->is_terminate()) {
      task_info->rcm = {EC::Terminate, "Task terminated before start"};
      task_info->status = TaskStatus::Finished;
      task_info->finished_time = timenow();
      return true;
    }
    return false;
  }

  ssize_t CalculateBufferSize(std::shared_ptr<BaseClient> src_client,
                              std::shared_ptr<BaseClient> dst_client,
                              ssize_t provided_size) {
    ssize_t src_size = src_client ? src_client->TransferRingBufferSize() : -1;
    ssize_t dst_size = dst_client ? dst_client->TransferRingBufferSize() : -1;
    bool is_local = !src_client && !dst_client;
    if (provided_size > AMMinBufferSize && provided_size < AMMaxBufferSize) {
      return provided_size;
    } else if (src_size < 0 && dst_size < 0) {
      if (is_local) {
        return AMDefaultLocalBufferSize;
      } else {
        return AMDefaultRemoteBufferSize;
      }
    } else if (src_size > 0 && dst_size < 0) {
      return std::max<ssize_t>(std::min<ssize_t>(src_size, AMMaxBufferSize),
                               AMMinBufferSize);
    } else if (src_size > 0 && dst_size > 0) {
      return std::max<ssize_t>(
          std::min<ssize_t>({src_size, dst_size, AMMaxBufferSize}),
          AMMinBufferSize);
    } else {
      return std::max<ssize_t>(std::min<ssize_t>(dst_size, AMMaxBufferSize),
                               AMMinBufferSize);
    }
  }

  std::tuple<ECM, std::shared_ptr<BaseClient>, std::shared_ptr<BaseClient>>
  TestHost(const TransferTask &task,
           const std::shared_ptr<ClientMaintainer> &hostm) {
    std::shared_ptr<BaseClient> src_client = nullptr;
    std::shared_ptr<BaseClient> dst_client = nullptr;
    ECM rcm = ECM{EC::Success, ""};
    if (!task.src_host.empty()) {
      src_client = hostm->GetHost(task.src_host);
      if (!src_client) {
        return {ECM{EC::NoSession,
                    fmt::format("Source host \"{}\" not found", task.src_host)},
                nullptr, nullptr};
      }
      rcm = src_client->Check();
      if (rcm.first != EC::Success) {
        return {
            ECM{rcm.first, fmt::format("Source host \"{}\" connection error",
                                       task.src_host)},
            nullptr, nullptr};
      }
    } else {
      src_client = hostm->local_client;
    }
    if (!task.dst_host.empty()) {
      dst_client = hostm->GetHost(task.dst_host);
      if (!dst_client) {
        return {
            ECM{EC::NoSession, fmt::format("Destination host \"{}\" not found",
                                           task.dst_host)},
            nullptr, nullptr};
      }
      rcm = dst_client->Check();
      if (rcm.first != EC::Success) {
        return {ECM{rcm.first,
                    fmt::format("Destination host \"{}\" connection error",
                                task.dst_host)},
                nullptr, nullptr};
      }
    } else {
      dst_client = hostm->local_client;
    }
    return {rcm, src_client, dst_client};
  }

  // Transit for SFTP same-host copy (blocking mode)
  ECM Transit(std::shared_ptr<AMSFTPClient> client,
              std::shared_ptr<TaskInfo> task_info) {
    auto &pd = *(task_info->pd);
    auto *task = task_info->cur_task;
    ECM rcm = ECM{EC::Success, ""};
    std::lock_guard<std::recursive_mutex> lock(client->mtx);
    rcm = client->mkdir(AMPathStr::dirname(task->dst));
    if (rcm.first != EC::Success) {
      return rcm;
    }

    LIBSSH2_SFTP_HANDLE *srcFile = libssh2_sftp_open(
        client->sftp, task->src.c_str(), LIBSSH2_FXF_READ, 0400);
    if (!srcFile) {
      EC rc = client->GetLastEC();
      std::string msg = client->GetLastErrorMsg();
      return {rc, fmt::format("Failed to open src file \"{}\": {}", task->src,
                              msg)};
    }

    LIBSSH2_SFTP_HANDLE *dstFile = libssh2_sftp_open(
        client->sftp, task->dst.c_str(),
        LIBSSH2_FXF_WRITE | LIBSSH2_FXF_CREAT | LIBSSH2_FXF_TRUNC, 0744);
    if (!dstFile) {
      libssh2_sftp_close_handle(srcFile);
      EC rc = client->GetLastEC();
      std::string msg = client->GetLastErrorMsg();
      return {rc, fmt::format("Failed to open dst file \"{}\": {}", task->dst,
                              msg)};
    }

    libssh2_session_set_blocking(client->session, 1);
    std::vector<char> buffer(chunk_size);
    uint64_t total_written = 0;
    ssize_t bytes_read, bytes_written;

    while (total_written < task->size) {
      if (pd.is_terminate()) {
        rcm = {EC::Terminate, "Transfer interrupted by user"};
        goto clean;
      }
      while (pd.is_pause() && !pd.is_terminate()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
      }

      size_t to_read = std::min<size_t>(chunk_size, task->size - total_written);
      size_t buffer_filled = 0;
      while (buffer_filled < to_read) {
        bytes_read = libssh2_sftp_read(srcFile, buffer.data() + buffer_filled,
                                       to_read - buffer_filled);
        if (bytes_read > 0) {
          buffer_filled += bytes_read;
        } else if (bytes_read == 0) {
          break;
        } else {
          EC rc = client->GetLastEC();
          std::string msg = client->GetLastErrorMsg();
          rcm = {rc, fmt::format("Read error: {}", msg)};
          goto clean;
        }
      }

      if (buffer_filled == 0) {
        break;
      }

      size_t buffer_written = 0;
      while (buffer_written < buffer_filled) {
        bytes_written =
            libssh2_sftp_write(dstFile, buffer.data() + buffer_written,
                               buffer_filled - buffer_written);
        if (bytes_written > 0) {
          buffer_written += bytes_written;
          total_written += bytes_written;
          task_info->total_transferred_size += bytes_written;
          task->transferred = total_written;
          InnerCallback(task_info, pd, false);
        } else if (bytes_written == 0) {
          break;
        } else {
          EC rc = client->GetLastEC();
          std::string msg = client->GetLastErrorMsg();
          rcm = {rc, fmt::format("Write error: {}", msg)};
          goto clean;
        }
      }
    }

  clean:
    if (srcFile) {
      libssh2_sftp_close_handle(srcFile);
    }
    if (dstFile) {
      libssh2_sftp_close_handle(dstFile);
    }
    InnerCallback(task_info, pd, true);
    return rcm;
  }

  // XToBuffer - read from source to ring buffer
  void XToBuffer(std::shared_ptr<BaseClient> client,
                 std::shared_ptr<TaskInfo> task_info) {
    auto &pd = *(task_info->pd);
    auto *task = task_info->cur_task;
    if (client->GetProtocol() == ClientProtocol::SFTP) {
      UnionFileHandle file_handle;
      auto clientf = std::static_pointer_cast<AMSFTPClient>(client);
      ECM rcm = file_handle.Init(task->src, task->size, clientf, false, true);
      if (rcm.first != EC::Success) {
        pd.set_terminate();
        task->rcm = rcm;
        return;
      }
      std::lock_guard<std::recursive_mutex> lock(clientf->mtx);
      while (file_handle.offset < file_handle.file_size && !pd.is_terminate()) {
        while (pd.ring_buffer->writable() == 0 && !pd.is_terminate() &&
               file_handle.offset < file_handle.file_size) {
          std::this_thread::sleep_for(std::chrono::milliseconds(20));
        }
        while (pd.is_pause() && !pd.is_terminate()) {
          std::this_thread::sleep_for(std::chrono::milliseconds(20));
        }
        if (pd.is_terminate()) {
          return;
        }
        auto [bytes_read, ecm] = file_handle.Read(pd.ring_buffer);
        if (ecm.first != EC::Success && ecm.first != EC::EndOfFile) {
          pd.set_terminate();
          task->rcm = ecm;
          return;
        }
      }
    } else if (client->GetProtocol() == ClientProtocol::LOCAL) {
      UnionFileHandle file_handle;
      ECM rcm = file_handle.Init(task->src, task->size, nullptr, false, true);
      if (rcm.first != EC::Success) {
        pd.set_terminate();
        task->rcm = rcm;
        return;
      }
      while (file_handle.offset < file_handle.file_size && !pd.is_terminate()) {
        while (pd.ring_buffer->writable() == 0 && !pd.is_terminate() &&
               file_handle.offset < file_handle.file_size) {
          std::this_thread::sleep_for(std::chrono::milliseconds(20));
        }
        while (pd.is_pause() && !pd.is_terminate()) {
          std::this_thread::sleep_for(std::chrono::milliseconds(20));
        }
        if (pd.is_terminate()) {
          return;
        }
        auto [bytes_read, ecm] = file_handle.Read(pd.ring_buffer);
        if (ecm.first != EC::Success && ecm.first != EC::EndOfFile) {
          pd.set_terminate();
          task->rcm = ecm;
          return;
        }
      }
    } else if (client->GetProtocol() == ClientProtocol::FTP) {
      auto client_ftp = std::static_pointer_cast<AMFTPClient>(client);
      ECM out_rcm;
      FTPDownloadSet(client_ftp, task->src, FTPToBufferWk, &pd);
      if (out_rcm.first != EC::Success) {
        pd.set_terminate();
        task->rcm = out_rcm;
      }
    }
  }

  // BufferToX - write from ring buffer to destination
  void BufferToX(std::shared_ptr<BaseClient> client,
                 std::shared_ptr<TaskInfo> task_info) {
    auto &pd = *(task_info->pd);
    auto *task = task_info->cur_task;
    if (client->GetProtocol() == ClientProtocol::SFTP) {
      UnionFileHandle file_handle;
      auto clientf = std::static_pointer_cast<AMSFTPClient>(client);
      ECM rcm = file_handle.Init(task->dst, task->size, clientf, true, true);
      if (rcm.first != EC::Success) {
        pd.set_terminate();
        task->rcm = rcm;
        return;
      }
      while (file_handle.offset < file_handle.file_size && !pd.is_terminate()) {
        while (pd.ring_buffer->available() == 0 && !pd.is_terminate()) {
          std::this_thread::sleep_for(std::chrono::milliseconds(20));
        }
        while (pd.is_pause() && !pd.is_terminate()) {
          std::this_thread::sleep_for(std::chrono::milliseconds(20));
        }
        if (pd.is_terminate()) {
          return;
        }
        auto [bytes_write, ecm] = file_handle.Write(pd.ring_buffer);
        if (ecm.first != EC::Success && ecm.first != EC::EndOfFile) {
          pd.set_terminate();
          task->rcm = ecm;
          return;
        }
        task_info->total_transferred_size += bytes_write;
        task->transferred = file_handle.offset;
        InnerCallback(task_info, pd, false);
      }
    } else if (client->GetProtocol() == ClientProtocol::LOCAL) {
      UnionFileHandle file_handle;
      ECM rcm = file_handle.Init(task->dst, task->size, nullptr, true, true);
      if (rcm.first != EC::Success) {
        pd.set_terminate();
        task->rcm = rcm;
        return;
      }
      while (file_handle.offset < file_handle.file_size && !pd.is_terminate()) {
        while (pd.ring_buffer->available() == 0 && !pd.is_terminate()) {
          std::this_thread::sleep_for(std::chrono::milliseconds(20));
        }
        while (pd.is_pause() && !pd.is_terminate()) {
          std::this_thread::sleep_for(std::chrono::milliseconds(20));
        }
        if (pd.is_terminate()) {
          return;
        }
        auto [bytes_write, ecm] = file_handle.Write(pd.ring_buffer);
        if (ecm.first != EC::Success && ecm.first != EC::EndOfFile) {
          pd.set_terminate();
          task->rcm = ecm;
          return;
        }
        task_info->total_transferred_size += bytes_write;
        task->transferred = file_handle.offset;
        InnerCallback(task_info, pd, false);
      }
    } else if (client->GetProtocol() == ClientProtocol::FTP) {
      auto client_ftp = std::static_pointer_cast<AMFTPClient>(client);
      ECM out_rcm;
      FTPUploadSet(client_ftp, task->dst, task_info->pd.get(), BufferToFTPWk);
      if (out_rcm.first != EC::Success) {
        pd.set_terminate(); 
        task->rcm = out_rcm;
      }
    }
  }

  // Static callbacks for FTP using WkProgressData
  static size_t BufferToFTPWk(char *ptr, size_t size, size_t nmemb,
                              void *userdata) {
    auto *pd = static_cast<WkProgressData *>(userdata);
    while (true) {
      if (pd->is_terminate()) {
        return CURL_READFUNC_ABORT;
      }
      while (pd->is_pause() && !pd->is_terminate()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
      }
      // Check if transfer complete
      auto ti = pd->task_info.lock();
      if (ti && ti->cur_task &&
          ti->cur_task->transferred >= ti->cur_task->size) {
        return 0;
      }
      if (pd->ring_buffer->available() == 0) {
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
        continue;
      }
      auto [read_ptr, read_len] = pd->ring_buffer->get_read_ptr();
      ssize_t to_read = read_len > size * nmemb ? size * nmemb : read_len;
      if (to_read > 0) {
        try {
          memcpy(ptr, read_ptr, to_read);
          pd->ring_buffer->commit_read(to_read);
          if (ti && ti->cur_task) {
            ti->cur_task->transferred += to_read;
            ti->total_transferred_size += to_read;
          }
          return to_read;
        } catch (const std::exception &e) {
          pd->set_terminate();
          if (ti && ti->cur_task)
            ti->cur_task->rcm = ECM{EC::BufferReadError, e.what()};
          return CURL_READFUNC_ABORT;
        }
      } else if (to_read < 0) {
        pd->set_terminate();
        if (ti && ti->cur_task)
          ti->cur_task->rcm =
              ECM{EC::BufferReadError, "Get negative value for data size"};
        return CURL_READFUNC_ABORT;
      }
    }
  }

  static size_t FTPToBufferWk(char *ptr, size_t size, size_t nmemb,
                              void *userdata) {
    auto *pd = static_cast<WkProgressData *>(userdata);
    size_t total = size * nmemb;
    size_t written = 0;
    while (written < total) {
      if (pd->is_terminate()) {
        return 0;
      }
      while (pd->is_pause() && !pd->is_terminate()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
      }
      while (pd->ring_buffer->writable() == 0 && !pd->is_terminate()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
      }
      if (pd->is_terminate()) {
        return 0;
      }
      auto [write_ptr, write_len] = pd->ring_buffer->get_write_ptr();
      size_t remaining = total - written;
      size_t to_write = std::min<size_t>(write_len, remaining);
      if (to_write > 0) {
        try {
          memcpy(write_ptr, ptr + written, to_write);
          pd->ring_buffer->commit_write(to_write);
          written += to_write;
        } catch (const std::exception &e) {
          pd->set_terminate();
          auto ti = pd->task_info.lock();
          if (ti && ti->cur_task)
            ti->cur_task->rcm = ECM{EC::BufferWriteError, e.what()};
          return 0;
        }
      }
    }
    return total;
  }

  // Upload with ProgressData (legacy - for AMSFTPWorker)
  static void FTPUploadSet(std::shared_ptr<AMFTPClient> client,
                           const std::string &dst, WkProgressData *pd,
                           curl_read_callback read_callback) {
    std::lock_guard<std::recursive_mutex> lock(client->mtx);
    ECM ecm = client->SetupPath(dst, false);
    if (ecm.first != EC::Success) {
      pd->task_info.lock()->cur_task->rcm = ecm;
      pd->set_terminate();
      return;
    }
    CURL *curl = client->GetCURL();
    curl_easy_setopt(curl, CURLOPT_UPLOAD, 1L);
    curl_easy_setopt(curl, CURLOPT_READFUNCTION, read_callback);
    curl_easy_setopt(curl, CURLOPT_READDATA, pd);
    curl_easy_setopt(curl, CURLOPT_INFILESIZE_LARGE,
                     (curl_off_t)pd->task_info.lock()->cur_task->size);
    curl_easy_setopt(curl, CURLOPT_FTP_CREATE_MISSING_DIRS, CURLFTP_CREATE_DIR);

    CURLcode res = curl_easy_perform(curl);

    if (res == CURLE_ABORTED_BY_CALLBACK || res == CURLE_WRITE_ERROR) {
      pd->set_terminate();
    } else if (res != CURLE_OK) {
      pd->task_info.lock()->cur_task->rcm =
          ECM{EC::FTPUploadFailed,
              fmt::format("Upload failed: {}", curl_easy_strerror(res))};
      pd->set_terminate();
    }
  }

  // Download with ProgressData (legacy - for AMSFTPWorker)
  static void FTPDownloadSet(std::shared_ptr<AMFTPClient> client,
                             const std::string &src,
                             curl_write_callback write_callback,
                             WkProgressData *pd) {
    std::lock_guard<std::recursive_mutex> lock(client->mtx);
    ECM ecm = client->SetupPath(src, false);
    if (ecm.first != EC::Success) {
      pd->task_info.lock()->cur_task->rcm = ecm;
      pd->set_terminate();
      return;
    }
    auto curl = client->GetCURL();
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, pd);
    CURLcode res = curl_easy_perform(curl);
    if (res == CURLE_ABORTED_BY_CALLBACK || res == CURLE_WRITE_ERROR) {
      pd->set_terminate();
    } else if (res != CURLE_OK) {
      pd->task_info.lock()->cur_task->rcm =
          ECM{EC::FTPDownloadFailed,
              fmt::format("Download failed: {}", curl_easy_strerror(res))};
      pd->set_terminate();
    }
  }

  // Single file transfer
  ECM TransferSingleFile(std::shared_ptr<BaseClient> src_client,
                         std::shared_ptr<BaseClient> dst_client,
                         std::shared_ptr<TaskInfo> task_info) {
    auto &pd = *(task_info->pd);
    auto *task = task_info->cur_task;
    if (src_client->GetUID() == dst_client->GetUID()) {
      if (src_client->GetProtocol() == ClientProtocol::SFTP) {
        return this->Transit(std::static_pointer_cast<AMSFTPClient>(src_client),
                             task_info);
      } else if (src_client->GetProtocol() == ClientProtocol::FTP) {
        auto client_ftp = std::static_pointer_cast<AMFTPClient>(src_client);
        if (!client_ftp->mirror_client) {
          client_ftp->mirror_client =
              std::make_shared<AMFTPClient>(src_client->GetRequest());
        }
        ECM ecm = client_ftp->mirror_client->Connect(false, nullptr, 5000);
        if (ecm.first != EC::Success) {
          return ecm;
        }
        dst_client = client_ftp->mirror_client;
      }
    }

    std::thread reading_thread(
        [&]() { this->XToBuffer(src_client, task_info); });
    this->BufferToX(dst_client, task_info);
    pd.set_terminate();

    if (reading_thread.joinable()) {
      reading_thread.join();
    }

    if (task->rcm.first != EC::Success) {
      return task->rcm;
    }
    if (task->transferred >= task->size) {
      return task->rcm;
    }
    return {EC::UnknownError, "Task not finished but exited unexpectedly"};
  }

  // Execute a single TaskInfo
  void ExecuteTask(std::shared_ptr<TaskInfo> task_info) {
    task_info->status = TaskStatus::Conducting;
    task_info->start_time = timenow();

    if (task_info->callback.need_total_size_cb) {
      task_info->callback.total_size_cb(task_info->total_size);
    }

    // Create or use existing WkProgressData
    if (!task_info->pd) {
      task_info->pd = std::make_shared<WkProgressData>(task_info);
    }
    auto &pd = *(task_info->pd);
    pd.task_info = task_info;

    for (auto &task : task_info->tasks) {
      // Check terminate before each file
      if (pd.is_terminate()) {
        task.rcm = {EC::Terminate, "Task terminated by user"};
        task.IsFinished = true;
        continue;
      }

      if (task.IsFinished) {
        continue;
      }

      auto test_res = TestHost(task, task_info->hostm);
      ECM rcm = std::get<0>(test_res);
      if (rcm.first != EC::Success) {
        task.rcm = rcm;
        task.IsFinished = true;
        if (task_info->callback.need_error_cb) {
          task_info->callback.error_cb(ErrorCBInfo(
              task.rcm, task.src, task.dst, task.src_host, task.dst_host));
        }
        continue;
      }

      auto src_client = std::get<1>(test_res);
      auto dst_client = std::get<2>(test_res);

      if (task.path_type == PathType::DIR) {
        task.rcm = dst_client->mkdirs(task.dst);
        task.IsFinished = true;
        continue;
      }

      // Setup cur_task pointer to this task in tasks vector
      task_info->cur_task = &task;
      task.transferred = 0;
      task.rcm = ECM(EC::Success, "");
      pd.ring_buffer = std::make_shared<StreamRingBuffer>(
          CalculateBufferSize(src_client, dst_client, task_info->buffer_size));

      task.rcm = TransferSingleFile(src_client, dst_client, task_info);
      task.IsFinished = true;

      if (task.rcm.first != EC::Success && task_info->callback.need_error_cb &&
          task.rcm.first != EC::Terminate) {
        task_info->callback.error_cb(ErrorCBInfo(task.rcm, task.src, task.dst,
                                                 task.src_host, task.dst_host));
      }

      InnerCallback(task_info, pd, true);
    }

    // bool any_error = false;
    // for (auto &task : task_info->tasks) {
    //   if (task.rcm.first != EC::Success) {
    //     any_error = true;
    //     task_info->rcm = task.rcm; // Last error
    //   }
    // }
    // if (!any_error) {
    //   task_info->rcm = {EC::Success, ""};
    // }

    task_info->status = TaskStatus::Finished;
    task_info->finished_time = timenow();
  }

  // Worker thread function
  void WorkerLoop() {
    while (running.load()) {
      std::shared_ptr<TaskInfo> task_info;
      {
        std::unique_lock<std::mutex> lock(queue_mtx);
        queue_cv.wait(
            lock, [this]() { return !running.load() || !task_queue.empty(); });
        if (!running.load() && task_queue.empty()) {
          break;
        }
        if (task_queue.empty()) {
          continue;
        }
        task_info = std::move(task_queue.front());
        task_queue.pop_front();
      }

      // Set as conducting task
      {
        std::lock_guard<std::mutex> lock(conducting_mtx);
        conducting_task = task_info;
      }

      // Check if should skip
      if (ShouldSkipTask(task_info)) {
        std::lock_guard<std::mutex> lock(result_mtx);
        results[task_info->id] = task_info;
        {
          std::lock_guard<std::mutex> lock2(conducting_mtx);
          conducting_task = nullptr;
        }
        continue;
      }

      // Execute task
      ExecuteTask(task_info);

      // Store result and clear conducting
      {
        std::lock_guard<std::mutex> lock(result_mtx);
        results[task_info->id] = task_info;
      }
      {
        std::lock_guard<std::mutex> lock(conducting_mtx);
        conducting_task = nullptr;
      }
    }
  }

public:
  AMWorkManager() {
    worker_thread = std::thread([this]() { WorkerLoop(); });
  }

  ~AMWorkManager() {
    running.store(false);
    queue_cv.notify_all();
    if (worker_thread.joinable()) {
      worker_thread.join();
    }
  }

  // Set chunk size
  size_t ChunkSize(int64_t size = -1) {
    if (size < 32 * AMKB) {
      return chunk_size;
    } else {
      this->chunk_size = std::min<size_t>(size, AMMaxBufferSize);
      return this->chunk_size;
    }
  }

  // Non-blocking transfer - returns task ID immediately
  // Control (pause/resume/terminate) via wk control functions
  uint64_t transfer(const TASKS &tasks,
                    const std::shared_ptr<ClientMaintainer> &hostm,
                    TransferCallback callback = TransferCallback(),
                    ssize_t buffer_size = -1) {
    auto task_info = std::make_shared<TaskInfo>();
    task_info->id = GenerateUID();
    task_info->submit_time = timenow();
    task_info->status = TaskStatus::Pending;
    task_info->tasks = tasks;
    task_info->hostm = hostm;
    task_info->callback = callback;
    task_info->buffer_size = buffer_size;

    // Create shared progress data for control
    task_info->pd = std::make_shared<WkProgressData>(task_info);

    // Calculate total size
    for (auto &task : task_info->tasks) {
      task_info->total_size += task.size;
    }

    uint64_t id = task_info->id;
    {
      std::lock_guard<std::mutex> lock(queue_mtx);
      task_queue.push_back(task_info);
    }
    queue_cv.notify_one();
    return id;
  }

  // Query task status
  std::optional<TaskStatus> get_status(uint64_t id) {
    {
      std::lock_guard<std::mutex> lock(queue_mtx);
      for (const auto &task : task_queue) {
        if (task->id == id) {
          return task->status;
        }
      }
    }
    {
      std::lock_guard<std::mutex> lock(conducting_mtx);
      if (conducting_task && conducting_task->id == id) {
        return conducting_task->status;
      }
    }
    {
      std::lock_guard<std::mutex> lock(result_mtx);
      auto it = results.find(id);
      if (it != results.end()) {
        return it->second->status;
      }
    }
    return std::nullopt;
  }

  // Query task result (full info) - returns copy and removes from results
  std::optional<TaskInfo> get_result(uint64_t id) {
    std::lock_guard<std::mutex> lock(result_mtx);
    auto it = results.find(id);
    if (it != results.end()) {
      TaskInfo result = *(it->second);
      results.erase(it);
      return result;
    }
    return std::nullopt;
  }

  // Get task info (from queue, conducting, or results)
  std::optional<TaskInfo> get_task(uint64_t id) {
    {
      std::lock_guard<std::mutex> lock(queue_mtx);
      for (const auto &task : task_queue) {
        if (task->id == id) {
          return *task;
        }
      }
    }
    {
      std::lock_guard<std::mutex> lock(conducting_mtx);
      if (conducting_task && conducting_task->id == id) {
        return *conducting_task;
      }
    }
    {
      std::lock_guard<std::mutex> lock(result_mtx);
      auto it = results.find(id);
      if (it != results.end()) {
        return *(it->second);
      }
    }
    return std::nullopt;
  }

  // Pause a task by ID
  bool pause(uint64_t id) {
    {
      std::lock_guard<std::mutex> lock(queue_mtx);
      for (auto &task : task_queue) {
        if (task->id == id && task->pd) {
          task->pd->set_pause();
          return true;
        }
      }
    }
    {
      std::lock_guard<std::mutex> lock(conducting_mtx);
      if (conducting_task && conducting_task->id == id && conducting_task->pd) {
        conducting_task->pd->set_pause();
        return true;
      }
    }
    return false;
  }

  // Resume a task by ID
  bool resume(uint64_t id) {
    {
      std::lock_guard<std::mutex> lock(queue_mtx);
      for (auto &task : task_queue) {
        if (task->id == id && task->pd) {
          task->pd->set_running();
          return true;
        }
      }
    }
    {
      std::lock_guard<std::mutex> lock(conducting_mtx);
      if (conducting_task && conducting_task->id == id && conducting_task->pd) {
        conducting_task->pd->set_running();
        return true;
      }
    }
    return false;
  }

  // Terminate a task by ID and return task info
  // For pending tasks, moves them to results immediately
  // For conducting tasks, waits for completion
  std::optional<TaskInfo> terminate(uint64_t id, int timeout_ms = 5000) {
    bool found_in_conducting = false;
    // Check pending tasks first
    {
      std::lock_guard<std::mutex> lock(queue_mtx);
      for (auto it = task_queue.begin(); it != task_queue.end(); ++it) {
        if ((*it)->id == id) {
          auto task = *it;
          if (task->pd) {
            task->pd->set_terminate();
          }
          task->rcm = {EC::Terminate, "Task terminated before start"};
          task->status = TaskStatus::Finished;
          task->finished_time = timenow();
          TaskInfo result = *task;
          // Move to results
          {
            std::lock_guard<std::mutex> rlock(result_mtx);
            results[task->id] = task;
          }
          task_queue.erase(it);
          return result;
        }
      }
    }
    // Check conducting task
    {
      std::lock_guard<std::mutex> lock(conducting_mtx);
      if (conducting_task && conducting_task->id == id) {
        if (conducting_task->pd) {
          conducting_task->pd->set_terminate();
        }
        found_in_conducting = true;
      }
    }
    // If not found anywhere, return immediately
    if (!found_in_conducting) {
      return std::nullopt;
    }
    // Wait for conducting task to finish
    int64_t start = am_ms();
    while (timeout_ms < 0 || (am_ms() - start) < timeout_ms) {
      {
        std::lock_guard<std::mutex> lock(result_mtx);
        auto it = results.find(id);
        if (it != results.end()) {
          TaskInfo result = *(it->second);
          results.erase(it);
          return result;
        }
      }
      std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    return std::nullopt;
  }

  // Get number of pending tasks
  size_t pending_count() {
    std::lock_guard<std::mutex> lock(queue_mtx);
    return task_queue.size();
  }

  // Check if any task is currently conducting
  bool is_conducting() {
    std::lock_guard<std::mutex> lock(conducting_mtx);
    return conducting_task != nullptr;
  }

  // Get currently conducting task ID (0 if none)
  uint64_t get_conducting_id() {
    std::lock_guard<std::mutex> lock(conducting_mtx);
    return conducting_task ? conducting_task->id : 0;
  }

  // Clear finished results
  void clear_results() {
    std::lock_guard<std::mutex> lock(result_mtx);
    results.clear();
  }

  // Remove a specific result
  bool remove_result(uint64_t id) {
    std::lock_guard<std::mutex> lock(result_mtx);
    return results.erase(id) > 0;
  }

  // Get all result IDs
  std::vector<uint64_t> get_result_ids() {
    std::lock_guard<std::mutex> lock(result_mtx);
    std::vector<uint64_t> ids;
    ids.reserve(results.size());
    for (const auto &[id, _] : results) {
      ids.push_back(id);
    }
    return ids;
  }
};
