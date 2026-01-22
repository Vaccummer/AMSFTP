#pragma once
// 标准库
#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <ctime>
#include <fcntl.h>
#include <filesystem>
#include <memory>
#include <mutex>
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
        std::lock_guard<std::recursive_mutex> lock(client->mtx);
        bytes_read = libssh2_sftp_read(sftp_handle, write_ptr, to_read);
        if (bytes_read > 0) {
          ring_buffer->commit_write(bytes_read);
          offset += bytes_read;
          return {bytes_read, {EC::Success, ""}};
        } else if (bytes_read == 0) {
          return {0, {EC::EndOfFile, "End of file"}};
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

class AMSFTPWorker {
private:
  amf worker_interrupt_flag = std::make_shared<InterruptFlag>();
  ECM Transit(const std::string &src, const std::string &dst,
              const std::shared_ptr<AMSFTPClient> &src_worker,
              const std::shared_ptr<AMSFTPClient> &dst_worker) {
    ErrorCode rc_final = EC::Success;
    std::string error_msg = "";
    LIBSSH2_SFTP_HANDLE *srcFile = nullptr;
    LIBSSH2_SFTP_HANDLE *dstFile = nullptr;
    std::lock_guard<std::recursive_mutex> lock(src_worker->mtx);
    std::lock_guard<std::recursive_mutex> lock2(dst_worker->mtx);
    dst_worker->mkdir(AMPathStr::dirname(dst));
    srcFile = libssh2_sftp_open(src_worker->sftp, src.c_str(), LIBSSH2_FXF_READ,
                                0400);
    dstFile = libssh2_sftp_open(
        dst_worker->sftp, dst.c_str(),
        LIBSSH2_FXF_WRITE | LIBSSH2_FXF_CREAT | LIBSSH2_FXF_TRUNC, 0744);

    if (!srcFile) {
      rc_final = src_worker->GetLastEC();
      error_msg = fmt::format("Failed to open src remote file: {}, cause {}",
                              src, src_worker->GetLastErrorMsg());
      src_worker->trace(
          TraceLevel::Error, rc_final,
          fmt::format("{}@{}", src_worker->res_data.nickname, src),
          "Remote2Remote", error_msg);
      return {rc_final, error_msg};
    }

    if (!dstFile) {
      // 获取错误代码
      rc_final = dst_worker->GetLastEC();
      error_msg = fmt::format("Failed to open dst remote file: {}, cause {}",
                              dst, dst_worker->GetLastErrorMsg());
      dst_worker->trace(
          TraceLevel::Error, rc_final,
          fmt::format("{}@{}", dst_worker->res_data.nickname, dst),
          "Remote2Remote", error_msg);
      return {rc_final, error_msg};
    }

    LIBSSH2_SFTP_ATTRIBUTES attrs;
    libssh2_sftp_fstat(srcFile, &attrs);
    uint64_t file_size = attrs.filesize;

    // uint64_t buffer_size_ori = calculate_buffer_size(file_size, 32 * AMGB);
    uint64_t all_read = 0;
    uint64_t all_write = 0;
    uint64_t last_callback_write = 0;
    long rc_read, rc_write;
    uint64_t idle_count = 0;

    libssh2_session_set_blocking(src_worker->session, 0);
    libssh2_session_set_blocking(dst_worker->session, 0);

    while (all_write < file_size) {
      bool did_work = false;

      // === 生产者：从源读取数据写入缓冲区 ===
      if (all_read < file_size && pd.ring_buffer->writable() > 0) {
        auto [write_ptr, max_write] = pd.ring_buffer->get_write_ptr();
        size_t to_read = std::min<size_t>(max_write, file_size - all_read);

        if (to_read > 0) {
          rc_read = libssh2_sftp_read(srcFile, write_ptr, to_read);
          if (rc_read > 0) {
            pd.ring_buffer->commit_write(rc_read);
            all_read += rc_read;
            did_work = true;
            idle_count = 0;
          } else if (rc_read < 0 && rc_read != LIBSSH2_ERROR_EAGAIN) {
            rc_final = src_worker->GetLastEC();
            error_msg = fmt::format("Sftp read error: {}",
                                    src_worker->GetLastErrorMsg());
            goto clean;
          }
        }
      }

      // === 消费者：从缓冲区读取数据写入目标 ===
      if (pd.ring_buffer->available() > 0) {
        auto [read_ptr, max_read] = pd.ring_buffer->get_read_ptr();

        if (max_read > 0) {
          rc_write = libssh2_sftp_write(dstFile, read_ptr, max_read);
          if (rc_write > 0) {
            pd.ring_buffer->commit_read(rc_write);
            all_write += rc_write;
            did_work = true;
            idle_count = 0;
          } else if (rc_write < 0 && rc_write != LIBSSH2_ERROR_EAGAIN) {
            rc_final = dst_worker->GetLastEC();
            error_msg = fmt::format("Sftp write error: {}",
                                    dst_worker->GetLastErrorMsg());
            goto clean;
          }
        }
      }

      // === 进度回调（每写入buffer_size或完成时触发）===
      if (all_write - last_callback_write >= pd.ring_buffer->get_capacity() ||
          all_write == file_size) {
        last_callback_write = all_write;
        pd.this_size = all_write;
        pd.accumulated_size += (all_write - last_callback_write);
        InnerCallback();

        // 暂停/终止检查
        while (pd.is_pause.load() && !pd.is_terminate.load()) {
          std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
        if (pd.is_terminate.load()) {
          rc_final = EC::Terminate;
          error_msg = "Transfer cancelled";
          goto clean;
        }
      }

      // === 空闲时让出CPU ===
      if (!did_work) {
        idle_count++;
        if (idle_count > 10) {
          std::this_thread::sleep_for(std::chrono::microseconds(20));
          idle_count = 0;
        }
      }
    }

  clean:
    libssh2_session_set_blocking(src_worker->session, 1);
    libssh2_session_set_blocking(dst_worker->session, 1);

    InnerCallback(true);

    if (srcFile) {
      libssh2_sftp_close_handle(srcFile);
    }

    if (dstFile) {
      libssh2_sftp_close_handle(dstFile);
    }

    return {rc_final, error_msg};
  }

  ECM InHostCopy(const std::string &src, const std::string &dst,
                 const std::shared_ptr<AMSFTPClient> &worker,
                 uint64_t chunk_size = 256 * AMKB) {
    ErrorCode rc_final = EC::Success;
    std::string error_msg = "";
    LIBSSH2_SFTP_HANDLE *srcFile = nullptr;
    LIBSSH2_SFTP_HANDLE *dstFile = nullptr;
    std::lock_guard<std::recursive_mutex> lock(worker->mtx);
    worker->mkdirs(AMPathStr::dirname(dst));
    srcFile =
        libssh2_sftp_open(worker->sftp, src.c_str(), LIBSSH2_FXF_READ, 0400);

    if (!srcFile) {
      rc_final = worker->GetLastEC();
      error_msg = fmt::format("Failed to open src remote file: {}, cause {}",
                              src, worker->GetLastErrorMsg());
      worker->trace(TraceLevel::Error, rc_final,
                    fmt::format("{}@{}", worker->res_data.nickname, src),
                    "Remote2Remote", error_msg);
      return {rc_final, error_msg};
    }
    dstFile = libssh2_sftp_open(
        worker->sftp, dst.c_str(),
        LIBSSH2_FXF_WRITE | LIBSSH2_FXF_CREAT | LIBSSH2_FXF_TRUNC, 0744);
    if (!dstFile) {
      // 获取错误代码
      rc_final = worker->GetLastEC();
      error_msg = fmt::format("Failed to open dst remote file: {}, cause {}",
                              dst, worker->GetLastErrorMsg());
      worker->trace(TraceLevel::Error, rc_final,
                    fmt::format("{}@{}", worker->res_data.nickname, dst),
                    "Remote2Remote", error_msg);
      return {rc_final, error_msg};
    }

    LIBSSH2_SFTP_ATTRIBUTES attrs;
    libssh2_sftp_fstat(srcFile, &attrs);
    uint64_t file_size = attrs.filesize;

    // uint64_t buffer_size_ori = calculate_buffer_size(file_size, 32 * AMGB);
    StreamRingBuffer ring(chunk_size);
    uint64_t all_read = 0;
    uint64_t all_write = 0;
    uint64_t last_callback_write = 0;
    long rc_read, rc_write;
    uint64_t idle_count = 0;

    libssh2_session_set_blocking(worker->session, 0);

    while (all_write < file_size) {
      bool did_work = false;

      // === 生产者：从源读取数据写入缓冲区 ===
      if (all_read < file_size && ring.writable() > 0) {
        auto [write_ptr, max_write] = ring.get_write_ptr();
        size_t to_read = std::min<size_t>(max_write, file_size - all_read);

        if (to_read > 0) {
          rc_read = libssh2_sftp_read(srcFile, write_ptr, to_read);
          if (rc_read > 0) {
            ring.commit_write(rc_read);
            all_read += rc_read;
            did_work = true;
            idle_count = 0;
          } else if (rc_read < 0 && rc_read != LIBSSH2_ERROR_EAGAIN) {
            rc_final = worker->GetLastEC();
            error_msg =
                fmt::format("Sftp read error: {}", worker->GetLastErrorMsg());
            goto clean;
          }
        }
      }

      // === 消费者：从缓冲区读取数据写入目标 ===
      if (ring.available() > 0) {
        auto [read_ptr, max_read] = ring.get_read_ptr();

        if (max_read > 0) {
          rc_write = libssh2_sftp_write(dstFile, read_ptr, max_read);
          if (rc_write > 0) {
            ring.commit_read(rc_write);
            all_write += rc_write;
            did_work = true;
            idle_count = 0;
          } else if (rc_write < 0 && rc_write != LIBSSH2_ERROR_EAGAIN) {
            rc_final = worker->GetLastEC();
            error_msg =
                fmt::format("Sftp write error: {}", worker->GetLastErrorMsg());
            goto clean;
          }
        }
      }

      // === 进度回调（每写入buffer_size或完成时触发）===
      if (all_write - last_callback_write >= chunk_size ||
          all_write == file_size) {

        last_callback_write = all_write;
        pd.accumulated_size += (all_write - last_callback_write);
        pd.this_size = all_write;
        InnerCallback();

        // 暂停/终止检查
        while (pd.is_pause.load() && !pd.is_terminate.load()) {
          std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
        if (pd.is_terminate.load()) {
          rc_final = EC::Terminate;
          error_msg = "Transfer cancelled";
          goto clean;
        }
      }

      // === 空闲时让出CPU ===
      if (!did_work) {
        idle_count++;
        if (idle_count > 10) {
          std::this_thread::sleep_for(std::chrono::microseconds(20));
          idle_count = 0;
        }
      }
    }

  clean:
    libssh2_session_set_blocking(worker->session, 1);

    InnerCallback(true);

    if (srcFile) {
      libssh2_sftp_close_handle(srcFile);
    }

    if (dstFile) {
      libssh2_sftp_close_handle(dstFile);
    }

    return {rc_final, error_msg};
  }

  void XToBuffer(const TransferTask &task, std::shared_ptr<BaseClient> client,
                 ConRequst request = ConRequst()) {
    if ((client->GetProtocol() == ClientProtocol::SFTP) ||
        (client->GetProtocol() == ClientProtocol::LOCAL)) {
      std::cout << "SFTP/LOCAL Reading" << std::endl;
      UnionFileHandle file_handle;
      std::shared_ptr<AMSFTPClient> clientf = nullptr;
      if (client->GetProtocol() == ClientProtocol::SFTP) {
        clientf = std::static_pointer_cast<AMSFTPClient>(client);
      }
      ECM rcm = file_handle.Init(task.src, task.size, clientf, false, true);
      if (rcm.first != EC::Success) {
        std::cout << "Init failed" << std::endl;
        pd.is_terminate.store(true);
        pd.rcm = rcm;
        return;
      }
      while (file_handle.offset < file_handle.file_size &&
             !pd.is_terminate.load()) {
        while (pd.ring_buffer->writable() == 0 && !pd.is_terminate.load() &&
               file_handle.offset < file_handle.file_size) {
          std::this_thread::sleep_for(std::chrono::milliseconds(20));
        }
        while (pd.is_pause.load() && !pd.is_terminate.load()) {
          std::this_thread::sleep_for(std::chrono::milliseconds(20));
        }
        if (pd.is_terminate.load()) {
          return;
        }
        auto [bytes_read, ecm] = file_handle.Read(pd.ring_buffer);
        if (ecm.first != EC::Success) {
          pd.is_terminate.store(true);
          pd.rcm = ecm;
          return;
        }
      }
      // } else if (!client && !request.nickname.empty()) {
      //   auto client_ftp = std::make_shared<AMFTPClient>(request);
      //   ECM ecm = client_ftp->Connect();
      //   if (ecm.first != EC::Success) {
      //     pd.is_terminate.store(true);
      //     pd.rcm = ecm;
      //     return;
      //   }
      //   client_ftp->Download(task.src, FTPToBuffer, &pd);
    } else if (client->GetProtocol() == ClientProtocol::FTP) {
      // 读取FTP文件，而且需要创建额外的ftp客户端
      auto client_ftp = std::static_pointer_cast<AMFTPClient>(client);
      client_ftp->Download(task.src, FTPToBuffer, &pd);
    }
  }

  void BufferToX(const TransferTask &task, std::shared_ptr<BaseClient> client,
                 ConRequst request = ConRequst()) {
    if ((client->GetProtocol() == ClientProtocol::SFTP) ||
        (client->GetProtocol() == ClientProtocol::LOCAL)) {
      std::cout << "SFTP/LOCAL Writing" << std::endl;
      UnionFileHandle file_handle;
      std::shared_ptr<AMSFTPClient> clientf = nullptr;
      if (client->GetProtocol() == ClientProtocol::SFTP) {
        clientf = std::static_pointer_cast<AMSFTPClient>(client);
      }
      ECM rcm = file_handle.Init(task.dst, task.size, clientf, true, true);
      if (rcm.first != EC::Success) {
        pd.is_terminate.store(true);
        pd.rcm = rcm;
        return;
      }
      while (file_handle.offset < file_handle.file_size &&
             !pd.is_terminate.load()) {
        while (pd.ring_buffer->available() == 0 && !pd.is_terminate.load()) {
          std::this_thread::sleep_for(std::chrono::milliseconds(20));
        }
        while (pd.is_pause.load() && !pd.is_terminate.load()) {
          std::this_thread::sleep_for(std::chrono::milliseconds(20));
        }
        if (pd.is_terminate.load()) {
          return;
        }
        auto [bytes_write, ecm] = file_handle.Write(pd.ring_buffer);
        if (ecm.first != EC::Success) {
          pd.is_terminate.store(true);
          pd.rcm = ecm;
          return;
        }
        pd.accumulated_size += bytes_write;
        pd.this_size = file_handle.offset;
        InnerCallback();
      }
      // } else if (!client && !request.nickname.empty()) {
      //   auto client_ftp = std::make_shared<AMFTPClient>(request);
      //   ECM ecm = client_ftp->Connect();
      //   if (ecm.first != EC::Success) {
      //     pd.is_terminate.store(true);
      //     pd.rcm = ecm;
      //     return;
      //   }
      //   client_ftp->Upload(task.dst, FTPToBuffer, &pd);
    } else if (client->GetProtocol() == ClientProtocol::FTP) {
      // 读取FTP文件，而且需要创建额外的ftp客户端
      auto client_ftp = std::static_pointer_cast<AMFTPClient>(client);
      client_ftp->Upload(task.dst, BufferToFTP, &pd);
    }
  }

  /*
  std::pair<ECM, PathInfo> Ustat(const std::string &path,
                                 const std::shared_ptr<ClientMaintainer> &hostm,
                                 const std::string &nickname = "") {
    if (nickname.empty()) {
      auto res = AMFS::stat(path);
      if (res.first.first != EC::Success) {
        return {ECM{EC::LocalStatError, res.first.second}, res.second};
      }
      return {ECM{EC::Success, ""}, res.second};
    }
    ECM rc = hostm->test_client(nickname);
    if (rc.first != EC::Success) {
      return {rc, PathInfo()};
    }
    auto client = hostm->GetHost(nickname);
    if (!client) {
      return {ECM{EC::NoSession, "Client not found"}, PathInfo()};
    }
    return client->stat(path);
  }

  std::vector<PathInfo> Uiwalk(const std::string &path,
                               const std::shared_ptr<ClientMaintainer> &hostm,
                               const std::string &nickname = "",
                               bool ignore_special_file = true) {
    if (nickname.empty()) {
      return {};
    }
    ECM rc = hostm->test_client(nickname);
    if (rc.first != EC::Success) {
      return {};
    }
    auto client = hostm->GetHost(nickname);
    if (!client) {
      return {};
    }
    return client->iwalk(path, ignore_special_file).second;
  }
*/

  ECM _UnionTransfer(const TransferTask &task,
                     std::shared_ptr<BaseClient> src_client = nullptr,
                     std::shared_ptr<BaseClient> dst_client = nullptr) {
    ConRequst request;
    if (src_client->GetProtocol() == ClientProtocol::SFTP &&
        dst_client->GetProtocol() == ClientProtocol::SFTP) {
      // 走SFTP非阻塞模式
      return this->Transit(task.src, task.dst,
                           std::static_pointer_cast<AMSFTPClient>(src_client),
                           std::static_pointer_cast<AMSFTPClient>(dst_client));
    }
    // } else if (src_client->GetProtocol() == ClientProtocol::FTP &&
    //             dst_client->GetProtocol() == ClientProtocol::FTP) {
    //   // 双FTP模式
    //   request = src_client->GetRequest();

    // }
    // 启动一个thread执行Reading

    std::cout << "start Reading" << std::endl;
    std::thread reading_thread(
        [&]() { this->XToBuffer(task, src_client, request); });

    std::cout << "start Writing" << std::endl;
    std::cout << "this_size: " << pd.this_size << std::endl;
    std::cout << "file_size: " << pd.file_size << std::endl;
    std::cout << "accumulated_size: " << pd.accumulated_size << std::endl;
    std::cout << "total_size: " << pd.total_size << std::endl;
    this->BufferToX(task, dst_client, request);
    std::cout << "this_size: " << pd.this_size << std::endl;
    std::cout << "file_size: " << pd.file_size << std::endl;
    std::cout << "is_terminate: " << pd.is_terminate.load() << std::endl;
    pd.is_terminate.store(true);
    std::cout << "Writing done" << std::endl;

    if (reading_thread.joinable()) {
      reading_thread.join();
    }
    std::cout << "Reading done" << std::endl;

    if (pd.rcm.first == EC::Success) {
      if (pd.is_terminate.load()) {
        return {EC::Terminate, "Transfer terminated by user"};
      } else {
        return {EC::Success, ""};
      }
    } else {
      return pd.rcm;
    }
  }

  ssize_t CalculateBufferSize(std::shared_ptr<BaseClient> src_client,
                              std::shared_ptr<BaseClient> dst_client,
                              ssize_t provided_size) {
    ssize_t src_size = src_client ? src_client->TransferRingBufferSize() : -1;
    ssize_t dst_size = dst_client ? dst_client->TransferRingBufferSize() : -1;
    bool is_local = !src_client && !dst_client;
    if (provided_size > AMMinBufferSize && provided_size < AMMaxBufferSize) {
      // 优先使用用户提供的缓冲区大小
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
      // src_host 为空时使用本地客户端
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
      // dst_host 为空时使用本地客户端
      dst_client = hostm->local_client;
    }
    return {rcm, src_client, dst_client};
  }

public:
  TransferCallback callback;
  ProgressData pd;

  AMSFTPWorker(TransferCallback callback, float cb_interval_s = 0.2)
      : callback(std::move(callback)), pd(cb_interval_s) {
    this->pd.progress_cb = [this](bool force) { InnerCallback(force); };
  }
  inline void InnerCallback(bool force = false) {
    if (callback.need_progress_cb) {
      auto time_now = timenow();
      if (force || ((time_now - pd.cb_time) > pd.cb_interval_s)) {
        pd.cb_time = time_now;
        py::gil_scoped_acquire acquire;
        py::object result = callback.progress_cb(ProgressCBInfo(
            pd.src, pd.dst, pd.src_host, pd.dst_host, pd.this_size,
            pd.file_size, pd.accumulated_size, pd.total_size));
        if (!result.is_none()) {
          if (py::isinstance<TransferControl>(result)) {
            SetState(py::cast<TransferControl>(result));
          }
        }
      }
    }
  }

  static size_t BufferToFTP(char *ptr, size_t size, size_t nmemb,
                            void *userdata) {
    // size指块数，但这个值往往是1
    auto *pd = static_cast<ProgressData *>(userdata);
    static int wait_count = 0; // 等待计数
    // 持续等待直到有数据可读并成功获取
    while (true) {
      // 检查中断
      if (pd->is_terminate.load()) {
        std::cout << "[BufferToFTP] Terminated, this_size=" << pd->this_size
                  << std::endl;
        return CURL_READFUNC_ABORT;
      }
      // 检查暂停
      while (pd->is_pause.load() && !pd->is_terminate.load()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
      }
      // 检查是否传输完成
      if (pd->this_size >= pd->file_size) {
        return 0; // 只有真正传输完成才返回 0 (EOF)
      }
      // 等待有数据可读
      if (pd->ring_buffer->available() == 0) {
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
        continue;
      }
      // 尝试获取数据
      auto [read_ptr, read_len] = pd->ring_buffer->get_read_ptr();
      ssize_t to_read = read_len > size * nmemb ? size * nmemb : read_len;

      if (to_read > 0) {
        try {
          memcpy(ptr, read_ptr, to_read);
          pd->ring_buffer->commit_read(to_read);
          pd->this_size += to_read;
          pd->accumulated_size += to_read;
          pd->progress_cb(false);
          return to_read;
        } catch (const std::exception &e) {
          pd->is_terminate.store(true);
          pd->rcm = ECM{EC::BufferReadError, e.what()};
          return CURL_READFUNC_ABORT;
        }
      } else if (to_read < 0) {
        pd->is_terminate.store(true);
        pd->rcm = ECM{EC::BufferReadError, "Get negative value for data size"};
        return CURL_READFUNC_ABORT;
      }
      // to_read == 0: 竞态条件，available() > 0 但实际获取不到数据
      // 继续循环重试，而不是返回 0
    }
  }

  static size_t FTPToBuffer(char *ptr, size_t size, size_t nmemb,
                            void *userdata) {
    auto *pd = static_cast<ProgressData *>(userdata);
    while (pd->ring_buffer->writable() == 0 && !pd->is_terminate.load() &&
           pd->this_size < pd->file_size) {
      std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    while (pd->is_pause.load() && !pd->is_terminate.load()) {
      std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    if (pd->is_terminate.load()) {
      return CURL_READFUNC_ABORT;
    }
    auto [write_ptr, write_len] = pd->ring_buffer->get_write_ptr();
    ssize_t to_read = write_len > size * nmemb ? size * nmemb : write_len;
    if (to_read > 0) {
      try {
        memcpy(write_ptr, ptr, to_read);
        pd->ring_buffer->commit_write(to_read);
        return to_read;
      } catch (const std::exception &e) {
        pd->is_terminate.store(true);
        pd->rcm = ECM{EC::BufferWriteError, e.what()};
        return CURL_READFUNC_ABORT;
      }
    } else if (to_read == 0) {
      return 0;
    } else {
      pd->is_terminate.store(true);
      pd->rcm = ECM{EC::BufferWriteError, "Get Negativate value for data size"};
      return CURL_READFUNC_ABORT;
    }
  }

  inline void SetState(TransferControl state) {
    switch (state) {
    case TransferControl::Running:
      this->pd.is_pause.store(false);
      break;
    case TransferControl::Pause:
      this->pd.is_pause.store(true);
      break;
    case TransferControl::Terminate:
      this->pd.is_terminate.store(true);
      break;
    default:
      break;
    }
  }

  inline TransferControl GetState() {
    if (pd.is_terminate.load()) {
      return TransferControl::Terminate;
    } else if (pd.is_pause.load()) {
      return TransferControl::Pause;
    } else {
      return TransferControl::Running;
    }
  }

  TASKS EraseOverlapTasks(const TASKS &tasks) {
    std::unordered_set<std::string> dst_set{};
    TASKS result{};
    std::string task_id;
    for (auto &task : tasks) {
      task_id = task.src + task.src_host + task.dst + task.dst_host;
      if (dst_set.count(task_id) == 0) {
        dst_set.insert(task_id);
        result.push_back(task);
      }
    }
    // 排序，讲task中type为DIR的task放在前面，type为FILE的task放在后面
    std::sort(result.begin(), result.end(),
              [](const TransferTask &a, const TransferTask &b) {
                return a.path_type == PathType::DIR &&
                       b.path_type != PathType::DIR;
              });
    return result;
  }

  TASKS transfer(const TASKS &tasks,
                 const std::shared_ptr<ClientMaintainer> &hostm,
                 ssize_t buffer_size = -1) {
    if (tasks.empty()) {
      return {};
    }
    auto tasksf = EraseOverlapTasks(tasks);
    this->pd.reset();
    ECM rcm = ECM{EC::Success, ""};
    std::shared_ptr<BaseClient> src_client = nullptr;
    std::shared_ptr<BaseClient> dst_client = nullptr;
    std::tuple<ECM, std::shared_ptr<BaseClient>, std::shared_ptr<BaseClient>>
        test_res;
    for (auto &task : tasksf) {
      pd.total_size += task.size;
    }

    if (callback.need_total_size_cb) {
      py::gil_scoped_acquire acquire;
      callback.total_size_cb(pd.total_size);
    }

    for (auto &task : tasksf) {
      if (task.IsFinished) {
        // 跳过在load_tasks中，未设置overlap且dst已经存在的任务
        goto check;
      }

      if (pd.is_terminate.load()) {
        task.rcm = ECM(EC::Terminate, "Transfer cancelled by user");
        goto check;
      }
      test_res = TestHost(task, hostm);
      rcm = std::get<0>(test_res);

      if (rcm.first != EC::Success) {
        task.rcm = rcm;
        goto check;
      }

      src_client = std::get<1>(test_res);
      dst_client = std::get<2>(test_res);
      if (task.path_type == PathType::DIR) {
        task.rcm = dst_client->mkdirs(task.dst);
        goto check;
      }
      pd.next_file(task,
                   CalculateBufferSize(src_client, dst_client, buffer_size));
      task.rcm = _UnionTransfer(task, src_client, dst_client);
      InnerCallback(true);

    check:
      task.IsFinished = true;
      if (task.rcm.first != EC::Success) {
        if (callback.need_error_cb && task.rcm.first != EC::Terminate) {
          py::gil_scoped_acquire acquire;
          callback.error_cb(ErrorCBInfo(task.rcm, task.src, task.dst,
                                        task.src_host, task.dst_host));
        }
      }
    }
    return tasksf;
  }

  std::pair<ECM, TASKS>
  load_tasks(const std::string &src, const std::string &dst,
             const std::shared_ptr<ClientMaintainer> &hostm,
             const std::string &src_host = "", const std::string &dst_host = "",
             bool overwrite = false, bool mkdir = true,
             bool ignore_sepcial_file = true, amf interrupt_flag = nullptr,
             int timeout_ms = -1, int64_t start_time = -1) {
    start_time = start_time == -1 ? am_ms() : start_time;
    interrupt_flag = interrupt_flag ? interrupt_flag : worker_interrupt_flag;
    WRV result = {};
    TASKS tasks = {};
    // 去除src的dst左右端的空格

    auto [rc1, src_client] = hostm->test_client(src_host, false, interrupt_flag,
                                                timeout_ms, start_time);

    if (rc1.first != EC::Success) {
      return {rc1, tasks};
    }
    auto [rc2, dst_client] = hostm->test_client(dst_host, false, interrupt_flag,
                                                timeout_ms, start_time);

    if (rc2.first != EC::Success) {
      return {rc2, tasks};
    }
    auto [rc3, src_stat] =
        src_client->stat(src, false, interrupt_flag, timeout_ms, start_time);

    if (rc3.first != EC::Success) {
      return {rc3, tasks};
    }

    // 检查是否为 src_file -> dst_file 的传输
    auto dstf = dst;
    auto srcf = src;
    bool is_dst_file = false;
    if (src_stat.type == PathType::FILE) {
      // 检查dst的扩展名和src扩展名是否相同

      std::string dst_ext = AMPathStr::extname(dstf);
      std::cout << "dst_ext: " << dst_ext << std::endl;
      std::cout << "src_ext: " << AMPathStr::extname(srcf) << std::endl;
      if (AMPathStr::extname(srcf) == dst_ext && !dst_ext.empty()) {
        is_dst_file = true;
      }
    }

    if (src_stat.type != PathType::DIR) {

      if (ignore_sepcial_file && src_stat.type != PathType::FILE) {
        return {ECM{EC::NotAFile, fmt::format("Src is not a common file and "
                                              "ignore_sepcial_file is true: {}",
                                              srcf)},
                {}};
      }

      if (!is_dst_file) {
        dstf = AMPathStr::join(dstf, AMPathStr::basename(srcf));
      }

      // 检测dst的父级目录是否存在
      auto [rcm4, dst_parent_info] =
          dst_client->stat(AMPathStr::dirname(dstf), false, interrupt_flag,
                           timeout_ms, start_time);

      if (rcm4.first != EC::Success && !mkdir) {
        return {ECM{EC::ParentDirectoryNotExist,
                    fmt::format("Dst parent path not exists: {}",
                                AMPathStr::dirname(dstf))},
                tasks};
      } else if (rcm4.first == EC::Success &&
                 dst_parent_info.type != PathType::DIR) {
        return {ECM(EC::NotADirectory,
                    fmt::format("Dst parent path is not a directory: {}",
                                dst_parent_info.path)),
                tasks};
      }

      if (rcm4.first == EC::Success) {
        auto [rcm5, dst_info] = dst_client->stat(dstf, false, interrupt_flag,
                                                 timeout_ms, start_time);
        // 检验目标路径是否存在
        if (rcm4.first == EC::Success) {
          if (dst_info.type == PathType::DIR) {
            return {ECM(EC::NotAFile,
                        fmt::format("Dst already exists and is a directory: {}",
                                    dstf)),
                    tasks};
          } else if (!overwrite) {
            return {ECM{EC::PathAlreadyExists,
                        fmt::format("Dst already exists: {}", dstf)},
                    tasks};
          }
        }
      }

      tasks.emplace_back(srcf, dstf, src_host, dst_host, src_stat.size,
                         src_stat.type);
      return {ECM(EC::Success, ""), tasks};
    }

    auto [rcm6, dst_info] =
        dst_client->stat(dstf, false, interrupt_flag, timeout_ms, start_time);

    if (rcm6.first != EC::Success && !mkdir) {
      return {ECM{EC::ParentDirectoryNotExist,
                  fmt::format("Dst parent path not exists: {}", dstf)},
              tasks};
    } else if (rcm6.first == EC::Success && dst_info.type != PathType::DIR) {
      return {ECM(EC::NotADirectory,
                  fmt::format("Dst already exists and is not a directory: {}",
                              dstf)),
              tasks};
    }

    auto [rcm7, src_paths] =
        src_client->iwalk(srcf, false, interrupt_flag, timeout_ms, start_time);
    if (rcm7.first != EC::Success) {
      return {rcm7, tasks};
    }
    tasks.reserve(src_paths.size());

    TransferTask taskt;
    std::string dst_n;
    for (auto &item : src_paths) {
      if (interrupt_flag && interrupt_flag->check()) {
        return {ECM{EC::Terminate, "Load tasks interrupted by user"}, tasks};
      }
      if (timeout_ms > 0 && am_ms() - start_time >= timeout_ms) {
        return {ECM{EC::OperationTimeout, "Load tasks timeout"}, tasks};
      }
      dst_n = AMPathStr::join(
          dstf, fs::relative(item.path, AMPathStr::dirname(srcf)));
      auto [rcm8, dst_info2] = dst_client->stat(dst_n, false, interrupt_flag,
                                                timeout_ms, start_time);
      if (rcm8.first == EC::Success) {
        if (dst_info2.type == PathType::DIR) {
          taskt = TransferTask(item.path, dst_n, src_host, dst_host, item.size,
                               item.type);
          taskt.IsFinished = true;
          taskt.rcm =
              ECM{EC::NotAFile, "Dst already exists and is a directory"};
        } else if (!overwrite) {
          taskt = TransferTask(item.path, dst_n, src_host, dst_host, item.size,
                               item.type);
          taskt.IsFinished = true;
          taskt.rcm = ECM{EC::PathAlreadyExists, "Dst already exists"};
        } else {
          taskt = TransferTask(item.path, dst_n, src_host, dst_host, item.size,
                               item.type);
        }
        tasks.push_back(taskt);
        continue;
      }
      tasks.emplace_back(item.path, dst_n, src_host, dst_host, item.size,
                         item.type);
    }
    return {ECM(EC::Success, ""), tasks};
  };
};
