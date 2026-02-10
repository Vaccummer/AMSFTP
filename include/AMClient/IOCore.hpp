#pragma once
// 标准库
#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <ctime>
#include <fcntl.h>
#include <functional>
#include <libssh2.h>
#include <list>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

// 自身依赖
#include "AMBase/CommonTools.hpp"
#include "AMClient/Base.hpp"
#include "AMClient/FTP.hpp"
#include "AMClient/Local.hpp"
#include "AMClient/SFTP.hpp"
#include "AMManager/Prompt.hpp"

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
  WkProgressData *pd = nullptr;

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
           bool is_write = false, bool sequential = true, bool truncate = true,
           WkProgressData *progress = nullptr) {
    this->path = path;
    this->is_write = is_write;
    this->file_size = file_size;
    this->client = client;
    this->is_sftp = (client != nullptr);
    this->pd = progress;

    if (is_sftp) {
      // SFTP file
      std::lock_guard<std::recursive_mutex> lock(client->mtx);
      libssh2_session_set_blocking(client->session, 0);

      if (is_write) {
        int flags = LIBSSH2_FXF_WRITE;
        if (truncate) {
          flags |= LIBSSH2_FXF_TRUNC | LIBSSH2_FXF_CREAT;
        }
        auto nb_res = client->nb_call(
            pd ? std::function<bool()>([this]() { return pd->is_terminate(); })
               : std::function<bool()>(),
            -1, am_ms(), [&]() {
              return libssh2_sftp_open(client->sftp, path.c_str(), flags, 0744);
            });
        sftp_handle = nb_res.value;
      } else {
        auto nb_res = client->nb_call(
            pd ? std::function<bool()>([this]() { return pd->is_terminate(); })
               : std::function<bool()>(),
            -1, am_ms(), [&]() {
              return libssh2_sftp_open(client->sftp, path.c_str(),
                                       LIBSSH2_FXF_READ, 0400);
            });
        sftp_handle = nb_res.value;
      }
      if (!sftp_handle) {
        EC rc = client->GetLastEC();
        std::string msg = client->GetLastErrorMsg();
        return {rc,
                AMStr::amfmt("Open sftp file \"{}\" failed: {}", path, msg)};
      }
    } else {
      // Local file
#ifdef _WIN32
      DWORD access = is_write ? (GENERIC_READ | GENERIC_WRITE) : GENERIC_READ;
      DWORD share = is_write ? 0 : FILE_SHARE_READ;
      DWORD creation =
          is_write ? (truncate ? CREATE_ALWAYS : OPEN_EXISTING) : OPEN_EXISTING;
      DWORD flags =
          sequential ? FILE_FLAG_SEQUENTIAL_SCAN : FILE_ATTRIBUTE_NORMAL;

      file_handle = CreateFileW(AMStr::wstr(path).c_str(), access, share,
                                nullptr, creation, flags, nullptr);

      if (file_handle == INVALID_HANDLE_VALUE) {
        return {EC::LocalFileOpenError,
                AMStr::amfmt("Failed to open local file \"{}\": error code {}",
                             path, GetLastError())};
      }
#else
      int flags = is_write ? O_RDWR : O_RDONLY;
      if (is_write && truncate) {
        flags |= (O_CREAT | O_TRUNC);
      }
      file_handle = open(path.c_str(), flags, 0644);

      if (file_handle == -1) {
        return {EC::LocalFileOpenError,
                AMStr::amfmt("Failed to open local file \"{}\": {}", path,
                             strerror(errno))};
      }
#endif
    }

    return {EC::Success, ""};
  }

  [[nodiscard]] bool IsValid() const {
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

  /**
   * @brief Seek to the specified offset for subsequent reads/writes.
   */
  ECM Seek(size_t new_offset) {
    if (!IsValid()) {
      return {EC::LocalFileOpenError, "File not initialized"};
    }
    if (new_offset == 0) {
      offset = 0;
      return {EC::Success, ""};
    }
    if (is_sftp) {
      if (!client) {
        return {EC::InvalidArg, "SFTP client not available"};
      }
      std::lock_guard<std::recursive_mutex> lock(client->mtx);
      libssh2_sftp_seek64(sftp_handle,
                          static_cast<libssh2_uint64_t>(new_offset));
      offset = new_offset;
      return {EC::Success, ""};
    }
#ifdef _WIN32
    LARGE_INTEGER li;
    li.QuadPart = static_cast<LONGLONG>(new_offset);
    LARGE_INTEGER new_pos;
    if (!SetFilePointerEx(file_handle, li, &new_pos, FILE_BEGIN)) {
      return {EC::LocalFileReadError,
              AMStr::amfmt("Seek local file \"{}\" failed: error code {}", path,
                           GetLastError())};
    }
    offset = static_cast<size_t>(new_pos.QuadPart);
    return {EC::Success, ""};
#else
    off_t res = lseek(file_handle, static_cast<off_t>(new_offset), SEEK_SET);
    if (res == static_cast<off_t>(-1)) {
      return {EC::LocalFileReadError,
              AMStr::amfmt("Seek local file \"{}\" failed: {}", path,
                           strerror(errno))};
    }
    offset = static_cast<size_t>(res);
    return {EC::Success, ""};
#endif
  }

  std::pair<ssize_t, ECM> Read() {
    if (!IsValid()) {
      return {-1, {EC::LocalFileOpenError, "File not initialized"}};
    }
    if (!pd || !pd->ring_buffer) {
      return {-1, {EC::InvalidArg, "Progress data not initialized"}};
    }

    auto [write_ptr, max_write] = pd->ring_buffer->get_write_ptr();
    ssize_t to_read = std::min<ssize_t>(max_write, (file_size - offset));
    ssize_t bytes_read;
    if (to_read > 0) {
      if (is_sftp) {
        // SFTP read (non-blocking)
        while (true) {
          if (pd->is_terminate()) {
            return {-1, {EC::Terminate, "Task terminated by user"}};
          }
          while (pd->is_pause() && !pd->is_terminate()) {
            std::this_thread::sleep_for(std::chrono::milliseconds(20));
          }
          {
            std::lock_guard<std::recursive_mutex> lock(client->mtx);
            bytes_read = libssh2_sftp_read(sftp_handle, write_ptr, to_read);
          }
          if (bytes_read > 0) {
            pd->ring_buffer->commit_write(bytes_read);
            offset += bytes_read;
            return {bytes_read, {EC::Success, ""}};
          }
          if (bytes_read == 0) {
            return {0, {EC::EndOfFile, "End of file"}};
          }
          if (bytes_read == LIBSSH2_ERROR_EAGAIN) {
            WaitResult wr =
                client->wait_for_socket(SocketWaitType::Read, [this]() {
                  return pd && pd->is_terminate();
                });
            if (wr == WaitResult::Error) {
              return {
                  -1,
                  {wait_result_to_error_code(wr), "SFTP read socket error"}};
            }
            if (wr == WaitResult::Interrupted) {
              return {-1, {EC::Terminate, "Task terminated by user"}};
            }
            continue;
          }
          return {bytes_read,
                  {client->GetLastEC(),
                   AMStr::amfmt("Read sftp file \"{}\" failed: {}", path,
                                client->GetLastErrorMsg())}};
        }
      } else {
        // Local file read
#ifdef _WIN32
        DWORD bytes_read = 0;
        if (!ReadFile(file_handle, write_ptr, static_cast<DWORD>(to_read),
                      &bytes_read, nullptr)) {
          return {-1,
                  {EC::LocalFileReadError,
                   AMStr::amfmt("Read local file \"{}\" failed: error code {}",
                                path, GetLastError())}};
        }
        if (bytes_read > 0) {
          pd->ring_buffer->commit_write(bytes_read);
          offset += bytes_read;
          return {static_cast<int>(bytes_read), {EC::Success, ""}};
        } else {
          return {0, {EC::EndOfFile, "End of file"}};
        }
#else
        ssize_t bytes_read = read(file_handle, write_ptr, to_read);
        if (bytes_read > 0) {
          pd->ring_buffer->commit_write(bytes_read);
          offset += bytes_read;
          return {static_cast<int>(bytes_read), {EC::Success, ""}};
        } else if (bytes_read == 0) {
          return {0, {EC::EndOfFile, "End of file"}};
        } else {
          return {-1,
                  {EC::LocalFileReadError,
                   AMStr::amfmt("Read local file \"{}\" failed: {}", path,
                                strerror(errno))}};
        }
#endif
      }
    }
    return {0, {EC::Success, ""}};
  }

  std::pair<ssize_t, ECM> Write() {
    if (!IsValid()) {
      return {-1, {EC::LocalFileOpenError, "File not initialized"}};
    }
    if (!pd || !pd->ring_buffer) {
      return {-1, {EC::InvalidArg, "Progress data not initialized"}};
    }

    auto [read_ptr, max_read] = pd->ring_buffer->get_read_ptr();
    ssize_t to_write = std::min<ssize_t>(max_read, (file_size - offset));
    ssize_t bytes_written;
    if (to_write > 0) {
      if (is_sftp) {
        // SFTP write (non-blocking)
        while (true) {
          if (pd->is_terminate()) {
            return {-1, {EC::Terminate, "Task terminated by user"}};
          }
          while (pd->is_pause() && !pd->is_terminate()) {
            std::this_thread::sleep_for(std::chrono::milliseconds(20));
          }
          {
            std::lock_guard<std::recursive_mutex> lock(client->mtx);
            bytes_written = libssh2_sftp_write(sftp_handle, read_ptr, to_write);
          }
          if (bytes_written > 0) {
            pd->ring_buffer->commit_read(bytes_written);
            offset += bytes_written;
            return {bytes_written, {EC::Success, ""}};
          }
          if (bytes_written == 0) {
            return {0, {EC::EndOfFile, "End of file"}};
          }
          if (bytes_written == LIBSSH2_ERROR_EAGAIN) {
            WaitResult wr = client->wait_for_socket(
                SocketWaitType::Write,
                [this]() { return pd && pd->is_terminate(); }, am_ms(), 200);
            if (wr == WaitResult::Error) {
              return {
                  LIBSSH2_ERROR_EAGAIN,
                  {wait_result_to_error_code(wr), "SFTP write socket error"}};
            }
            if (wr == WaitResult::Interrupted) {
              return {-1, {EC::Terminate, "Task terminated by user"}};
            }
            continue;
          }
          EC rc = client->GetLastEC();
          std::string msg = client->GetLastErrorMsg();
          return {bytes_written,
                  {rc, AMStr::amfmt("Write sftp file \"{}\" failed: {}", path,
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
                   AMStr::amfmt("Write local file \"{}\" failed: error code {}",
                                path, GetLastError())}};
        }
        if (bytes_written > 0) {
          pd->ring_buffer->commit_read(bytes_written);
          offset += bytes_written;
          return {static_cast<int>(bytes_written), {EC::Success, ""}};
        } else {
          return {0, {EC::EndOfFile, "End of file"}};
        }
#else
        ssize_t bytes_written = write(file_handle, read_ptr, to_write);
        if (bytes_written > 0) {
          pd->ring_buffer->commit_read(bytes_written);
          offset += bytes_written;
          return {static_cast<int>(bytes_written), {EC::Success, ""}};
        } else if (bytes_written == 0) {
          return {0, {EC::EndOfFile, "End of file"}};
        } else {
          return {-1,
                  {EC::LocalFileWriteError,
                   AMStr::amfmt("Write local file \"{}\" failed: {}", path,
                                strerror(errno))}};
        }
#endif
      }
    }
    return {0, {EC::Success, ""}};
  }
};

using ECM = std::pair<ErrorCode, std::string>;
using EC = ErrorCode;

inline std::shared_ptr<BaseClient>
CreateClient(const ConRequst &requeset, ClientProtocol protocol,
             ssize_t trace_num = 10, TraceCallback trace_cb = {},
             ssize_t buffer_size = 8 * AMMB, std::vector<std::string> keys = {},
             AuthCallback auth_cb = {}) {
  if (protocol == ClientProtocol::SFTP) {
    auto client = std::make_shared<AMSFTPClient>(
        requeset, keys, trace_num, std::move(trace_cb), std::move(auth_cb));
    client->TransferRingBufferSize(buffer_size);
    return std::dynamic_pointer_cast<BaseClient>(client);
  } else if (protocol == ClientProtocol::FTP) {
    auto client = std::make_shared<AMFTPClient>(
        requeset, trace_num, std::move(trace_cb), std::move(auth_cb));
    client->TransferRingBufferSize(buffer_size);
    return std::dynamic_pointer_cast<BaseClient>(client);
  }
  return nullptr;
}

class ClientMaintainer {
private:
  std::atomic<bool> is_heartbeat;
  std::thread heartbeat_thread;

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
              CallCallbackSafe(disconnect_cb, host.second, rcm);
            }
          }
        }
      }
      while (millsecond < interval_s * 1000) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        millsecond += 100;
        if (!is_heartbeat.load(std::memory_order_acquire)) {
          return;
        }
      }
      millsecond = 0;
    }
  }

public:
  using DisconnectCallback =
      std::function<void(const std::shared_ptr<BaseClient> &, const ECM &)>;
  std::unordered_map<std::string, std::shared_ptr<BaseClient>> hosts;
  DisconnectCallback disconnect_cb;
  bool is_disconnect_cb = false;
  std::shared_ptr<AMLocalClient> local_client;
  ~ClientMaintainer() {
    is_heartbeat.store(false, std::memory_order_relaxed);
    if (heartbeat_thread.joinable()) {
      heartbeat_thread.join();
    }
  }

  std::shared_ptr<BaseClient> GetHost(const std::string &nickname) {
    if (nickname.empty() || AMStr::lowercase(nickname) == "local") {
      return local_client;
    }

    if (hosts.find(nickname) == hosts.end()) {
      return nullptr;
    }
    return hosts[nickname];
  }

  ClientMaintainer(int heartbeat_interval_s = 60,
                   DisconnectCallback disconnect_cb = {},
                   std::shared_ptr<AMLocalClient> local_client = nullptr,
                   std::unordered_map<std::string, std::shared_ptr<BaseClient>>
                       init_hosts = {}) {
    // 初始化本地客户端
    if (local_client && local_client->GetProtocol() == ClientProtocol::LOCAL) {
      this->local_client = std::move(local_client);
    } else {
      this->local_client =
          std::make_shared<AMLocalClient>(ConRequst("local", "", ""));
    }
    hosts = std::move(init_hosts);
    this->disconnect_cb = std::move(disconnect_cb);
    this->is_disconnect_cb = static_cast<bool>(this->disconnect_cb);

    if (heartbeat_interval_s < 0) {
      this->is_heartbeat.store(false, std::memory_order_relaxed);
      return;
    }

    this->is_heartbeat.store(true, std::memory_order_relaxed);
    heartbeat_thread = std::thread(
        [this, heartbeat_interval_s]() { HeartbeatAct(heartbeat_interval_s); });
  }

  /**
   * @brief Get nickname list of managed hosts.
   */
  std::vector<std::string> get_nicknames() {
    std::vector<std::string> host_list;
    for (auto &host : hosts) {
      host_list.push_back(host.first);
    }
    return host_list;
  }

  /**
   * @brief Get nickname list of managed hosts (const overload).
   */
  std::vector<std::string> get_nicknames() const {
    std::vector<std::string> host_list;
    for (const auto &host : hosts) {
      host_list.push_back(host.first);
    }
    return host_list;
  }

  /**
   * @brief Snapshot managed hosts.
   */
  std::unordered_map<std::string, std::shared_ptr<BaseClient>>
  get_hosts_snapshot() {
    std::lock_guard<std::recursive_mutex> lock(beat_mtx);
    return hosts;
  }

  std::shared_ptr<BaseClient> get_client(const std::string &nickname) {
    std::lock_guard<std::recursive_mutex> lock(beat_mtx);
    if (nickname.empty() || AMStr::lowercase(nickname) == "local") {
      return local_client;
    }
    auto it = hosts.find(nickname);
    if (it == hosts.end()) {
      return nullptr;
    }
    return it->second;
  }

  std::vector<std::shared_ptr<BaseClient>> get_clients() {
    std::vector<std::shared_ptr<BaseClient>> client_list{};
    std::lock_guard<std::recursive_mutex> lock(beat_mtx);
    if (local_client) {
      client_list.push_back(local_client);
    }
    client_list.reserve(client_list.size() + hosts.size());
    for (const auto &host : hosts) {
      client_list.push_back(host.second);
    }
    return client_list;
  }

  void add_client(const std::string &nickname,
                  std::shared_ptr<BaseClient> client, bool overwrite = false) {
    if (nickname.empty() || AMStr::lowercase(nickname) == "local") {
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
    if (nickname.empty() || AMStr::lowercase(nickname) == "local") {
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
    if (nickname.empty() || AMStr::lowercase(nickname) == "local") {
      return {ECM{EC::Success, ""}, local_client};
    }
    start_time = start_time == -1 ? am_ms() : start_time;
    ;
    if (hosts.find(nickname) == hosts.end()) {
      return {ECM{EC::ClientNotFound,
                  AMStr::amfmt("Client not found: {}", nickname)},
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

  void SetDisconnectCallback(DisconnectCallback callback = {}) {
    std::lock_guard<std::recursive_mutex> lock(beat_mtx);
    disconnect_cb = std::move(callback);
    is_disconnect_cb = static_cast<bool>(disconnect_cb);
  };
};

class AMConfigManager;
class AMClientManager;

class AMWorkManager {
private:
  using TaskId = std::string;

  std::atomic<bool> running_{true};
  std::atomic<size_t> desired_thread_count_{1};

  std::vector<std::thread> worker_threads_;

  std::mutex queue_mtx_;
  std::condition_variable queue_cv_;
  std::vector<std::list<TaskId>> affinity_queues_;
  std::list<TaskId> public_queue_;

  mutable std::mutex registry_mtx_;
  std::unordered_map<TaskId, std::shared_ptr<TaskInfo>> task_registry_;

  mutable std::mutex result_mtx_;
  std::unordered_map<TaskId, std::shared_ptr<TaskInfo>> results_;

  mutable std::mutex conducting_mtx_;
  std::unordered_set<TaskId> conducting_tasks_;
  std::vector<TaskId> conducting_by_thread_;
  std::vector<std::shared_ptr<TaskInfo>> conducting_infos_;
  size_t chunk_size_ = 256 * AMKB;
  std::atomic<bool> is_deconstruct{false};

  /**
   * @brief Clamp thread count to the supported range [1, 64].
   */
  static size_t ClampThreadCount(size_t count) {
    constexpr size_t kMinThreads = 1;
    constexpr size_t kMaxThreads = 64;
    return std::max<size_t>(kMinThreads, std::min<size_t>(count, kMaxThreads));
  }

  /**
   * @brief Check whether a thread ID is valid for affinity scheduling.
   */
  bool IsValidThreadId(int thread_id) const {
    const size_t active_count =
        desired_thread_count_.load(std::memory_order_relaxed);
    return thread_id >= 0 && static_cast<size_t>(thread_id) < active_count &&
           static_cast<size_t>(thread_id) < affinity_queues_.size();
  }

  /**
   * @brief Check whether a task id is already in use.
   */
  bool IsTaskIdUsed_(const TaskId &task_id) const {
    std::scoped_lock lock(registry_mtx_, result_mtx_, conducting_mtx_);
    if (task_registry_.find(task_id) != task_registry_.end()) {
      return true;
    }
    if (results_.find(task_id) != results_.end()) {
      return true;
    }
    return conducting_tasks_.find(task_id) != conducting_tasks_.end();
  }

  /**
   * @brief Generate a simple numeric task id that does not duplicate.
   */
  TaskId GenerateTaskId_() const {
    static std::atomic<uint64_t> counter{0};
    while (true) {
      const uint64_t value = counter.fetch_add(1, std::memory_order_relaxed);
      TaskId candidate = std::to_string(value);
      if (!IsTaskIdUsed_(candidate)) {
        return candidate;
      }
    }
  }

  /**
   * @brief Determine whether any pending tasks exist.
   *
   * This function assumes queue_mtx_ is already held.
   */
  bool HasPendingTasksLocked() const {
    if (!public_queue_.empty()) {
      return true;
    }
    for (const auto &queue : affinity_queues_) {
      if (!queue.empty()) {
        return true;
      }
    }
    return false;
  }

  /**
   * @brief Ensure progress data and inner callback are prepared.
   */
  void EnsureProgressData(const std::shared_ptr<TaskInfo> &task_info) {
    if (!task_info->pd) {
      task_info->pd = std::make_shared<WkProgressData>(task_info);
    }
    if (!task_info->pd->inner_callback) {
      std::weak_ptr<TaskInfo> ti_w = task_info;
      std::weak_ptr<WkProgressData> pd_w = task_info->pd;
      task_info->pd->inner_callback = [this, ti_w, pd_w](bool force) {
        auto ti_s = ti_w.lock();
        auto pd_s = pd_w.lock();
        if (!ti_s || !pd_s) {
          return;
        }
        this->InnerCallback(ti_s, *pd_s, force);
      };
    }
    task_info->pd->task_info = task_info;
  }

  /**
   * @brief Register a task and enqueue it into the appropriate queue.
   */
  void RegisterTask(const std::shared_ptr<TaskInfo> &task_info,
                    TaskAssignType assign_type, int affinity_thread) {
    std::scoped_lock<std::mutex, std::mutex> lock(registry_mtx_, queue_mtx_);
    std::list<TaskId> *target_queue = nullptr;
    if (assign_type == TaskAssignType::Affinity &&
        IsValidThreadId(affinity_thread)) {
      target_queue = &affinity_queues_[static_cast<size_t>(affinity_thread)];
    } else {
      assign_type = TaskAssignType::Public;
      affinity_thread = -1;
      target_queue = &public_queue_;
    }

    target_queue->push_back(task_info->id);

    task_info->assign_type.store(assign_type, std::memory_order_relaxed);
    task_info->affinity_thread.store(affinity_thread,
                                     std::memory_order_relaxed);
    task_info->OnWhichThread.store(-1, std::memory_order_relaxed);
    task_registry_[task_info->id] = task_info;
  }

  /**
   * @brief Dequeue a task for a specific worker thread.
   */
  std::optional<std::pair<TaskId, std::shared_ptr<TaskInfo>>>
  DequeueTask(size_t thread_index) {
    while (true) {
      {
        std::unique_lock<std::mutex> lock(queue_mtx_);
        queue_cv_.wait(lock, [this, thread_index]() {
          return !running_.load(std::memory_order_acquire) ||
                 HasPendingTasksLocked() ||
                 thread_index >=
                     desired_thread_count_.load(std::memory_order_relaxed);
        });

        if (!running_.load(std::memory_order_relaxed) &&
            !HasPendingTasksLocked()) {
          return std::nullopt;
        }

        if (thread_index >=
            desired_thread_count_.load(std::memory_order_relaxed)) {
          const bool has_affinity = thread_index < affinity_queues_.size() &&
                                    !affinity_queues_[thread_index].empty();
          if (!has_affinity) {
            return std::nullopt;
          }
        }

        TaskId task_id;
        if (thread_index < affinity_queues_.size() &&
            !affinity_queues_[thread_index].empty()) {
          task_id = affinity_queues_[thread_index].front();
          affinity_queues_[thread_index].pop_front();
        } else if (!public_queue_.empty()) {
          task_id = public_queue_.front();
          public_queue_.pop_front();
        } else {
          continue;
        }

        lock.unlock();

        std::lock_guard<std::mutex> registry_lock(registry_mtx_);
        auto it = task_registry_.find(task_id);
        if (it == task_registry_.end()) {
          continue;
        }
        auto task_info = it->second;
        // task_registry_.erase(it);
        return {{task_id, task_info}};
      }
    }
  }

  /**
   * @brief Store a completed task or invoke its result callback.
   */
  void HandleCompletedTask(const std::shared_ptr<TaskInfo> &task_info) {
    if (task_info->result_callback) {
      CallCallbackSafe(task_info->result_callback, task_info);
      return;
    }
    std::lock_guard<std::mutex> lock(result_mtx_);
    results_[task_info->id] = task_info;
  }

  /**
   * @brief Mark a task as currently conducting on a worker thread.
   */
  void SetConducting(size_t thread_index, const TaskId &task_id,
                     const std::shared_ptr<TaskInfo> &task_info) {
    std::lock_guard<std::mutex> lock(conducting_mtx_);
    if (thread_index >= conducting_by_thread_.size()) {
      conducting_by_thread_.resize(thread_index + 1);
      conducting_infos_.resize(thread_index + 1);
    }
    conducting_by_thread_[thread_index] = task_id;
    conducting_infos_[thread_index] = task_info;
    conducting_tasks_.insert(task_id);
  }

  /**
   * @brief Clear conducting state for a worker thread.
   */
  void ClearConducting(size_t thread_index) {
    std::lock_guard<std::mutex> lock(conducting_mtx_);
    if (thread_index < conducting_by_thread_.size()) {
      const TaskId id = conducting_by_thread_[thread_index];
      if (!id.empty()) {
        conducting_tasks_.erase(id);
      }
      conducting_by_thread_[thread_index].clear();
      conducting_infos_[thread_index] = nullptr;
    }
  }

  // Internal progress callback wrapper
  void InnerCallback(std::shared_ptr<TaskInfo> task_info, WkProgressData &pd,
                     bool force = false) {
    if (!task_info->callback.need_progress_cb) {
      return;
    }
    TransferTask *cur_task = nullptr;
    {
      std::lock_guard<std::mutex> lock(task_info->mtx);
      cur_task = task_info->cur_task;
    }
    if (!cur_task) {
      return;
    }

    auto time_now = timenow();
    if (!force &&
        ((time_now - pd.cb_time) <= task_info->callback.cb_interval_s)) {
      return;
    }

    pd.cb_time = time_now;
    ECM cb_error = {EC::Success, ""};
    auto ctrl_opt = task_info->callback.CallProgress(
        ProgressCBInfo(
            cur_task->src, cur_task->dst, cur_task->src_host,
            cur_task->dst_host, cur_task->transferred, cur_task->size,
            task_info->total_transferred_size.load(std::memory_order_relaxed),
            task_info->total_size.load(std::memory_order_relaxed)),
        &cb_error);

    if (cb_error.first != EC::Success && task_info->callback.need_error_cb) {
      task_info->callback.CallError(
          ErrorCBInfo(cb_error, cur_task->src, cur_task->dst,
                      cur_task->src_host, cur_task->dst_host));
    }

    if (!ctrl_opt.has_value()) {
      return;
    }

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

  // Check if task should be skipped (terminated before conducting)
  bool ShouldSkipTask(std::shared_ptr<TaskInfo> task_info) {
    if (task_info->pd && task_info->pd->is_terminate_only()) {
      task_info->SetResult({EC::Terminate, "Task terminated before start"});
      task_info->SetStatus(TaskStatus::Finished);
      task_info->finished_time.store(timenow(), std::memory_order_relaxed);
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
        return {ECM{EC::NoSession, AMStr::amfmt("Source host \"{}\" not found",
                                                task.src_host)},
                nullptr, nullptr};
      }
      rcm = src_client->Check();
      if (rcm.first != EC::Success) {
        return {
            ECM{rcm.first, AMStr::amfmt("Source host \"{}\" connection error",
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
            ECM{EC::NoSession, AMStr::amfmt("Destination host \"{}\" not found",
                                            task.dst_host)},
            nullptr, nullptr};
      }
      rcm = dst_client->Check();
      if (rcm.first != EC::Success) {
        return {ECM{rcm.first,
                    AMStr::amfmt("Destination host \"{}\" connection error",
                                 task.dst_host)},
                nullptr, nullptr};
      }
    } else {
      dst_client = hostm->local_client;
    }
    return {rcm, src_client, dst_client};
  }

  // Transit for SFTP same-host copy (non-blocking read/write)
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

    auto src_open = client->nb_call(
        std::function<bool()>([&]() { return pd.is_terminate(); }), -1, am_ms(),
        [&]() {
          return libssh2_sftp_open(client->sftp, task->src.c_str(),
                                   LIBSSH2_FXF_READ, 0400);
        });
    LIBSSH2_SFTP_HANDLE *srcFile = src_open.value;
    if (!srcFile) {
      EC rc = client->GetLastEC();
      std::string msg = client->GetLastErrorMsg();
      return {rc, AMStr::amfmt("Failed to open src file \"{}\": {}", task->src,
                               msg)};
    }

    const size_t resume_offset = task->transferred;
    int dst_flags = LIBSSH2_FXF_WRITE;
    if (resume_offset == 0) {
      dst_flags |= LIBSSH2_FXF_CREAT | LIBSSH2_FXF_TRUNC;
    }
    auto dst_open = client->nb_call(
        std::function<bool()>([&]() { return pd.is_terminate(); }), -1, am_ms(),
        [&]() {
          return libssh2_sftp_open(client->sftp, task->dst.c_str(), dst_flags,
                                   0744);
        });
    LIBSSH2_SFTP_HANDLE *dstFile = dst_open.value;
    if (!dstFile) {
      libssh2_sftp_close_handle(srcFile);
      EC rc = client->GetLastEC();
      std::string msg = client->GetLastErrorMsg();
      return {rc, AMStr::amfmt("Failed to open dst file \"{}\": {}", task->dst,
                               msg)};
    }

    libssh2_session_set_blocking(client->session, 0);
    std::vector<char> buffer(chunk_size_);
    size_t total_written = resume_offset;
    ssize_t bytes_read, bytes_written;

    if (resume_offset > 0) {
      libssh2_sftp_seek64(srcFile,
                          static_cast<libssh2_uint64_t>(resume_offset));
      libssh2_sftp_seek64(dstFile,
                          static_cast<libssh2_uint64_t>(resume_offset));
    }

    while (total_written < task->size) {
      if (pd.is_terminate()) {
        rcm = {EC::Terminate, "Transfer interrupted by user"};
        goto clean;
      }
      while (pd.is_pause() && !pd.is_terminate()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
      }

      size_t to_read =
          std::min<size_t>(chunk_size_, task->size - total_written);
      size_t buffer_filled = 0;
      while (buffer_filled < to_read) {
        bytes_read = libssh2_sftp_read(srcFile, buffer.data() + buffer_filled,
                                       to_read - buffer_filled);
        if (bytes_read > 0) {
          buffer_filled += bytes_read;
        } else if (bytes_read == 0) {
          break;
        } else if (bytes_read == LIBSSH2_ERROR_EAGAIN) {
          WaitResult wr = client->wait_for_socket(
              SocketWaitType::Read, [&]() { return pd.is_terminate(); },
              am_ms(), 200);
          if (wr == WaitResult::Interrupted) {
            rcm = {EC::Terminate, "Transfer interrupted by user"};
            goto clean;
          }
          if (wr == WaitResult::Error) {
            rcm = {wait_result_to_error_code(wr), "SFTP read socket error"};
            goto clean;
          }
          continue;
        } else {
          EC rc = client->GetLastEC();
          std::string msg = client->GetLastErrorMsg();
          rcm = {rc, AMStr::amfmt("Read error: {}", msg)};
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
          task_info->total_transferred_size.fetch_add(
              static_cast<size_t>(bytes_written), std::memory_order_relaxed);
          task_info->this_task_transferred_size.store(
              total_written, std::memory_order_relaxed);
          task->transferred = task_info->this_task_transferred_size.load(
              std::memory_order_relaxed);
          InnerCallback(task_info, pd, false);
        } else if (bytes_written == 0) {
          break;
        } else if (bytes_written == LIBSSH2_ERROR_EAGAIN) {
          WaitResult wr = client->wait_for_socket(
              SocketWaitType::Write, [&]() { return pd.is_terminate(); },
              am_ms(), 200);
          if (wr == WaitResult::Interrupted) {
            rcm = {EC::Terminate, "Transfer interrupted by user"};
            goto clean;
          }
          if (wr == WaitResult::Error) {
            rcm = {wait_result_to_error_code(wr), "SFTP write socket error"};
            goto clean;
          }
          continue;
        } else {
          EC rc = client->GetLastEC();
          std::string msg = client->GetLastErrorMsg();
          rcm = {rc, AMStr::amfmt("Write error: {}", msg)};
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
      ECM rcm = file_handle.Init(task->src, task->size, clientf, false, true,
                                 true, &pd);
      if (rcm.first != EC::Success) {
        pd.set_terminate();
        task->rcm = rcm;
        return;
      }
      if (task->transferred > 0) {
        ECM seek_rcm = file_handle.Seek(task->transferred);
        if (seek_rcm.first != EC::Success) {
          pd.set_terminate();
          task->rcm = seek_rcm;
          return;
        }
      }
      std::lock_guard<std::recursive_mutex> lock(clientf->mtx);
      libssh2_session_set_blocking(clientf->session, 0);
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
        auto [bytes_read, ecm] = file_handle.Read();
        if (ecm.first != EC::Success && ecm.first != EC::EndOfFile) {
          pd.set_terminate();
          task->rcm = ecm;
          return;
        }
      }
    } else if (client->GetProtocol() == ClientProtocol::LOCAL) {
      UnionFileHandle file_handle;
      ECM rcm = file_handle.Init(task->src, task->size, nullptr, false, true,
                                 true, &pd);
      if (rcm.first != EC::Success) {
        pd.set_terminate();
        task->rcm = rcm;
        return;
      }
      if (task->transferred > 0) {
        ECM seek_rcm = file_handle.Seek(task->transferred);
        if (seek_rcm.first != EC::Success) {
          pd.set_terminate();
          task->rcm = seek_rcm;
          return;
        }
      }
      while (file_handle.offset < file_handle.file_size) {
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
        auto [bytes_read, ecm] = file_handle.Read();
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
      const bool resume = task->transferred > 0;
      ECM rcm = file_handle.Init(task->dst, task->size, clientf, true, true,
                                 !resume, &pd);
      if (rcm.first != EC::Success) {
        pd.set_terminate();
        task->rcm = rcm;
        return;
      }
      if (resume) {
        ECM seek_rcm = file_handle.Seek(task->transferred);
        if (seek_rcm.first != EC::Success) {
          pd.set_terminate();
          task->rcm = seek_rcm;
          return;
        }
      }
      libssh2_session_set_blocking(clientf->session, 0);
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
        auto [bytes_write, ecm] = file_handle.Write();
        if (ecm.first != EC::Success && ecm.first != EC::EndOfFile) {
          pd.set_terminate();
          task->rcm = ecm;
          return;
        }
        if (bytes_write > 0) {
          task_info->total_transferred_size.fetch_add(
              static_cast<size_t>(bytes_write), std::memory_order_relaxed);
          task_info->this_task_transferred_size.store(
              static_cast<size_t>(file_handle.offset),
              std::memory_order_relaxed);
        }
        task->transferred = task_info->this_task_transferred_size.load(
            std::memory_order_relaxed);
        InnerCallback(task_info, pd, false);
      }
    } else if (client->GetProtocol() == ClientProtocol::LOCAL) {
      UnionFileHandle file_handle;
      const bool resume = task->transferred > 0;
      ECM rcm = file_handle.Init(task->dst, task->size, nullptr, true, true,
                                 !resume, &pd);
      if (rcm.first != EC::Success) {
        pd.set_terminate();
        task->rcm = rcm;
        return;
      }
      if (resume) {
        ECM seek_rcm = file_handle.Seek(task->transferred);
        if (seek_rcm.first != EC::Success) {
          pd.set_terminate();
          task->rcm = seek_rcm;
          return;
        }
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
        auto [bytes_write, ecm] = file_handle.Write();
        if (ecm.first != EC::Success && ecm.first != EC::EndOfFile) {
          pd.set_terminate();
          task->rcm = ecm;
          return;
        }
        if (bytes_write > 0) {
          task_info->total_transferred_size.fetch_add(
              static_cast<size_t>(bytes_write), std::memory_order_relaxed);
          task_info->this_task_transferred_size.store(
              static_cast<size_t>(file_handle.offset),
              std::memory_order_relaxed);
        }
        task->transferred = task_info->this_task_transferred_size.load(
            std::memory_order_relaxed);
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
      TransferTask *cur_task = nullptr;
      if (ti) {
        std::lock_guard<std::mutex> lock(ti->mtx);
        cur_task = ti->cur_task;
      }
      if (cur_task && cur_task->transferred >= cur_task->size) {
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
          if (cur_task) {
            const size_t delta = static_cast<size_t>(to_read);
            const size_t total = ti->this_task_transferred_size.fetch_add(
                                     delta, std::memory_order_relaxed) +
                                 delta;
            cur_task->transferred = total;
            ti->total_transferred_size.fetch_add(static_cast<size_t>(to_read),
                                                 std::memory_order_relaxed);
          }
          pd->CallInnerCallback(false);
          return to_read;
        } catch (const std::exception &e) {
          pd->set_terminate();
          if (cur_task) {
            cur_task->rcm = ECM{EC::BufferReadError, e.what()};
          }
          return CURL_READFUNC_ABORT;
        }
      } else if (to_read < 0) {
        pd->set_terminate();
        if (cur_task) {
          cur_task->rcm =
              ECM{EC::BufferReadError, "Get negative value for data size"};
        }
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
          TransferTask *cur_task = nullptr;
          if (ti) {
            std::lock_guard<std::mutex> lock(ti->mtx);
            cur_task = ti->cur_task;
          }
          if (cur_task) {
            cur_task->rcm = ECM{EC::BufferWriteError, e.what()};
          }
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
    auto ti = pd->task_info.lock();
    TransferTask *cur_task = nullptr;
    if (ti) {
      std::lock_guard<std::mutex> tlock(ti->mtx);
      cur_task = ti->cur_task;
    }
    if (!cur_task) {
      pd->set_terminate();
      return;
    }
    const size_t resume_offset = cur_task->transferred;
    ECM ecm = client->SetupPath(dst, false);
    if (ecm.first != EC::Success) {
      cur_task->rcm = ecm;
      pd->set_terminate();
      return;
    }
    CURL *curl = client->GetCURL();
    curl_easy_setopt(curl, CURLOPT_UPLOAD, 1L);
    curl_easy_setopt(curl, CURLOPT_READFUNCTION, read_callback);
    curl_easy_setopt(curl, CURLOPT_READDATA, pd);
    curl_easy_setopt(curl, CURLOPT_RESUME_FROM_LARGE,
                     static_cast<curl_off_t>(resume_offset));
    curl_easy_setopt(
        curl, CURLOPT_INFILESIZE_LARGE,
        static_cast<curl_off_t>(resume_offset < cur_task->size
                                    ? (cur_task->size - resume_offset)
                                    : 0));
    curl_easy_setopt(curl, CURLOPT_FTP_CREATE_MISSING_DIRS, CURLFTP_CREATE_DIR);

    CURLcode res = curl_easy_perform(curl);

    if (res == CURLE_ABORTED_BY_CALLBACK || res == CURLE_WRITE_ERROR) {
      pd->set_terminate();
    } else if (res != CURLE_OK) {
      cur_task->rcm =
          ECM{EC::FTPUploadFailed,
              AMStr::amfmt("Upload failed: {}", curl_easy_strerror(res))};
      pd->set_terminate();
    }
  }

  // Download with ProgressData (legacy - for AMSFTPWorker)
  static void FTPDownloadSet(std::shared_ptr<AMFTPClient> client,
                             const std::string &src,
                             curl_write_callback write_callback,
                             WkProgressData *pd) {
    std::lock_guard<std::recursive_mutex> lock(client->mtx);
    auto ti = pd->task_info.lock();
    TransferTask *cur_task = nullptr;
    if (ti) {
      std::lock_guard<std::mutex> tlock(ti->mtx);
      cur_task = ti->cur_task;
    }
    if (!cur_task) {
      pd->set_terminate();
      return;
    }
    const size_t resume_offset = cur_task->transferred;
    ECM ecm = client->SetupPath(src, false);
    if (ecm.first != EC::Success) {
      cur_task->rcm = ecm;
      pd->set_terminate();
      return;
    }
    auto curl = client->GetCURL();
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, pd);
    curl_easy_setopt(curl, CURLOPT_RESUME_FROM_LARGE,
                     static_cast<curl_off_t>(resume_offset));
    CURLcode res = curl_easy_perform(curl);
    if (res == CURLE_ABORTED_BY_CALLBACK || res == CURLE_WRITE_ERROR) {
      pd->set_terminate();
    } else if (res != CURLE_OK) {
      cur_task->rcm =
          ECM{EC::FTPDownloadFailed,
              AMStr::amfmt("Download failed: {}", curl_easy_strerror(res))};
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
    int bb = 1;

    if (reading_thread.joinable()) {
      reading_thread.join();
    }

    task->transferred =
        task_info->this_task_transferred_size.load(std::memory_order_relaxed);
    if (task->rcm.first != EC::Success) {
      return task->rcm;
    }
    if (task->transferred >= task->size) {
      return task->rcm;
    } else if (pd.is_pause_only()) {
      return {EC::TransferPause, "Task paused by user"};
    } else if (pd.is_terminate_only()) {
      return {EC::Terminate, "Task terminated by user"};
    }
    return {EC::UnknownError, "Task not finished but exited unexpectedly"};
  }

  /**
   * @brief Worker thread function with affinity-aware scheduling.
   */
  void WorkerLoop(size_t thread_index) {
    while (running_.load(std::memory_order_relaxed)) {
      if (thread_index >=
          desired_thread_count_.load(std::memory_order_relaxed)) {
        std::lock_guard<std::mutex> lock(queue_mtx_);
        const bool has_affinity = thread_index < affinity_queues_.size() &&
                                  !affinity_queues_[thread_index].empty();
        if (!has_affinity) {
          break;
        }
      }

      auto task_opt = DequeueTask(thread_index);
      if (!task_opt.has_value()) {
        break;
      }

      const auto &[task_id, task_info] = *task_opt;
      SetConducting(thread_index, task_id, task_info);
      task_info->OnWhichThread.store(static_cast<int>(thread_index),
                                     std::memory_order_relaxed);

      if (ShouldSkipTask(task_info)) {
        task_info->OnWhichThread.store(-1, std::memory_order_relaxed);
        HandleCompletedTask(task_info);
        ClearConducting(thread_index);
        continue;
      }

      EnsureProgressData(task_info);
      ExecuteTask(task_info);
      task_info->DeleteProgressData();
      // task_info->OnWhichThread.store(-1);

      if (running_.load(std::memory_order_relaxed) &&
          task_info->GetStatus() != TaskStatus::Paused) {
        HandleCompletedTask(task_info);
      }
      ClearConducting(thread_index);
    }

    // Ensure this worker is not reported as executing any task.
    // The task clears OnWhichThread on exit paths above.
    ClearConducting(thread_index);
  }

  // Execute a single TaskInfo
  void ExecuteTask(std::shared_ptr<TaskInfo> task_info) {
    task_info->SetStatus(TaskStatus::Conducting);
    if (!task_info->keep_start_time.load(std::memory_order_relaxed) ||
        task_info->start_time.load(std::memory_order_relaxed) <= 0.0) {
      task_info->start_time.store(timenow(), std::memory_order_relaxed);
    }

    if (task_info->callback.need_total_size_cb) {
      task_info->callback.CallTotalSize(
          task_info->total_size.load(std::memory_order_relaxed));
    }

    auto &pd = *(task_info->pd);
    pd.task_info = task_info;

    if (!task_info->tasks) {
      task_info->SetStatus(TaskStatus::Finished);
      task_info->SetResult({EC::InvalidArg, "No task is provided"});
      task_info->finished_time.store(timenow(), std::memory_order_relaxed);
      return;
    }

    for (auto &task : *(task_info->tasks)) {
      // Check terminate/pause before each file
      if (pd.is_pause_only()) {
        task_info->SetStatus(TaskStatus::Paused);
        task_info->keep_start_time.store(true, std::memory_order_relaxed);
        return;
      } else if (pd.is_terminate_only()) {
        task.rcm = {EC::Terminate, "Task terminated by user"};
        task.IsFinished = true;
        continue;
      }

      if (task.IsFinished) {
        continue;
      }

      auto hostm_locked = task_info->hostm;
      if (!hostm_locked) {
        task.rcm = {EC::ClientNotFound, "ClientMaintainer expired"};
        task.IsFinished = true;
        if (task_info->callback.need_error_cb) {
          task_info->callback.CallError(ErrorCBInfo(
              task.rcm, task.src, task.dst, task.src_host, task.dst_host));
        }
        continue;
      }
      auto test_res = TestHost(task, hostm_locked);
      ECM rcm = std::get<0>(test_res);
      if (rcm.first != EC::Success) {
        task.rcm = rcm;
        task.IsFinished = true;
        if (task_info->callback.need_error_cb) {
          task_info->callback.CallError(ErrorCBInfo(
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
      task_info->SetCurrentTask(&task);
      task.rcm = ECM(EC::Success, "");
      size_t resume_offset = task.transferred;
      bool resume_ok = false;

      // offset check
      if (resume_offset > 0) {
        if (resume_offset > task.size) {
          task.rcm = {EC::InvalidOffset, "Offset exceeds src size"};
          task.IsFinished = true;
          if (task_info->callback.need_error_cb) {
            task_info->callback.CallError(ErrorCBInfo(
                task.rcm, task.src, task.dst, task.src_host, task.dst_host));
          }
          continue;
        }
        auto [dst_rcm, dst_info] = dst_client->stat(task.dst, false);
        if (dst_rcm.first != EC::Success) {
          task.rcm = {EC::InvalidOffset, "Dst stat failed but offset is given"};
          task.IsFinished = true;
          goto OffsetErrorCB;
        }
        if (dst_info.type == PathType::DIR) {
          task.rcm = {EC::NotAFile, "Dst already exists but is a directory"};
          task.IsFinished = true;
          goto OffsetErrorCB;
        }
        if (resume_offset > dst_info.size) {
          task.rcm = {EC::InvalidOffset, "Offset exceeds dst file size"};
          task.IsFinished = true;
          goto OffsetErrorCB;
        }
        goto PassOffsetCheck;
      OffsetErrorCB:
        if (task_info->callback.need_error_cb) {
          task_info->callback.CallError(ErrorCBInfo(
              task.rcm, task.src, task.dst, task.src_host, task.dst_host));
        }
        continue;
      }
    PassOffsetCheck:
      task_info->this_task_transferred_size.store(resume_offset,
                                                  std::memory_order_relaxed);
      if (resume_offset > 0) {
        task_info->total_transferred_size.fetch_add(resume_offset,
                                                    std::memory_order_relaxed);
      }

      if (src_client->GetUID() == dst_client->GetUID() &&
          src_client->GetProtocol() == ClientProtocol::SFTP) {
        pd.ring_buffer = nullptr;
      } else {
        pd.ring_buffer = std::make_shared<StreamRingBuffer>(CalculateBufferSize(
            src_client, dst_client,
            task_info->buffer_size.load(std::memory_order_relaxed)));
      }

      task.rcm = TransferSingleFile(src_client, dst_client, task_info);
      if (pd.is_pause_only()) {
        task.rcm = {EC::TransferPause, "Task paused by user"};
        task_info->SetStatus(TaskStatus::Paused);
        task_info->keep_start_time.store(true, std::memory_order_relaxed);
        return;
      }
      task.IsFinished = true;
      if (task.rcm.first == EC::Success) {
        task_info->success_filenum.fetch_add(1, std::memory_order_relaxed);
      } else if (task.rcm.first != EC::Success &&
                 task_info->callback.need_error_cb &&
                 task.rcm.first != EC::Terminate &&
                 task.rcm.first != EC::TransferPause) {
        task_info->callback.CallError(ErrorCBInfo(
            task.rcm, task.src, task.dst, task.src_host, task.dst_host));
      }

      InnerCallback(task_info, pd, true);
    }

    if (!task_info->pd->is_terminate_only()) {
      bool any_error = false;
      for (auto &task : *(task_info->tasks)) {
        if (task.rcm.first != EC::Success) {
          any_error = true;
          task_info->SetResult(task.rcm); // Last error
          break;
        }
      }
      if (!any_error) {
        task_info->SetResult({EC::Success, ""});
      }
    } else {
      task_info->SetResult({EC::Terminate, "Task terminated by user"});
    }
    task_info->SetStatus(TaskStatus::Finished);
    task_info->finished_time.store(timenow(), std::memory_order_relaxed);
  }

public:
  /**
   * @brief Construct a work manager with a default single worker thread.
   */
  AMWorkManager() {
    affinity_queues_.resize(1);
    conducting_by_thread_.resize(1);
    conducting_infos_.resize(1);
    worker_threads_.emplace_back([this]() { WorkerLoop(0); });
  }

  /**
   * @brief Stop all workers and join their threads.
   */
  ~AMWorkManager() { GracefulTerminate(); }

  /**
   * @brief Gracefully terminate pending/conducting tasks and stop workers.
   *
   * @param timeout_ms Max wait time for conducting tasks; negative to wait
   * forever.
   * @return ECM result (timeout when tasks remain conducting).
   */
  ECM GracefulTerminate(int timeout_ms = 5000) {
    if (is_deconstruct.load(std::memory_order_relaxed)) {
      return {EC::Success, ""};
    }
    running_.store(false, std::memory_order_relaxed);
    queue_cv_.notify_all();
    {
      std::lock_guard<std::mutex> lock(conducting_mtx_);
      for (const auto &info : conducting_infos_) {
        if (info && info->pd) {
          info->pd->set_terminate();
        }
      }
    }

    const int64_t start = am_ms();
    while (is_conducting()) {
      if (timeout_ms >= 0 && (am_ms() - start) > timeout_ms) {
        return {EC::OperationTimeout, "Graceful terminate timed out"};
      }
      std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }

    for (auto &thread : worker_threads_) {
      if (thread.joinable()) {
        thread.join();
      }
    }
    is_deconstruct.store(true, std::memory_order_relaxed);
    return {EC::Success, ""};
  }

  /**
   * @brief Set or get the chunk size used by transit transfers.
   */
  size_t ChunkSize(int64_t size = -1) {
    if (size < 32 * AMKB) {
      return chunk_size_;
    }
    this->chunk_size_ = std::min<size_t>(static_cast<size_t>(size), 4 * AMMB);
    return chunk_size_;
  }

  /**
   * @brief Adjust or query the worker thread count.
   */
  size_t ThreadCount(size_t new_count = 0) {
    if (new_count == 0) {
      return desired_thread_count_.load(std::memory_order_relaxed);
    }

    new_count = ClampThreadCount(new_count);
    const size_t current =
        desired_thread_count_.load(std::memory_order_relaxed);
    if (new_count == current) {
      return current;
    }

    if (new_count > current) {
      {
        std::lock_guard<std::mutex> lock(queue_mtx_);
        if (new_count > affinity_queues_.size()) {
          affinity_queues_.resize(new_count);
        }
      }
      {
        std::lock_guard<std::mutex> lock(conducting_mtx_);
        if (new_count > conducting_by_thread_.size()) {
          conducting_by_thread_.resize(new_count);
          conducting_infos_.resize(new_count);
        }
      }

      desired_thread_count_.store(new_count, std::memory_order_relaxed);
      const size_t existing_threads = worker_threads_.size();
      for (size_t idx = existing_threads; idx < new_count; ++idx) {
        worker_threads_.emplace_back([this, idx]() { WorkerLoop(idx); });
      }
      queue_cv_.notify_all();
      return new_count;
    }

    desired_thread_count_.store(new_count, std::memory_order_relaxed);
    queue_cv_.notify_all();
    return new_count;
  }

  // former is occupied, latter is idle
  std::pair<std::vector<size_t>, std::vector<size_t>> get_thread_ids() {
    std::vector<size_t> occupied;
    std::vector<size_t> idle;
    const size_t count = desired_thread_count_.load(std::memory_order_relaxed);
    occupied.reserve(count);
    idle.reserve(count);
    std::lock_guard<std::mutex> lock(conducting_mtx_);
    for (size_t i = 0; i < count; ++i) {
      const bool busy =
          i < conducting_by_thread_.size() && !conducting_by_thread_[i].empty();
      if (busy) {
        occupied.push_back(i);
      } else {
        idle.push_back(i);
      }
    }
    return {occupied, idle};
  }

  /**
   * @brief Submit an already-constructed TaskInfo object.
   */
  ECM submit(std::shared_ptr<TaskInfo> task_info) {
    if (!task_info) {
      return {EC::InvalidArg, "TaskInfo is nullptr"};
    }
    if (!task_info->tasks || task_info->tasks->empty()) {
      return {EC::InvalidArg, "Tasks is nullptr or empty"};
    }

    if (task_info->id.empty() || IsTaskIdUsed_(task_info->id)) {
      task_info->id = GenerateTaskId_();
    }
    task_info->submit_time.store(timenow(), std::memory_order_relaxed);
    task_info->SetStatus(TaskStatus::Pending);

    task_info->CalTotalSize();
    task_info->CalFileNum();

    task_info->total_transferred_size.store(0, std::memory_order_relaxed);
    task_info->OnWhichThread.store(-1, std::memory_order_relaxed);

    const int requested_thread_id =
        task_info->affinity_thread.load(std::memory_order_relaxed);
    const bool affinity_valid = IsValidThreadId(requested_thread_id);
    const TaskAssignType assign_type =
        affinity_valid ? TaskAssignType::Affinity : TaskAssignType::Public;
    const int affinity_id = affinity_valid ? requested_thread_id : -1;

    RegisterTask(task_info, assign_type, affinity_id);
    queue_cv_.notify_all();
    return {EC::Success, ""};
  }

  /**
   * @brief Compatibility overload that builds a TaskInfo and submits it.
   */
  std::shared_ptr<TaskInfo>
  cre_taskinfo(std::shared_ptr<TASKS> tasks,
               const std::shared_ptr<ClientMaintainer> &hostm,
               TransferCallback callback = TransferCallback(),
               ssize_t buffer_size = -1, bool quiet = false,
               int thread_id = -1) {
    auto task_info = std::make_shared<TaskInfo>(quiet);
    task_info->id = GenerateTaskId_();
    task_info->tasks = tasks;
    task_info->CalTotalSize();
    task_info->CalFileNum();

    task_info->hostm = hostm;
    task_info->callback = callback;
    task_info->buffer_size.store(buffer_size, std::memory_order_relaxed);
    task_info->affinity_thread.store(thread_id, std::memory_order_relaxed);
    return task_info;
  }

  /**
   * @brief Query task status by ID.
   */
  std::optional<TaskStatus> get_status(const TaskId &id) {
    {
      std::lock_guard<std::mutex> lock(registry_mtx_);
      auto it = task_registry_.find(id);
      if (it != task_registry_.end() && it->second) {
        return it->second->GetStatus();
      }
    }
    // {
    //   std::lock_guard<std::mutex> lock(conducting_mtx_);
    //   for (size_t idx = 0; idx < conducting_tasks_.size(); ++idx) {
    //     if (conducting_tasks_[idx] == id && conducting_infos_[idx]) {
    //       return conducting_infos_[idx]->GetStatus();
    //     }
    //   }
    // }
    {
      std::lock_guard<std::mutex> lock(result_mtx_);
      auto it = results_.find(id);
      if (it != results_.end() && it->second) {
        return it->second->GetStatus();
      }
    }
    return std::nullopt;
  }

  /**
   * @brief Query task result and optionally remove it from the cache.
   */
  std::shared_ptr<TaskInfo> get_result(const TaskId &id, bool remove = true) {
    std::lock_guard<std::mutex> lock(result_mtx_);
    auto it = results_.find(id);
    if (it == results_.end()) {
      return nullptr;
    }
    auto task_info = it->second;
    if (remove) {
      results_.erase(it);
    }
    return task_info;
  }

  /**
   * @brief Get task info from registry, conducting set, or results cache.
   *
   * @return Pair of task info and active flag (true if not finished).
   */
  std::pair<std::shared_ptr<TaskInfo>, bool> get_task(const TaskId &id) const {

    std::lock_guard<std::mutex> lock(registry_mtx_);
    auto it = task_registry_.find(id);
    if (it != task_registry_.end()) {
      return {it->second, true};
    }

    return {nullptr, false};
  }

  /**
   * @brief Pause a task by ID and wait for paused status.
   *
   * @param timeout_ms Max wait time in milliseconds; negative to wait forever.
   */
  ECM pause(const TaskId &id, int timeout_ms = 5000) {
    auto [task_info, active] = get_task(id);
    if (!task_info || !active) {
      return {EC::TaskNotFound, AMStr::amfmt("Task not found: {}", id)};
    }
    auto status_t = task_info->GetStatus();
    if (status_t == TaskStatus::Pending) {
      return {EC::OperationUnsupported,
              AMStr::amfmt("Task is still pending: {}", id)};
    } else if (status_t == TaskStatus::Finished) {
      return {EC::OperationUnsupported,
              AMStr::amfmt("Task is already finished: {}", id)};
    }
    if (status_t == TaskStatus::Paused ||
        (task_info->pd && task_info->pd->is_pause_only())) {
      return {EC::Success, AMStr::amfmt("Task already paused: {}", id)};
    }
    if (task_info->pd) {
      task_info->pd->set_pause();
    }
    const int64_t start = am_ms();
    while (timeout_ms < 0 || (am_ms() - start) < timeout_ms) {
      status_t = task_info->GetStatus();
      if (status_t == TaskStatus::Paused) {
        return {EC::Success, ""};
      }
      if (status_t == TaskStatus::Finished) {
        return {EC::OperationUnsupported,
                AMStr::amfmt("Task is already finished: {}", id)};
      }
      std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    return {EC::OperationTimeout, AMStr::amfmt("Task pause timeout: {}", id)};
  }

  /**
   * @brief Resume a task by ID and wait for in-flight pause to complete.
   *
   * @param timeout_ms Max wait time in milliseconds; negative to wait forever.
   */
  ECM resume(const TaskId &id, int timeout_ms = 5000) {
    auto [task_info, active] = get_task(id);
    if (!task_info || !active) {
      return {EC::TaskNotFound, AMStr::amfmt("Task not found: {}", id)};
    }
    auto status_t = task_info->GetStatus();
    if (status_t == TaskStatus::Pending) {
      return {EC::OperationUnsupported,
              AMStr::amfmt("Task is still pending: {}", id)};
    } else if (status_t == TaskStatus::Finished) {
      return {EC::OperationUnsupported,
              AMStr::amfmt("Task is already finished: {}", id)};
    }
    if (task_info->pd && task_info->pd->is_pause_only() &&
        status_t != TaskStatus::Paused) {
      const int64_t start = am_ms();
      while (timeout_ms < 0 || (am_ms() - start) < timeout_ms) {
        status_t = task_info->GetStatus();
        if (status_t == TaskStatus::Paused) {
          break;
        }
        if (status_t == TaskStatus::Finished) {
          return {EC::OperationUnsupported,
                  AMStr::amfmt("Task is already finished: {}", id)};
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
      }
      if (status_t != TaskStatus::Paused) {
        return {EC::OperationTimeout,
                AMStr::amfmt("Task pause timeout: {}", id)};
      }
    }
    status_t = task_info->GetStatus();
    if (status_t == TaskStatus::Paused ||
        (task_info->pd && task_info->pd->is_pause_only())) {
      if (task_info->pd) {
        task_info->pd->set_running();
      }
      const int on_thread =
          task_info->OnWhichThread.load(std::memory_order_relaxed);
      if (on_thread >= 0) {
        task_info->SetStatus(TaskStatus::Conducting);
        return {EC::Success, ""};
      }
      task_info->SetStatus(TaskStatus::Pending);
      task_info->OnWhichThread.store(-1, std::memory_order_relaxed);
      const int affinity_thread =
          task_info->affinity_thread.load(std::memory_order_relaxed);
      TaskAssignType assign_type =
          task_info->assign_type.load(std::memory_order_relaxed);
      if (assign_type == TaskAssignType::Affinity &&
          !IsValidThreadId(affinity_thread)) {
        assign_type = TaskAssignType::Public;
      }
      RegisterTask(task_info, assign_type,
                   assign_type == TaskAssignType::Affinity ? affinity_thread
                                                           : -1);
      queue_cv_.notify_all();
      return {EC::Success, ""};
    }
    return {EC::Success, AMStr::amfmt("Task is conducting: {}", id)};
  }

  /**
   * @brief Terminate a task by ID and optionally wait for completion.
   *
   * @return Pair of task info and termination result.
   */
  std::pair<std::shared_ptr<TaskInfo>, ECM> terminate(const TaskId &id,
                                                      int timeout_ms = 5000) {
    auto [existing, active] = get_task(id);
    if (!existing) {
      return {nullptr,
              {EC::TaskNotFound, AMStr::amfmt("Task not found: {}", id)}};
    }
    if (existing->GetStatus() == TaskStatus::Finished) {
      return {existing,
              {EC::OperationUnsupported,
               AMStr::amfmt("Task already finished: {}", id)}};
    }

    if (existing->GetStatus() == TaskStatus::Paused) {
      std::scoped_lock<std::mutex, std::mutex> lock(registry_mtx_, queue_mtx_);
      auto it = task_registry_.find(id);
      if (it != task_registry_.end() && it->second) {
        const auto &task_info = it->second;
        if (task_info->pd) {
          task_info->pd->set_terminate();
        }
        task_info->SetResult({EC::Terminate, "Task terminated while paused"});
        task_info->SetStatus(TaskStatus::Finished);
        task_info->finished_time.store(timenow(), std::memory_order_relaxed);
        task_info->OnWhichThread.store(-1, std::memory_order_relaxed);
        HandleCompletedTask(task_info);
        task_registry_.erase(it);
        queue_cv_.notify_all();
        return {task_info, {EC::Success, ""}};
      }
    }

    if (existing->GetStatus() == TaskStatus::Pending) {
      std::scoped_lock<std::mutex, std::mutex> lock(registry_mtx_, queue_mtx_);
      auto it = task_registry_.find(id);
      if (it != task_registry_.end() && it->second) {
        const auto &task_info = it->second;
        const int affinity_thread =
            task_info->affinity_thread.load(std::memory_order_relaxed);
        const TaskAssignType assign_type =
            task_info->assign_type.load(std::memory_order_relaxed);
        if (assign_type == TaskAssignType::Affinity && affinity_thread >= 0 &&
            static_cast<size_t>(affinity_thread) < affinity_queues_.size()) {
          affinity_queues_[static_cast<size_t>(affinity_thread)].remove(id);
        } else {
          public_queue_.remove(id);
        }
        task_registry_.erase(it);
        if (task_info->pd) {
          task_info->pd->set_terminate();
        }
        task_info->SetResult({EC::Terminate, "Task terminated before start"});
        task_info->SetStatus(TaskStatus::Finished);
        task_info->finished_time.store(timenow(), std::memory_order_relaxed);
        task_info->OnWhichThread.store(-1, std::memory_order_relaxed);
        queue_cv_.notify_all();
        HandleCompletedTask(task_info);
        return {task_info, {EC::Success, ""}};
      }
    }

    if (existing->pd) {
      existing->pd->set_terminate();
    }

    const int64_t start = am_ms();
    while (timeout_ms < 0 || (am_ms() - start) < timeout_ms) {
      if (existing->GetStatus() == TaskStatus::Finished) {
        if (existing->hostm) {
          HandleCompletedTask(existing);
        }
        return {existing, {EC::Success, ""}};
      }
      std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    return {
        existing,
        {EC::OperationTimeout, AMStr::amfmt("Task terminate timeout: {}", id)}};
  }

  /**
   * @brief Get the total number of pending tasks across all queues.
   */
  size_t pending_count() {
    std::lock_guard<std::mutex> lock(queue_mtx_);
    size_t count = public_queue_.size();
    for (const auto &queue : affinity_queues_) {
      count += queue.size();
    }
    return count;
  }

  /**
   * @brief Check whether any task is currently conducting.
   */
  bool is_conducting() {
    std::lock_guard<std::mutex> lock(conducting_mtx_);
    return !conducting_tasks_.empty();
  }

  /**
   * @brief Get a copy of currently conducting task IDs.
   */
  std::unordered_set<TaskId> get_conducting_ids() {
    std::lock_guard<std::mutex> lock(conducting_mtx_);
    return conducting_tasks_;
  }

  /**
   * @brief Clear all finished results from the cache.
   */
  void clear_results() {
    std::lock_guard<std::mutex> lock(result_mtx_);
    results_.clear();
  }

  /**
   * @brief Remove a specific result from the cache.
   */
  bool remove_result(const TaskId &id) {
    std::lock_guard<std::mutex> lock(result_mtx_);
    return results_.erase(id) > 0;
  }

  /**
   * @brief Get all result IDs currently cached.
   */
  std::vector<std::string> get_result_ids() const {
    std::lock_guard<std::mutex> lock(result_mtx_);
    std::vector<std::string> ids;
    ids.reserve(results_.size());
    for (const auto &[id, _] : results_) {
      ids.push_back(id);
    }
    return ids;
  }

  /**
   * @brief Snapshot the task registry map (task id -> task info).
   */
  std::unordered_map<std::string, std::shared_ptr<TaskInfo>>
  get_registry_copy() const {
    std::lock_guard<std::mutex> lock(registry_mtx_);
    return task_registry_;
  }

  /**
   * @brief Snapshot all pending tasks that have not started yet.
   */
  std::vector<std::shared_ptr<TaskInfo>> get_pending_tasks() const {
    std::vector<std::shared_ptr<TaskInfo>> tasks;
    std::lock_guard<std::mutex> lock(registry_mtx_);
    tasks.reserve(task_registry_.size());
    for (const auto &pair : task_registry_) {
      if (pair.second) {
        tasks.push_back(pair.second);
      }
    }
    return tasks;
  }

  /**
   * @brief Snapshot all currently conducting tasks.
   */
  std::vector<std::shared_ptr<TaskInfo>> get_conducting_tasks() const {
    std::vector<std::shared_ptr<TaskInfo>> tasks;
    std::lock_guard<std::mutex> lock(conducting_mtx_);
    tasks.reserve(conducting_infos_.size());
    for (const auto &info : conducting_infos_) {
      if (info) {
        tasks.push_back(info);
      }
    }
    return tasks;
  }

  static std::pair<ECM, TASKS>
  load_tasks(const std::string &src, const std::string &dst,
             const std::shared_ptr<ClientMaintainer> &hostm,
             const std::string &src_host = "", const std::string &dst_host = "",
             bool clone = false, bool overwrite = false, bool mkdir = true,
             bool ignore_sepcial_file = true, bool resume = false,
             amf interrupt_flag = nullptr, int timeout_ms = -1,
             int64_t start_time = -1) {
    start_time = start_time == -1 ? am_ms() : start_time;
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

    if (resume && src_stat.type == PathType::DIR) {
      return {ECM{EC::NotAFile,
                  AMStr::amfmt("Resume requires src to be a file: {}", src)},
              tasks};
    }

    // 检查是否为 src_file -> dst_file 的传输
    auto dstf = dst;
    auto srcf = src;
    bool is_dst_file = false;
    if (resume) {
      is_dst_file = true;
    }
    if (clone) {
      is_dst_file = true;
    } else if (src_stat.type == PathType::FILE) {
      // 检查dst的扩展名和src扩展名是否相同

      std::string dst_ext = AMPathStr::extname(dstf);
      if (AMPathStr::extname(srcf) == dst_ext && !dst_ext.empty()) {
        is_dst_file = true;
      }
    }

    if (src_stat.type != PathType::DIR) {

      if (ignore_sepcial_file && src_stat.type != PathType::FILE) {
        return {
            ECM{EC::NotAFile, AMStr::amfmt("Src is not a common file and "
                                           "ignore_sepcial_file is true: {}",
                                           srcf)},
            {}};
      }

      if (resume) {
        if (src_stat.type != PathType::FILE) {
          return {
              ECM{EC::NotAFile,
                  AMStr::amfmt("Resume requires src to be a file: {}", srcf)},
              tasks};
        }
        auto [dst_stat_rcm, dst_info] = dst_client->stat(
            dstf, false, interrupt_flag, timeout_ms, start_time);
        if (dst_stat_rcm.first != EC::Success) {
          return {ECM{EC::PathNotExist,
                      AMStr::amfmt("Resume requires dst to exist: {}", dstf)},
                  tasks};
        }
        if (dst_info.type != PathType::FILE) {
          return {
              ECM{EC::NotAFile,
                  AMStr::amfmt("Resume requires dst to be a file: {}", dstf)},
              tasks};
        }
        if (dst_info.size > src_stat.size) {
          return {ECM{EC::InvalidArg,
                      AMStr::amfmt("Resume requires dst size <= src size: "
                                   "{} > {}",
                                   dst_info.size, src_stat.size)},
                  tasks};
        }
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
                    AMStr::amfmt("Dst parent path not exists: {}",
                                 AMPathStr::dirname(dstf))},
                tasks};
      } else if (rcm4.first == EC::Success &&
                 dst_parent_info.type != PathType::DIR) {
        return {ECM(EC::NotADirectory,
                    AMStr::amfmt("Dst parent path is not a directory: {}",
                                 dst_parent_info.path)),
                tasks};
      }

      if (rcm4.first == EC::Success) {
        auto [rcm5, dst_info] = dst_client->stat(dstf, false, interrupt_flag,
                                                 timeout_ms, start_time);
        // 检验目标路径是否存在
        if (rcm5.first == EC::Success) {
          if (dst_info.type == PathType::DIR) {
            return {ECM(EC::NotAFile,
                        AMStr::amfmt(
                            "Dst already exists and is a directory: {}", dstf)),
                    tasks};
          } else if (!overwrite && !resume) {
            return {ECM{EC::PathAlreadyExists,
                        AMStr::amfmt("Dst already exists: {}", dstf)},
                    tasks};
          }
        }
      }

      tasks.emplace_back(srcf, dstf, src_host, dst_host, src_stat.size,
                         src_stat.type);
      if (resume) {
        auto [dst_stat_rcm, dst_info] = dst_client->stat(
            dstf, false, interrupt_flag, timeout_ms, start_time);
        if (dst_stat_rcm.first != EC::Success ||
            dst_info.type != PathType::FILE) {
          return {
              ECM{EC::InvalidArg,
                  AMStr::amfmt("Resume requires dst to be a file: {}", dstf)},
              tasks};
        }
        tasks.back().transferred = dst_info.size;
      }
      return {ECM(EC::Success, ""), tasks};
    }

    auto [rcm6, dst_info] =
        dst_client->stat(dstf, false, interrupt_flag, timeout_ms, start_time);

    if (rcm6.first != EC::Success && !mkdir) {
      return {ECM{EC::ParentDirectoryNotExist,
                  AMStr::amfmt("Dst parent path not exists: {}", dstf)},
              tasks};
    } else if (rcm6.first == EC::Success && dst_info.type != PathType::DIR) {
      return {ECM(EC::NotADirectory,
                  AMStr::amfmt("Dst already exists and is not a directory: {}",
                               dstf)),
              tasks};
    }

    auto [rcm7, src_pack] = src_client->iwalk(
        srcf, true, false, nullptr, interrupt_flag, timeout_ms, start_time);
    if (rcm7.first != EC::Success) {
      return {rcm7, tasks};
    }
    const auto &src_paths = src_pack.first;
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
      const std::string base_path = clone ? srcf : AMPathStr::dirname(srcf);
      dst_n = AMPathStr::join(dstf, fs::relative(item.path, base_path));
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
