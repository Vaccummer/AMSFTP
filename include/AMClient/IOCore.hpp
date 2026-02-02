#pragma once
// 标准库
#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <ctime>
#include <fcntl.h>
#include <functional>
#include <list>
#include <mutex>
#include <numeric>
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
        return {rc,
                AMStr::amfmt("Open sftp file \"{}\" failed: {}", path, msg)};
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
                AMStr::amfmt("Failed to open local file \"{}\": error code {}",
                             path, GetLastError())};
      }
#else
      int flags = is_write ? (O_RDWR | O_CREAT | O_TRUNC) : O_RDONLY;
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
          return {bytes_read,
                  {rc, AMStr::amfmt("Read sftp file \"{}\" failed: {}", path,
                                    msg)}};
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
                   AMStr::amfmt("Read local file \"{}\" failed: {}", path,
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
                   AMStr::amfmt("Write local file \"{}\" failed: {}", path,
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
  std::unordered_map<std::string, std::shared_ptr<BaseClient>> hosts;
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
        if (!is_heartbeat.load()) {
          return;
        }
      }
      millsecond = 0;
    }
  }

public:
  using DisconnectCallback =
      std::function<void(const std::shared_ptr<BaseClient> &, const ECM &)>;
  DisconnectCallback disconnect_cb;
  bool is_disconnect_cb = false;
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
      this->is_heartbeat.store(false);
      return;
    }

    this->is_heartbeat.store(true);
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
    const size_t active_count = desired_thread_count_.load();
    return thread_id >= 0 && static_cast<size_t>(thread_id) < active_count &&
           static_cast<size_t>(thread_id) < affinity_queues_.size();
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

    task_info->assign_type.store(assign_type);
    task_info->affinity_thread.store(affinity_thread);
    task_info->OnWhichThread.store(-1);
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
          return !running_.load() || HasPendingTasksLocked() ||
                 thread_index >= desired_thread_count_.load();
        });

        if (!running_.load() && !HasPendingTasksLocked()) {
          return std::nullopt;
        }

        if (thread_index >= desired_thread_count_.load()) {
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
        task_registry_.erase(it);
        return std::make_optional(std::make_pair(task_id, task_info));
      }
    }
  }

  /**
   * @brief Store a completed task or invoke its result callback.
   */
  void HandleCompletedTask(const std::shared_ptr<TaskInfo> &task_info) {
    AMPromptManager::Instance().PrintTaskResult(task_info);
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
        ProgressCBInfo(cur_task->src, cur_task->dst, cur_task->src_host,
                       cur_task->dst_host, cur_task->transferred,
                       cur_task->size, task_info->total_transferred_size.load(),
                       task_info->total_size.load()),
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
    if (task_info->pd && task_info->pd->is_terminate()) {
      task_info->SetResult({EC::Terminate, "Task terminated before start"});
      task_info->SetStatus(TaskStatus::Finished);
      task_info->finished_time.store(timenow());
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
      return {rc, AMStr::amfmt("Failed to open src file \"{}\": {}", task->src,
                               msg)};
    }

    LIBSSH2_SFTP_HANDLE *dstFile = libssh2_sftp_open(
        client->sftp, task->dst.c_str(),
        LIBSSH2_FXF_WRITE | LIBSSH2_FXF_CREAT | LIBSSH2_FXF_TRUNC, 0744);
    if (!dstFile) {
      libssh2_sftp_close_handle(srcFile);
      EC rc = client->GetLastEC();
      std::string msg = client->GetLastErrorMsg();
      return {rc, AMStr::amfmt("Failed to open dst file \"{}\": {}", task->dst,
                               msg)};
    }

    libssh2_session_set_blocking(client->session, 1);
    std::vector<char> buffer(chunk_size_);
    size_t total_written = 0;
    ssize_t bytes_read, bytes_written;

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
              static_cast<size_t>(bytes_written));
          task_info->this_task_transferred_size.store(total_written);
          task->transferred = task_info->this_task_transferred_size.load();
          InnerCallback(task_info, pd, false);
        } else if (bytes_written == 0) {
          break;
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
        if (bytes_write > 0) {
          task_info->total_transferred_size.fetch_add(
              static_cast<size_t>(bytes_write));
          task_info->this_task_transferred_size.store(
              static_cast<size_t>(file_handle.offset));
        }
        task->transferred = task_info->this_task_transferred_size.load();
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
        if (bytes_write > 0) {
          task_info->total_transferred_size.fetch_add(
              static_cast<size_t>(bytes_write));
          task_info->this_task_transferred_size.store(
              static_cast<size_t>(file_handle.offset));
        }
        task->transferred = task_info->this_task_transferred_size.load();
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
            const size_t total =
                ti->this_task_transferred_size.fetch_add(delta) + delta;
            cur_task->transferred = total;
            ti->total_transferred_size.fetch_add(static_cast<size_t>(to_read));
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
    curl_easy_setopt(curl, CURLOPT_INFILESIZE_LARGE,
                     static_cast<curl_off_t>(cur_task->size));
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
    ECM ecm = client->SetupPath(src, false);
    if (ecm.first != EC::Success) {
      cur_task->rcm = ecm;
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

    if (reading_thread.joinable()) {
      reading_thread.join();
    }

    task->transferred = task_info->this_task_transferred_size.load();
    if (task->rcm.first != EC::Success) {
      return task->rcm;
    }
    if (task->transferred >= task->size) {
      return task->rcm;
    } else if (pd.is_terminate()) {
      return {EC::Terminate, "Task terminated by user"};
    }
    return {EC::UnknownError, "Task not finished but exited unexpectedly"};
  }

  /**
   * @brief Worker thread function with affinity-aware scheduling.
   */
  void WorkerLoop(size_t thread_index) {
    while (running_.load()) {
      if (thread_index >= desired_thread_count_.load()) {
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
      task_info->OnWhichThread.store(static_cast<int>(thread_index));

      EnsureProgressData(task_info);

      if (ShouldSkipTask(task_info)) {
        task_info->pd.reset();
        task_info->OnWhichThread.store(-1);
        HandleCompletedTask(task_info);
        ClearConducting(thread_index);
        continue;
      }

      ExecuteTask(task_info);
      task_info->pd.reset();
      task_info->OnWhichThread.store(-1);

      HandleCompletedTask(task_info);
      ClearConducting(thread_index);
    }

    // Ensure this worker is not reported as executing any task.
    // The task clears OnWhichThread on exit paths above.
    ClearConducting(thread_index);
  }

  // Execute a single TaskInfo
  void ExecuteTask(std::shared_ptr<TaskInfo> task_info) {
    EnsureProgressData(task_info);
    task_info->SetStatus(TaskStatus::Conducting);
    task_info->start_time.store(timenow());

    if (task_info->callback.need_total_size_cb) {
      task_info->callback.CallTotalSize(task_info->total_size.load());
    }

    auto &pd = *(task_info->pd);
    pd.task_info = task_info;

    if (!task_info->tasks) {
      task_info->SetStatus(TaskStatus::Finished);
      task_info->finished_time.store(timenow());
      return;
    }

    for (auto &task : *(task_info->tasks)) {
      // Check terminate before each file
      if (pd.is_terminate()) {
        task.rcm = {EC::Terminate, "Task terminated by user"};
        task.IsFinished = true;
        continue;
      }

      if (task.IsFinished) {
        continue;
      }

      auto hostm_locked = task_info->hostm.lock();
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
      task.transferred = 0;
      task_info->this_task_transferred_size.store(0);
      task.rcm = ECM(EC::Success, "");
      if (src_client->GetUID() == dst_client->GetUID() &&
          src_client->GetProtocol() == ClientProtocol::SFTP) {
        pd.ring_buffer = nullptr;
      }
      pd.ring_buffer = std::make_shared<StreamRingBuffer>(CalculateBufferSize(
          src_client, dst_client, task_info->buffer_size.load()));

      task.rcm = TransferSingleFile(src_client, dst_client, task_info);
      task.IsFinished = true;

      if (task.rcm.first != EC::Success && task_info->callback.need_error_cb &&
          task.rcm.first != EC::Terminate) {

        task_info->callback.CallError(ErrorCBInfo(
            task.rcm, task.src, task.dst, task.src_host, task.dst_host));
      }

      InnerCallback(task_info, pd, true);
    }

    // bool any_error = false;
    // for (auto &task : tasks) {
    //   if (task.rcm.first != EC::Success) {
    //     any_error = true;
    //     task_info->rcm = task.rcm; // Last error
    //   }
    // }
    // if (!any_error) {
    //   task_info->rcm = {EC::Success, ""};
    // }

    task_info->SetStatus(TaskStatus::Finished);
    task_info->finished_time.store(timenow());
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
  ~AMWorkManager() {
    running_.store(false);
    queue_cv_.notify_all();
    for (auto &thread : worker_threads_) {
      if (thread.joinable()) {
        thread.join();
      }
    }
  }

  /**
   * @brief Set or get the chunk size used by transit transfers.
   */
  size_t ChunkSize(int64_t size = -1) {
    if (size < 32 * AMKB) {
      return chunk_size_;
    }
    chunk_size_ = std::min<size_t>(static_cast<size_t>(size), AMMaxBufferSize);
    return chunk_size_;
  }

  /**
   * @brief Adjust or query the worker thread count.
   */
  size_t ThreadCount(size_t new_count = 0) {
    if (new_count == 0) {
      return desired_thread_count_.load();
    }

    new_count = ClampThreadCount(new_count);
    const size_t current = desired_thread_count_.load();
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

      desired_thread_count_.store(new_count);
      const size_t existing_threads = worker_threads_.size();
      for (size_t idx = existing_threads; idx < new_count; ++idx) {
        worker_threads_.emplace_back([this, idx]() { WorkerLoop(idx); });
      }
      queue_cv_.notify_all();
      return new_count;
    }

    desired_thread_count_.store(new_count);
    queue_cv_.notify_all();
    return new_count;
  }

  // former is occupied, latter is idle
  std::pair<std::vector<size_t>, std::vector<size_t>> get_thread_ids() {
    std::vector<size_t> occupied;
    std::vector<size_t> idle;
    const size_t count = desired_thread_count_.load();
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

    if (task_info->id.empty()) {
      task_info->id = GenerateUID();
    }
    task_info->submit_time.store(timenow());
    task_info->SetStatus(TaskStatus::Pending);

    if (task_info->total_size.load() == 0) {
      task_info->total_size.store(
          std::accumulate(task_info->tasks->begin(), task_info->tasks->end(), 0,
                          [](size_t sum, const TransferTask &task) {
                            return sum + task.size;
                          }));
    }
    task_info->total_transferred_size.store(0);
    task_info->OnWhichThread.store(-1);

    const int requested_thread_id = task_info->affinity_thread.load();
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
    task_info->id = GenerateUID();
    task_info->tasks = tasks;
    task_info->total_size.store(std::accumulate(
        tasks->begin(), tasks->end(), 0,
        [](size_t sum, const TransferTask &task) { return sum + task.size; }));
    task_info->hostm = hostm;
    task_info->callback = callback;
    task_info->buffer_size.store(buffer_size);
    task_info->affinity_thread.store(thread_id);
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
    {
      std::lock_guard<std::mutex> lock(registry_mtx_);
      auto it = task_registry_.find(id);
      if (it != task_registry_.end()) {
        return {it->second, true};
      }
    }
    {
      std::lock_guard<std::mutex> lock(conducting_mtx_);
      for (size_t idx = 0; idx < conducting_by_thread_.size(); ++idx) {
        if (conducting_by_thread_[idx] == id) {
          return {conducting_infos_[idx], true};
        }
      }
    }
    {
      std::lock_guard<std::mutex> lock(result_mtx_);
      auto it = results_.find(id);
      if (it != results_.end()) {
        return {it->second, false};
      }
    }
    return {nullptr, false};
  }

  /**
   * @brief Pause a task by ID.
   */
  bool pause(const TaskId &id) {
    auto [task_info, active] = get_task(id);
    if (!task_info || !active || !task_info->pd) {
      return false;
    }
    task_info->pd->set_pause();
    return true;
  }

  /**
   * @brief Resume a task by ID.
   */
  bool resume(const TaskId &id) {
    auto [task_info, active] = get_task(id);
    if (!task_info || !active || !task_info->pd) {
      return false;
    }
    task_info->pd->set_running();
    return true;
  }

  /**
   * @brief Terminate a task by ID and optionally wait for completion.
   *
   * @return Pair of task info and termination success flag.
   */
  std::pair<std::shared_ptr<TaskInfo>, bool> terminate(const TaskId &id,
                                                       int timeout_ms = 5000) {
    auto [existing, active] = get_task(id);
    if (!existing) {
      return {nullptr, false};
    }
    if (!active) {
      return {existing, false};
    }

    std::shared_ptr<TaskInfo> pending_task = nullptr;
    bool terminated = false;
    {
      std::scoped_lock<std::mutex, std::mutex> lock(registry_mtx_, queue_mtx_);
      auto it = task_registry_.find(id);
      if (it != task_registry_.end() && it->second) {
        bool in_queue = false;
        const auto &task_info = it->second;
        if (task_info->GetStatus() == TaskStatus::Finished) {
          pending_task = task_info;
          terminated = false;
        }
        const int affinity_thread = task_info->affinity_thread.load();
        const TaskAssignType assign_type = task_info->assign_type.load();
        if (assign_type == TaskAssignType::Affinity && affinity_thread >= 0 &&
            static_cast<size_t>(affinity_thread) < affinity_queues_.size()) {
          const auto &queue =
              affinity_queues_[static_cast<size_t>(affinity_thread)];
          in_queue = std::find(queue.begin(), queue.end(), id) != queue.end();
        } else {
          in_queue = std::find(public_queue_.begin(), public_queue_.end(),
                               id) != public_queue_.end();
        }
        if (in_queue) {
          if (task_info->pd) {
            task_info->pd->set_terminate();
          }
          task_info->SetResult({EC::Terminate, "Task terminated before start"});
          task_info->SetStatus(TaskStatus::Finished);
          task_info->finished_time.store(timenow());
          task_info->OnWhichThread.store(-1);

          if (assign_type == TaskAssignType::Affinity && affinity_thread >= 0 &&
              static_cast<size_t>(affinity_thread) < affinity_queues_.size()) {
            affinity_queues_[static_cast<size_t>(affinity_thread)].remove(id);
          } else {
            public_queue_.remove(id);
          }
          task_registry_.erase(it);
          queue_cv_.notify_all();
          pending_task = task_info;
          terminated = true;
        }
      }
    }

    if (pending_task) {
      HandleCompletedTask(pending_task);
      return {pending_task, terminated};
    }

    std::shared_ptr<TaskInfo> conducting_task = nullptr;
    {
      std::lock_guard<std::mutex> lock(conducting_mtx_);
      for (size_t idx = 0; idx < conducting_by_thread_.size(); ++idx) {
        if (conducting_by_thread_[idx] == id) {
          conducting_task = conducting_infos_[idx];
          break;
        }
      }
    }

    if (!conducting_task) {
      auto result = get_result(id, false);
      if (result) {
        return {result, false};
      }
      return {nullptr, false};
    }

    if (conducting_task->GetStatus() == TaskStatus::Finished) {
      return {conducting_task, false};
    }

    if (conducting_task->pd) {
      conducting_task->pd->set_terminate();
    }
    terminated = true;

    const int64_t start = am_ms();
    while (timeout_ms < 0 || (am_ms() - start) < timeout_ms) {
      auto result = get_result(id, true);
      if (result) {
        return {result, terminated};
      }
      if (conducting_task->GetStatus() == TaskStatus::Finished &&
          conducting_task->result_callback) {
        return {conducting_task, terminated};
      }
      std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    return {conducting_task, terminated};
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
  std::vector<std::string> get_result_ids() {
    std::lock_guard<std::mutex> lock(result_mtx_);
    std::vector<std::string> ids;
    ids.reserve(results_.size());
    for (const auto &[id, _] : results_) {
      ids.push_back(id);
    }
    return ids;
  }

  /**
   * @brief Snapshot all pending tasks that have not started yet.
   */
  std::vector<std::shared_ptr<TaskInfo>> get_pending_tasks() {
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
  std::vector<std::shared_ptr<TaskInfo>> get_conducting_tasks() {
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
             bool ignore_sepcial_file = true, amf interrupt_flag = nullptr,
             int timeout_ms = -1, int64_t start_time = -1) {
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

    // 检查是否为 src_file -> dst_file 的传输
    auto dstf = dst;
    auto srcf = src;
    bool is_dst_file = false;
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
          } else if (!overwrite) {
            return {ECM{EC::PathAlreadyExists,
                        AMStr::amfmt("Dst already exists: {}", dstf)},
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
                  AMStr::amfmt("Dst parent path not exists: {}", dstf)},
              tasks};
    } else if (rcm6.first == EC::Success && dst_info.type != PathType::DIR) {
      return {ECM(EC::NotADirectory,
                  AMStr::amfmt("Dst already exists and is not a directory: {}",
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
