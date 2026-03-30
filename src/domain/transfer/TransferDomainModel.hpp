#pragma once
#include "domain/client/ClientPort.hpp"
#include "domain/filesystem/FileSystemModel.hpp"
#include "foundation/core/DataClass.hpp"
#include <atomic>
#include <cstddef>
#include <unordered_map>
#include <utility>
#include <vector>

namespace AMDomain::transfer {
class UserTransferSet;
class TaskInfo;
class TransferTask;
using Cache = std::vector<std::optional<UserTransferSet>>;
using TASKS = std::vector<TransferTask>;
using Client = AMDomain::client::IClientPort;
using TransferClientContainer = std::unordered_map<
    std::string,
    std::variant<std::shared_ptr<Client>,
                 std::pair<std::shared_ptr<Client>, std::shared_ptr<Client>>>>;
using ResultCallback = std::function<void(std::shared_ptr<TaskInfo>)>;
using ClientHandle = std::shared_ptr<AMDomain::client::IClientPort>;
using ClientPath = AMDomain::filesystem::ClientPath;
enum class TaskStatus { Pending, Conducting, Paused, Finished };
enum class ControlIntent { Running, Pause, Terminate };

struct ProgressCBInfo {
  std::string src;
  std::string dst;
  std::string src_host;
  std::string dst_host;
  size_t this_size;
  size_t file_size;
  size_t accumulated_size;
  size_t total_size;
  ProgressCBInfo(std::string src, std::string dst, std::string src_host,
                 std::string dst_host, size_t this_size, size_t file_size,
                 size_t accumulated_size, size_t total_size)
      : src(std::move(src)), dst(std::move(dst)), src_host(std::move(src_host)),
        dst_host(std::move(dst_host)), this_size(std::move(this_size)),
        file_size(std::move(file_size)),
        accumulated_size(std::move(accumulated_size)),
        total_size(std::move(total_size)) {}
};

struct ErrorCBInfo {
  ECM ecm;
  std::string src;
  std::string dst;
  std::string src_host;
  std::string dst_host;
  ErrorCBInfo(ECM ecm, std::string src, std::string dst,
              std::string src_host, std::string dst_host)
      : ecm(std::move(ecm)), src(std::move(src)), dst(std::move(dst)),
        src_host(std::move(src_host)), dst_host(std::move(dst_host)) {}
};

struct TransferCallback {
  using ErrorCallback = std::function<void(const ErrorCBInfo &)>;
  using ProgressCallback =
      std::function<std::optional<TransferControl>(const ProgressCBInfo &)>;
  using TotalSizeCallback = std::function<void(size_t)>;

  bool need_error_cb = false;
  bool need_progress_cb = false;
  bool need_total_size_cb = false;
  ErrorCallback error_cb = {}; // void(ErrorCBInfo)
  ProgressCallback progress_cb =
      {}; // optional<TransferControl>(ProgressCBInfo)
  TotalSizeCallback total_size_cb = {}; // void(size_t)
  float cb_interval_s = 0.1f;           // Callback interval in seconds

  TransferCallback(TotalSizeCallback total_size = {}, ErrorCallback error = {},
                   ProgressCallback progress = {}, float cb_interval_s = 0.1f)
      : error_cb(std::move(error)), progress_cb(std::move(progress)),
        total_size_cb(std::move(total_size)), cb_interval_s(cb_interval_s) {
    need_total_size_cb = static_cast<bool>(total_size_cb);
    need_error_cb = static_cast<bool>(error_cb);
    need_progress_cb = static_cast<bool>(progress_cb);
  }

  void SetErrorCB(ErrorCallback cb = {}) {
    error_cb = std::move(cb);
    need_error_cb = static_cast<bool>(error_cb);
  }

  void SetProgressCB(ProgressCallback cb = {}) {
    progress_cb = std::move(cb);
    need_progress_cb = static_cast<bool>(progress_cb);
  };

  void SetTotalSizeCB(TotalSizeCallback cb = {}) {
    total_size_cb = std::move(cb);
    need_total_size_cb = static_cast<bool>(total_size_cb);
  }

  ECM CallError(const ErrorCBInfo &info) const {
    return CallCallbackSafe(error_cb, info);
  }

  ECM CallTotalSize(size_t total_size) const {
    return CallCallbackSafe(total_size_cb, total_size);
  }

  std::optional<TransferControl> CallProgress(const ProgressCBInfo &info,
                                              ECM *cb_error = nullptr) const {
    if (cb_error) {
      *cb_error = {EC::Success, ""};
    }
    if (!progress_cb) {
      return std::nullopt;
    }
    try {
      return progress_cb(info);
    } catch (const std::exception &e) {
      if (cb_error) {
        *cb_error = {EC::PyCBError, e.what()};
      }
      return TransferControl::Terminate;
    } catch (...) {
      if (cb_error) {
        *cb_error = {EC::PyCBError, "Unknown progress callback error"};
      }
      return TransferControl::Terminate;
    }
  }
};

struct TransferTask {
  std::string src;
  std::string src_host;
  std::string dst;
  std::string dst_host;
  size_t size;
  PathType path_type = PathType::FILE;
  bool overwrite = false;
  bool IsFinished = false;
  ECM rcm = ECM(EC::Success, "");
  size_t transferred = 0; // Current file transferred size
  TransferTask() : src(""), src_host(""), dst(""), dst_host(""), size(0) {}
  TransferTask(std::string src, std::string dst, std::string src_host,
               std::string dst_host, size_t size,
               PathType path_type = PathType::FILE)
      : src(std::move(src)), src_host(std::move(src_host)), dst(std::move(dst)),
        dst_host(std::move(dst_host)), size(size), path_type(path_type) {}
};

namespace TaskStruct {
struct TaskTime {
  std::atomic<double> submit{0};
  std::atomic<double> start{0};
  std::atomic<double> finish{0};
};

struct TaskState {
  AMAtomic<ECM> rcm = AMAtomic<ECM>(ECM{EC::Success, ""});
  std::atomic<TaskStatus> status{TaskStatus::Pending};
  std::atomic<ControlIntent> intent{ControlIntent::Running};
};

struct TaskSize {
  std::atomic<size_t> total{0};
  std::atomic<size_t> transferred{0};
  std::atomic<size_t> cur_task{0};
  std::atomic<size_t> cur_task_transferred{0};
  std::atomic<size_t> filenum{0};
  std::atomic<size_t> success_filenum{0};
  std::atomic<size_t> buffer{0};
};

struct TaskCoreData {
  AMAtomic<TASKS> tasks = AMAtomic<TASKS>(TASKS());
  AMDomain::client::ClientControlComponent control = {};
  std::atomic<TransferTask *> cur_task{nullptr};
  TransferClientContainer clients;
  std::vector<std::string> nicknames;
};

struct TaskSet {
  std::shared_ptr<std::vector<UserTransferSet>> transfer_sets = nullptr;
  bool quiet = false;
  TransferCallback callback;
  std::atomic<bool> keep_start_time{false};
  std::atomic<bool> completion_dispatched{false};
  std::atomic<int> OnWhichThread{-1};
  std::atomic<int> affinity_thread{-1};
  std::atomic<TaskAssignType> assign_type{TaskAssignType::Public};
};

struct TaskCallback {
  TransferCallback runtime = {};
  ResultCallback result = {};
};

} // namespace TaskStruct

struct TaskInfo {
  /**
   * @brief Callback invoked when the task completes.
   */

  using ID = std::string;

  /**
   * @brief Unique task identifier.
   */
  ID id = "";
  TaskStruct::TaskTime Time;
  TaskStruct::TaskState State;
  TaskStruct::TaskSize Size;
  TaskStruct::TaskCoreData Core;
  TaskStruct::TaskSet Set;
  TaskStruct::TaskCallback Callback;

  /**
   * @brief Construct a task info with optional quiet flag.
   */
  explicit TaskInfo() = default;

  /**
   * @brief Calculate and update total size from tasks when needed.
   *
   * @param force Recalculate even if total_size is already Set.
   * @return Updated total Size.
   */
  size_t CalTotalSize(bool force = false) {
    size_t current = Size.total.load(std::memory_order_relaxed);
    if (!force && current != 0) {
      return current;
    }
    current = 0;
    auto taks_l = Core.tasks.lock();

    for (const auto &task : *taks_l) {
      current += task.size;
    }
    Size.total.store(current, std::memory_order_relaxed);
    return current;
  }

  /**
   * @brief Calculate and update file count from tasks when needed.
   *
   * @param force Recalculate even if filenum is already Set.
   * @return Updated file count.
   */
  size_t CalFileNum(bool force = false) {
    size_t current = Size.filenum.load(std::memory_order_relaxed);
    if (!force && current != 0) {
      return current;
    }
    current = 0;
    auto local_tasks = Core.tasks.lock();
    for (const auto &task : *local_tasks) {
      if (task.path_type == PathType::FILE) {
        current += 1;
      }
    }
    Size.filenum.store(current, std::memory_order_relaxed);
    return current;
  }

  void DeleteProgressData() {}

  bool TryMarkCompletionDispatched() {
    bool expected = false;
    return Set.completion_dispatched.compare_exchange_strong(
        expected, true, std::memory_order_acq_rel);
  }

  void ResetCompletionDispatch() {
    Set.completion_dispatched.store(false, std::memory_order_release);
  }

  TaskStatus GetStatus() const {
    return State.status.load(std::memory_order_relaxed);
  }

  ControlIntent GetIntent() const {
    return State.intent.load(std::memory_order_relaxed);
  }

  bool IsPauseRequested() const { return GetIntent() == ControlIntent::Pause; }

  bool IsTerminateRequested() const {
    return GetIntent() == ControlIntent::Terminate;
  }

  void RequestInterrupt() {
    State.intent.store(ControlIntent::Terminate, std::memory_order_relaxed);
    const auto &token = Core.control.ControlToken();
    if (token) {
      token->RequestInterrupt();
    }
  }

  void ClearInterrupt() {
    const auto &token = Core.control.ControlToken();
    if (token) {
      token->ClearInterrupt();
    }
  }

  void SetRunningIntent() {
    if (IsTerminateRequested()) {
      return;
    }
    State.intent.store(ControlIntent::Running, std::memory_order_relaxed);
  }

  bool IsInterrupted() const {
    return GetIntent() != ControlIntent::Running ||
           Core.control.IsInterrupted();
  }

  void RequestPause() {
    if (IsTerminateRequested()) {
      return;
    }
    State.intent.store(ControlIntent::Pause, std::memory_order_relaxed);
    const auto &token = Core.control.ControlToken();
    if (token) {
      token->RequestInterrupt();
    }
  }

  void SetStatus(TaskStatus new_status) { State.status.store(new_status); }

  void SetResult(const ECM &new_rcm) { State.rcm.lock().store(new_rcm); }

  ECM GetResult() { return State.rcm.lock().load(); }
};

/**
 * @brief User-facing transfer input set with explicit scoped endpoints.
 */
class UserTransferSet {
public:
  /**
   * @brief The list of explicit source endpoints.
   */
  std::vector<ClientPath> srcs = {};

  /**
   * @brief Explicit destination endpoint for all sources in this Set.
   */
  ClientPath dst = {};

  /**
   * @brief Whether to create missing destination directories.
   */
  bool mkdir = true;

  /**
   * @brief Whether to overwrite existing targets.
   */
  bool overwrite = false;

  /**
   * @brief Whether to clone directory layout.
   */
  bool clone = false;

  /**
   * @brief Whether to ignore special files during traversal.
   */
  bool ignore_special_file = true;

  /**
   * @brief Whether to resume from an existing destination breakpoint.
   */
  bool resume = false;

  UserTransferSet() = default;

  UserTransferSet(std::vector<ClientPath> srcs, ClientPath dst, bool mkdir,
                  bool overwrite, bool ignore_special_file, bool resume = false)
      : srcs(std::move(srcs)), dst(std::move(dst)), mkdir(mkdir),
        overwrite(overwrite), ignore_special_file(ignore_special_file),
        resume(resume) {}
};

using TaskHistory = std::unordered_map<TaskInfo::ID, sptr<TaskInfo>>;
using ProgressCallback =
    std::function<void(std::shared_ptr<TaskInfo>, bool force)>;
} // namespace AMDomain::transfer
