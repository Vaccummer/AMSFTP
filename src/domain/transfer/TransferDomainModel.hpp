#pragma once
#include "domain/client/ClientDomainService.hpp"
#include "domain/client/ClientPort.hpp"
#include "domain/filesystem/FileSystemModel.hpp"
#include "foundation/core/DataClass.hpp"
#include "foundation/tools/string.hpp"
#include <chrono>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <map>
#include <optional>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

namespace AMDomain::transfer {
class UserTransferSet;
struct TaskInfo;
struct TransferTask;
using TaskID = int64_t;
using AMDomain::filesystem::PathTarget;
using TASKS = std::vector<TransferTask>;
using ClientHandle = std::shared_ptr<AMDomain::client::IClientPort>;
using ResultCallback = std::function<void(std::shared_ptr<TaskInfo>)>;
using TaskHistory = std::unordered_map<TaskID, sptr<TaskInfo>>;
using ProgressCallback =
    std::function<void(std::shared_ptr<TaskInfo>, bool force)>;

enum class TaskStatus { Pending, Conducting, Paused, Finished };
enum class TaskAssignType { Affinity, Public };
enum class ControlIntent { Running, Pause, Terminate };
enum class ActiveStopReason { Pause, Terminate };
enum class TransferControl { Running = 1, Pause = 0, Terminate = -1 };

struct TransferClientHolder {
  ClientHandle src = nullptr;
  ClientHandle dst = nullptr;
};

class TransferClientContainer final {
public:
  [[nodiscard]] ECM AddSrcClient(const std::string &nickname,
                                 ClientHandle client) {
    if (!client) {
      return Err(ErrorCode::InvalidHandle, "", "",
                 "Source client handle is null");
    }
    const std::string key = NormalizeNickname_(nickname);
    auto &slot = holders_[key];
    if (slot.dst && slot.dst == client) {
      return Err(ErrorCode::InvalidArg, "", "",
                 AMStr::fmt("Source and destination clients must be different "
                            "for host {}",
                            key));
    }
    if (!slot.src) {
      slot.src = std::move(client);
    }
    return OK;
  }

  [[nodiscard]] ECM AddDstClient(const std::string &nickname,
                                 ClientHandle client) {
    if (!client) {
      return Err(ErrorCode::InvalidHandle, "", "",
                 "Destination client handle is null");
    }
    const std::string key = NormalizeNickname_(nickname);
    auto &slot = holders_[key];
    if (slot.src && slot.src == client) {
      return Err(ErrorCode::InvalidArg, "", "",
                 AMStr::fmt("Source and destination clients must be different "
                            "for host {}",
                            key));
    }
    if (!slot.dst) {
      slot.dst = std::move(client);
    }
    return OK;
  }

  [[nodiscard]] std::optional<TransferClientHolder>
  GetClient(const std::string &nickname) const {
    const std::string key = NormalizeNickname_(nickname);
    auto it = holders_.find(key);
    if (it == holders_.end()) {
      return std::nullopt;
    }
    return it->second;
  }

  [[nodiscard]] ClientHandle GetSrcClient(const std::string &nickname) const {
    auto holder = GetClient(nickname);
    if (!holder.has_value()) {
      return nullptr;
    }
    return holder->src;
  }

  [[nodiscard]] ClientHandle GetDstClient(const std::string &nickname) const {
    auto holder = GetClient(nickname);
    if (!holder.has_value()) {
      return nullptr;
    }
    return holder->dst;
  }

  [[nodiscard]] bool empty() const { return holders_.empty(); }

  void ReleaseClient(const std::string &nickname) {
    const std::string key = NormalizeNickname_(nickname);
    auto it = holders_.find(key);
    if (it == holders_.end()) {
      return;
    }
    std::unordered_set<AMDomain::client::IClientPort *> released = {};
    ReleaseClientLease_(it->second.src, &released);
    ReleaseClientLease_(it->second.dst, &released);
    holders_.erase(it);
  }

  void ReleaseAll() {
    std::unordered_set<AMDomain::client::IClientPort *> released = {};
    for (auto &entry : holders_) {
      ReleaseClientLease_(entry.second.src, &released);
      ReleaseClientLease_(entry.second.dst, &released);
    }
    holders_.clear();
  }

private:
  static std::string NormalizeNickname_(const std::string &nickname) {
    return nickname.empty() ? std::string("local") : nickname;
  }

  static void ReleaseClientLease_(
      const ClientHandle &client,
      std::unordered_set<AMDomain::client::IClientPort *> *released) {
    if (!client) {
      return;
    }
    auto *raw = client.get();
    if (released != nullptr && !released->insert(raw).second) {
      return;
    }
    bool wrote = false;
    client->MetaDataPort().MutateNamedValue<bool>(
        "transfer.lease", [&](bool *leased, bool name_found, bool type_match) {
          if (name_found && type_match && leased) {
            *leased = false;
            wrote = true;
          }
        });
    if (!wrote) {
      (void)client->MetaDataPort().StoreNamedData("transfer.lease",
                                                  std::any(false), true);
    }
  }

private:
  std::unordered_map<std::string, TransferClientHolder> holders_ = {};
};

/**
 * @brief Settings payload for `Options.TransferManager`.
 */
struct TransferManagerArg {
  static constexpr size_t kMinBufferBytes = 1024;
  static constexpr size_t kMaxBufferBytes = 1024 * 1024 * 1024;

  int max_threads = 16;
  int bar_refresh_interval_ms = 200;
  size_t ring_buffersize = AMDomain::client::ClientService::AMDefaultBufferSize;
};

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
  ErrorCBInfo(ECM ecm, std::string src, std::string dst, std::string src_host,
              std::string dst_host)
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
      *cb_error = OK;
    }
    if (!progress_cb) {
      return std::nullopt;
    }
    try {
      return progress_cb(info);
    } catch (const std::exception &e) {
      if (cb_error) {
        *cb_error = {EC::PyCBError, "", "", e.what()};
      }
      return TransferControl::Terminate;
    } catch (...) {
      if (cb_error) {
        *cb_error = {EC::PyCBError, "", "", "Unknown progress callback error"};
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
  std::optional<ECM> rcm = std::nullopt;
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
  AMAtomic<ECM> rcm = AMAtomic<ECM>(OK);
  std::atomic<TaskStatus> status{TaskStatus::Pending};
  std::atomic<ControlIntent> intent{ControlIntent::Running};
};

struct TaskSize {
  std::atomic<size_t> total{0};
  std::atomic<size_t> transferred{0};
  std::atomic<size_t> cur_task{0};
  std::atomic<size_t> cur_task_transferred{0};
  std::atomic<size_t> filenum{0};
  std::atomic<size_t> finished_filenum{0};
  std::atomic<size_t> success_filenum{0};
  std::atomic<size_t> buffer{0};
};

struct TaskProgressData {
  struct SpeedSample {
    std::chrono::steady_clock::time_point when = {};
    size_t transferred = 0;
  };

  mutable AMAtomic<std::deque<SpeedSample>> speed_samples =
      AMAtomic<std::deque<SpeedSample>>(std::deque<SpeedSample>{});
};

struct TaskCoreData {
  AMAtomic<TASKS> dir_tasks = AMAtomic<TASKS>(TASKS());
  AMAtomic<TASKS> file_tasks = AMAtomic<TASKS>(TASKS());
  ControlComponent control = {};
  AMAtomic<TransferTask *> cur_task = AMAtomic<TransferTask *>(nullptr);
  TransferClientContainer clients;
  std::vector<std::string> nicknames;
};

struct TaskSet {
  std::shared_ptr<std::vector<UserTransferSet>> transfer_sets = nullptr;
  bool quiet = false;
  TransferCallback callback;
  std::atomic<bool> keep_start_time{false};
  std::atomic<bool> completion_dispatched{false};
  AMAtomic<std::map<size_t, std::function<void()>>> completion_wakeups =
      AMAtomic<std::map<size_t, std::function<void()>>>{};
  std::atomic<size_t> completion_wakeup_seed{1};
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
  TaskID id = 0;
  TaskStruct::TaskTime Time;
  TaskStruct::TaskState State;
  TaskStruct::TaskSize Size;
  TaskStruct::TaskProgressData Progress;
  TaskStruct::TaskCoreData Core;
  TaskStruct::TaskSet Set;
  TaskStruct::TaskCallback Callback;
  struct CurrentTaskSnapshot {
    std::string src = {};
    std::string dst = {};
    std::string src_host = {};
    std::string dst_host = {};
    size_t size = 0;
    size_t transferred = 0;
  };

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
    auto task_l = Core.file_tasks.lock();

    for (const auto &task : *task_l) {
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
    auto local_tasks = Core.file_tasks.lock();
    for (const auto &task : *local_tasks) {
      if (task.path_type == PathType::FILE) {
        current += 1;
      }
    }
    Size.filenum.store(current, std::memory_order_relaxed);
    return current;
  }

  void DeleteProgressData() {
    auto samples = Progress.speed_samples.lock();
    samples->clear();
  }

  void ResetProgressData(bool seed_current_sample = true) {
    auto samples = Progress.speed_samples.lock();
    samples->clear();
    if (!seed_current_sample) {
      return;
    }
    AppendSpeedSampleLocked_(
        &samples, Size.transferred.load(std::memory_order_relaxed),
        std::chrono::steady_clock::now());
  }

  void SetTransferredSize(size_t value) {
    Size.transferred.store(value, std::memory_order_relaxed);
    AppendSpeedSample_(value);
  }

  [[nodiscard]] size_t AddTransferredSize(size_t delta) {
    if (delta == 0) {
      return Size.transferred.load(std::memory_order_relaxed);
    }
    const size_t next =
        Size.transferred.fetch_add(delta, std::memory_order_relaxed) + delta;
    AppendSpeedSample_(next);
    return next;
  }

  [[nodiscard]] size_t SubTransferredSize(size_t delta) {
    if (delta == 0) {
      return Size.transferred.load(std::memory_order_relaxed);
    }
    size_t current = Size.transferred.load(std::memory_order_relaxed);
    while (true) {
      const size_t next = (delta >= current) ? 0 : (current - delta);
      if (Size.transferred.compare_exchange_weak(
              current, next, std::memory_order_relaxed,
              std::memory_order_relaxed)) {
        AppendSpeedSample_(next);
        return next;
      }
    }
  }

  [[nodiscard]] double GetSpeedBytesPerSecond(
      int64_t window_ms = 7000) const {
    const auto horizon =
        std::chrono::milliseconds(std::max<int64_t>(1, window_ms));
    auto samples = Progress.speed_samples.lock();
    if (samples->size() < 2) {
      return 0.0;
    }

    const auto &latest = samples->back();
    const auto cutoff = latest.when - horizon;
    auto first = samples->begin();
    for (auto it = samples->begin(); it != samples->end(); ++it) {
      if (it->when <= cutoff) {
        first = it;
        continue;
      }
      break;
    }

    const double dt =
        std::chrono::duration<double>(latest.when - first->when).count();
    if (dt <= 0.0 || latest.transferred < first->transferred) {
      return 0.0;
    }
    return static_cast<double>(latest.transferred - first->transferred) / dt;
  }

  bool TryMarkCompletionDispatched() {
    bool expected = false;
    return Set.completion_dispatched.compare_exchange_strong(
        expected, true, std::memory_order_acq_rel);
  }

  void ResetCompletionDispatch() {
    Set.completion_dispatched.store(false, std::memory_order_release);
  }

  size_t RegisterCompletionWakeup(std::function<void()> wakeup) {
    if (!wakeup) {
      return 0;
    }
    const size_t id =
        Set.completion_wakeup_seed.fetch_add(1, std::memory_order_relaxed);
    auto wakeups = Set.completion_wakeups.lock();
    (*wakeups)[id] = std::move(wakeup);
    return id;
  }

  bool UnregisterCompletionWakeup(size_t token) {
    if (token == 0) {
      return false;
    }
    auto wakeups = Set.completion_wakeups.lock();
    return wakeups->erase(token) > 0;
  }

  void NotifyCompletionWakeups() {
    std::vector<std::function<void()>> wakeups_copy = {};
    {
      auto wakeups = Set.completion_wakeups.lock();
      wakeups_copy.reserve(wakeups->size());
      for (const auto &[_, wakeup] : *wakeups) {
        if (wakeup) {
          wakeups_copy.push_back(wakeup);
        }
      }
    }
    for (auto &wakeup : wakeups_copy) {
      wakeup();
    }
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

  void RequestInterrupt(size_t grace_period_ms = 0) {
    State.intent.store(ControlIntent::Terminate, std::memory_order_relaxed);
    const auto &token = Core.control.InterruptRaw();
    if (token) {
      token->RequestInterrupt(grace_period_ms);
    }
  }

  void ClearInterrupt() {
    const auto &token = Core.control.InterruptRaw();
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
    return GetIntent() != ControlIntent::Running || Core.control.ShouldStop();
  }

  void RequestPause(size_t grace_period_ms = 0) {
    if (IsTerminateRequested()) {
      return;
    }
    State.intent.store(ControlIntent::Pause, std::memory_order_relaxed);
    const auto &token = Core.control.InterruptRaw();
    if (token) {
      token->RequestInterrupt(grace_period_ms);
    }
  }

  void SetStatus(TaskStatus new_status) { State.status.store(new_status); }

  void SetResult(const ECM &new_rcm) { State.rcm.lock().store(new_rcm); }

  ECM GetResult() { return State.rcm.lock().load(); }

  void SetCurrentTask(TransferTask *task) { Core.cur_task.lock().store(task); }

  void ClearCurrentTask() { Core.cur_task.lock().store(nullptr); }

  [[nodiscard]] TransferTask *GetCurrentTask() const {
    auto guard = const_cast<AMAtomic<TransferTask *> &>(Core.cur_task).lock();
    return guard.load();
  }

  [[nodiscard]] std::optional<CurrentTaskSnapshot>
  GetCurrentTaskSnapshot() const {
    auto guard = const_cast<AMAtomic<TransferTask *> &>(Core.cur_task).lock();
    TransferTask *task = guard.load();
    if (!task) {
      return std::nullopt;
    }
    CurrentTaskSnapshot out = {};
    out.src = task->src;
    out.dst = task->dst;
    out.src_host = task->src_host;
    out.dst_host = task->dst_host;
    out.size = task->size;
    out.transferred = task->transferred;
    return out;
  }

private:
  static constexpr int64_t kSpeedSampleRetentionMs = 60000;
  using SpeedSamples = std::deque<TaskStruct::TaskProgressData::SpeedSample>;
  using SpeedSamplesGuard = AMAtomic<SpeedSamples>::Guard;

  void AppendSpeedSample_(size_t transferred) {
    auto samples = Progress.speed_samples.lock();
    AppendSpeedSampleLocked_(&samples, transferred,
                             std::chrono::steady_clock::now());
  }

  void AppendSpeedSampleLocked_(
      SpeedSamplesGuard *samples, size_t transferred,
      std::chrono::steady_clock::time_point when) {
    if (samples == nullptr) {
      return;
    }
    (*samples)->push_back({when, transferred});
    const auto retention =
        std::chrono::milliseconds(kSpeedSampleRetentionMs);
    while ((*samples)->size() > 1 &&
           (when - (*samples)->front().when) > retention) {
      (*samples)->pop_front();
    }
  }
};

/**
 * @brief User-facing transfer input set with explicit scoped endpoints.
 */
class UserTransferSet {
public:
  /**
   * @brief The list of explicit source endpoints.
   */
  std::vector<PathTarget> srcs = {};

  /**
   * @brief Explicit destination endpoint for all sources in this Set.
   */
  PathTarget dst = {};

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

  UserTransferSet(std::vector<PathTarget> srcs, PathTarget dst, bool mkdir,
                  bool overwrite, bool ignore_special_file, bool resume = false)
      : srcs(std::move(srcs)), dst(std::move(dst)), mkdir(mkdir),
        overwrite(overwrite), ignore_special_file(ignore_special_file),
        resume(resume) {}
};

} // namespace AMDomain::transfer
