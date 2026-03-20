#include "TransferBackendPort.hpp"

#include "AMWorkManager.hpp"
#include "foundation/tools/enum_related.hpp"
#include "foundation/tools/string.hpp"

#include <algorithm>
#include <list>
#include <mutex>
#include <unordered_set>
#include <utility>

namespace AMApplication::TransferRuntime {
namespace {
/**
 * @brief Native application runtime backend for transfer orchestration.
 */
class DefaultTransferBackend final : public ITransferBackendPort {
public:
  /**
   * @brief Construct one backend with an internal application worker.
   */
  DefaultTransferBackend(std::function<int()> thread_count_provider,
                         std::function<std::shared_ptr<ITransferClientPoolPort>()>
                             pool_provider)
      : thread_count_provider_(std::move(thread_count_provider)),
        pool_provider_(std::move(pool_provider)),
        worker_(std::make_shared<AMWorkManager>()) {}

  /**
   * @brief Initialize transfer backend runtime.
   */
  ECM Init() override {
    if (!worker_) {
      worker_ = std::make_shared<AMWorkManager>();
    }
    int init_thread_num = 1;
    if (thread_count_provider_) {
      try {
        init_thread_num = thread_count_provider_();
      } catch (...) {
        init_thread_num = 1;
      }
    }
    init_thread_num = std::min(std::max(1, init_thread_num), 128);
    (void)worker_->ThreadCount(static_cast<size_t>(init_thread_num));
    return Ok();
  }

  /**
   * @brief Execute one prepared task synchronously.
   */
  ECM TransferTaskSync(
      const std::shared_ptr<TaskInfo> &task_info,
      AMDomain::client::amf interrupt_flag) override {
    if (!task_info) {
      return Ok();
    }
    if (!task_info->tasks || task_info->tasks->empty()) {
      return Ok();
    }
    if (!worker_) {
      return Err(EC::InvalidHandle, "Transfer worker backend is unavailable");
    }

    auto token = TaskControlToken::CreateShared();
    task_info->control_token = token;
    if (interrupt_flag && interrupt_flag->IsInterrupted()) {
      (void)token->Terminate();
    }

    BindHistoryResultCallback_(task_info);
    ECM submit_rcm = worker_->Submit(task_info);
    if (!isok(submit_rcm)) {
      return submit_rcm;
    }

    while (!task_info->WaitFinished(100)) {
      if (!interrupt_flag || !interrupt_flag->IsInterrupted()) {
        continue;
      }
      auto term_result = worker_->Terminate(task_info->id, 1000);
      ECM term_rcm = term_result.second;
      if (term_rcm.first == EC::Success || term_rcm.first == EC::TaskNotFound ||
          term_rcm.first == EC::OperationUnsupported) {
        continue;
      }
      return term_rcm;
    }

    RecordHistory_(task_info);
    return task_info->GetResult();
  }

  /**
   * @brief Execute one prepared task asynchronously.
   */
  ECM TransferTaskAsync(
      const std::shared_ptr<TaskInfo> &task_info,
      AMDomain::client::amf interrupt_flag) override {
    if (!task_info) {
      return Ok();
    }
    if (!task_info->tasks || task_info->tasks->empty()) {
      return Err(EC::InvalidArg, "Task List is empty");
    }
    if (!worker_) {
      return Err(EC::InvalidHandle, "Transfer worker backend is unavailable");
    }

    if (interrupt_flag && interrupt_flag->IsInterrupted()) {
      return Err(EC::Terminate, "Interrupted before async transfer submission");
    }

    task_info->control_token = TaskControlToken::CreateShared();

    BindHistoryResultCallback_(task_info);
    return worker_->Submit(task_info);
  }

  /**
   * @brief Create one task-info object bound to a transfer client pool.
   */
  [[nodiscard]] std::shared_ptr<TaskInfo> CreateTaskInfo(
      std::shared_ptr<TASKS> tasks,
      const std::shared_ptr<ITransferClientPoolPort> &pool,
      TransferCallback callback = TransferCallback(),
      ssize_t buffer_size = -1, bool quiet = false,
      int thread_id = -1) override {
    if (!worker_) {
      ECM init_rcm = Init();
      if (!isok(init_rcm)) {
        return nullptr;
      }
    }
    if (!worker_ || !tasks || !pool) {
      return nullptr;
    }
    return worker_->CreateTaskInfo(std::move(tasks), pool, std::move(callback),
                                   buffer_size, quiet, thread_id);
  }

  /**
   * @brief List transfer task ids.
   */
  [[nodiscard]] std::vector<ID> ListTaskIds() const override {
    std::vector<ID> ids = {};
    std::unordered_set<ID> seen = {};
    for (const auto &task_info : CollectAllTasks_()) {
      if (!task_info || task_info->id.empty()) {
        continue;
      }
      if (seen.insert(task_info->id).second) {
        ids.push_back(task_info->id);
      }
    }
    return ids;
  }

  /**
   * @brief Find transfer task by id.
   */
  [[nodiscard]] std::shared_ptr<TaskInfo>
  FindTask(const ID &task_id) const override {
    if (task_id.empty() || !worker_) {
      return nullptr;
    }
    auto active = worker_->GetTask(task_id);
    if (active.first) {
      return active.first;
    }
    auto finished = worker_->GetResult(task_id, false);
    if (finished) {
      return finished;
    }
    std::lock_guard<std::mutex> lock(history_mtx_);
    for (const auto &task_info : history_) {
      if (task_info && task_info->id == task_id) {
        return task_info;
      }
    }
    return nullptr;
  }

  /**
   * @brief Get counts of pending and conducting tasks.
   */
  void GetTaskCounts(size_t *pending_count,
                     size_t *conducting_count) const override {
    if (pending_count) {
      *pending_count = worker_ ? worker_->PendingCount() : 0;
    }
    if (conducting_count) {
      *conducting_count =
          worker_ ? worker_->GetConductingIds().size() : static_cast<size_t>(0);
    }
  }

  /**
   * @brief Get or set worker thread count.
   */
  ECM Thread(int num = -1) override {
    if (!worker_) {
      return Err(EC::InvalidHandle, "Transfer worker backend is unavailable");
    }
    if (num < 0) {
      const size_t count = worker_->ThreadCount(0);
      return {EC::Success, std::to_string(count)};
    }
    if (num < 1) {
      return Err(EC::InvalidArg, "Thread count must be >= 1");
    }
    const size_t count = worker_->ThreadCount(static_cast<size_t>(num));
    return {EC::Success, std::to_string(count)};
  }

  /**
   * @brief Apply worker thread count without presentation side effects.
   */
  ECM SetWorkerThreadCount(size_t count) override {
    if (!worker_) {
      return Err(EC::InvalidHandle, "Transfer worker backend is unavailable");
    }
    if (count == 0) {
      return Err(EC::InvalidArg, "Thread count must be >= 1");
    }
    const size_t updated = worker_->ThreadCount(count);
    return {EC::Success, std::to_string(updated)};
  }

  /**
   * @brief Terminate one task.
   */
  ECM Terminate(const ID &task_id, int timeout_ms = 5000) override {
    if (!worker_) {
      return Err(EC::InvalidHandle, "Transfer worker backend is unavailable");
    }
    auto [task_info, rcm] = worker_->Terminate(task_id, timeout_ms);
    if (task_info && isok(rcm)) {
      RecordHistory_(task_info);
    }
    return rcm;
  }

  /**
   * @brief Terminate tasks in batch.
   */
  ECM Terminate(const std::vector<ID> &task_ids,
                int timeout_ms = 5000) override {
    if (task_ids.empty()) {
      return Err(EC::InvalidArg, "Task id list is empty");
    }
    ECM first_error = Ok();
    std::vector<ID> failed_ids = {};
    for (const auto &task_id : task_ids) {
      ECM rcm = Terminate(task_id, timeout_ms);
      if (isok(rcm)) {
        continue;
      }
      if (isok(first_error)) {
        first_error = rcm;
      }
      failed_ids.push_back(task_id);
    }
    if (failed_ids.empty()) {
      return Ok();
    }
    return {first_error.first,
            AMStr::fmt("Terminate failed for: {}", AMStr::join(failed_ids, ", "))};
  }

  /**
   * @brief Pause one task.
   */
  ECM Pause(const ID &task_id) override {
    if (!worker_) {
      return Err(EC::InvalidHandle, "Transfer worker backend is unavailable");
    }
    return worker_->Pause(task_id);
  }

  /**
   * @brief Pause tasks in batch.
   */
  ECM Pause(const std::vector<ID> &task_ids) override {
    if (task_ids.empty()) {
      return Err(EC::InvalidArg, "Task id list is empty");
    }
    ECM first_error = Ok();
    std::vector<ID> failed_ids = {};
    for (const auto &task_id : task_ids) {
      ECM rcm = Pause(task_id);
      if (isok(rcm)) {
        continue;
      }
      if (isok(first_error)) {
        first_error = rcm;
      }
      failed_ids.push_back(task_id);
    }
    if (failed_ids.empty()) {
      return Ok();
    }
    return {first_error.first,
            AMStr::fmt("Pause failed for: {}", AMStr::join(failed_ids, ", "))};
  }

  /**
   * @brief Resume one task.
   */
  ECM Resume(const ID &task_id) override {
    if (!worker_) {
      return Err(EC::InvalidHandle, "Transfer worker backend is unavailable");
    }
    return worker_->Resume(task_id);
  }

  /**
   * @brief Resume tasks in batch.
   */
  ECM Resume(const std::vector<ID> &task_ids) override {
    if (task_ids.empty()) {
      return Err(EC::InvalidArg, "Task id list is empty");
    }
    ECM first_error = Ok();
    std::vector<ID> failed_ids = {};
    for (const auto &task_id : task_ids) {
      ECM rcm = Resume(task_id);
      if (isok(rcm)) {
        continue;
      }
      if (isok(first_error)) {
        first_error = rcm;
      }
      failed_ids.push_back(task_id);
    }
    if (failed_ids.empty()) {
      return Ok();
    }
    return {first_error.first,
            AMStr::fmt("Resume failed for: {}", AMStr::join(failed_ids, ", "))};
  }

  /**
   * @brief Retry one finished task.
   */
  ECM Retry(const ID &task_id, bool is_async, bool quiet,
            const std::vector<int> &indices) override {
    if (!worker_) {
      return Err(EC::InvalidHandle, "Transfer worker backend is unavailable");
    }
    auto old_task_info = FindTask(task_id);
    if (!old_task_info) {
      return Err(EC::TaskNotFound, AMStr::fmt("Task not found: {}", task_id));
    }
    if (old_task_info->GetStatus() != TaskStatus::Finished) {
      return Err(EC::OperationUnsupported,
                 AMStr::fmt("Task is not finished: {}", task_id));
    }
    if (!old_task_info->tasks || old_task_info->tasks->empty()) {
      return Err(EC::InvalidArg, "Task has no entries to retry");
    }

    std::vector<size_t> selected = {};
    selected.reserve(indices.empty() ? old_task_info->tasks->size()
                                     : indices.size());
    if (indices.empty()) {
      for (size_t i = 0; i < old_task_info->tasks->size(); ++i) {
        if (old_task_info->tasks->at(i).rcm.first != EC::Success) {
          selected.push_back(i);
        }
      }
      if (selected.empty()) {
        for (size_t i = 0; i < old_task_info->tasks->size(); ++i) {
          selected.push_back(i);
        }
      }
    } else {
      std::unordered_set<size_t> seen = {};
      for (int index : indices) {
        if (index <= 0 ||
            static_cast<size_t>(index) > old_task_info->tasks->size()) {
          return Err(
              EC::InvalidArg,
              AMStr::fmt("Retry index out of range: {} for task {}", index, task_id));
        }
        const size_t normalized = static_cast<size_t>(index - 1);
        if (seen.insert(normalized).second) {
          selected.push_back(normalized);
        }
      }
    }

    auto retry_tasks = std::make_shared<TASKS>();
    retry_tasks->reserve(selected.size());
    for (size_t index : selected) {
      auto task = old_task_info->tasks->at(index);
      task.IsFinished = false;
      task.rcm = Ok();
      task.transferred = 0;
      retry_tasks->push_back(std::move(task));
    }
    if (retry_tasks->empty()) {
      return Err(EC::InvalidArg, "No task entries selected for retry");
    }

    auto pool = pool_provider_ ? pool_provider_() : nullptr;
    if (!pool) {
      return Err(EC::InvalidHandle, "Transfer client pool is unavailable");
    }
    auto retry_info = worker_->CreateTaskInfo(
        retry_tasks, std::move(pool), old_task_info->callback, -1, quiet,
        old_task_info->affinity_thread.load(std::memory_order_relaxed));
    retry_info->nicknames = old_task_info->nicknames;
    if (old_task_info->transfer_sets) {
      retry_info->transfer_sets = std::make_shared<std::vector<UserTransferSet>>(
          *old_task_info->transfer_sets);
    }

    if (is_async) {
      return TransferTaskAsync(retry_info, nullptr);
    }
    return TransferTaskSync(retry_info, nullptr);
  }

private:
  /**
   * @brief Bind history-record callback while preserving existing callback.
   */
  void BindHistoryResultCallback_(const std::shared_ptr<TaskInfo> &task_info) {
    if (!task_info) {
      return;
    }
    auto user_callback = task_info->result_callback;
    task_info->result_callback =
        [this, user_callback](const std::shared_ptr<TaskInfo> &finished_info) {
          RecordHistory_(finished_info);
          if (user_callback) {
            (void)CallCallbackSafe(user_callback, finished_info);
          }
        };
  }

  /**
   * @brief Record one finished task into history cache.
   */
  void RecordHistory_(const std::shared_ptr<TaskInfo> &task_info) {
    if (!task_info || task_info->id.empty()) {
      return;
    }
    std::lock_guard<std::mutex> lock(history_mtx_);
    auto it = std::find_if(history_.begin(), history_.end(),
                           [&task_info](const std::shared_ptr<TaskInfo> &it_task) {
                             return it_task && it_task->id == task_info->id;
                           });
    if (it == history_.end()) {
      history_.push_front(task_info);
      return;
    }
    *it = task_info;
  }

  /**
   * @brief Build one merged task snapshot across active/finished caches.
   */
  [[nodiscard]] std::vector<std::shared_ptr<TaskInfo>> CollectAllTasks_() const {
    std::vector<std::shared_ptr<TaskInfo>> out = {};
    if (!worker_) {
      return out;
    }
    std::unordered_set<ID> seen = {};

    auto append_task = [&out, &seen](const std::shared_ptr<TaskInfo> &task_info) {
      if (!task_info || task_info->id.empty()) {
        return;
      }
      if (seen.insert(task_info->id).second) {
        out.push_back(task_info);
      }
    };

    for (const auto &[_, task_info] : worker_->GetRegistryCopy()) {
      append_task(task_info);
    }
    for (const auto &task_id : worker_->GetResultIds()) {
      append_task(worker_->GetResult(task_id, false));
    }
    {
      std::lock_guard<std::mutex> lock(history_mtx_);
      for (const auto &task_info : history_) {
        append_task(task_info);
      }
    }
    return out;
  }

private:
  std::function<int()> thread_count_provider_ = {};
  std::function<std::shared_ptr<ITransferClientPoolPort>()> pool_provider_ = {};
  std::shared_ptr<AMWorkManager> worker_ = nullptr;
  mutable std::mutex history_mtx_;
  std::list<std::shared_ptr<TaskInfo>> history_ = {};
};
} // namespace

/**
 * @brief Create the application-native transfer backend.
 */
std::shared_ptr<ITransferBackendPort> CreateDefaultTransferBackend(
    std::function<int()> thread_count_provider,
    std::function<std::shared_ptr<ITransferClientPoolPort>()> pool_provider) {
  return std::make_shared<DefaultTransferBackend>(
      std::move(thread_count_provider), std::move(pool_provider));
}
} // namespace AMApplication::TransferRuntime
