#pragma once

#include "application/transfer/TransferWorkflows.hpp"
#include "foundation/DataClass.hpp"
#include <cstddef>
#include <string>
#include <vector>

namespace AMApplication::TaskWorkflow {
/**
 * @brief Session mode flags for task/job command workflows.
 */
struct SessionMode {
  /**
   * @brief Force interactive behavior.
   */
  bool enforce_interactive = false;

  /**
   * @brief Runtime interactive state from current session.
   */
  bool current_interactive = false;

  /**
   * @brief Command label for validation diagnostics.
   */
  std::string command_name;
};

/**
 * @brief Task list filter options.
 */
struct TaskListFilter {
  bool pending = false;
  bool suspend = false;
  bool finished = false;
  bool conducting = false;
};

/**
 * @brief Task inspect options.
 */
struct TaskInspectOptions {
  std::string id;
  bool set = false;
  bool entry = false;
};

/**
 * @brief Retry options for finished tasks.
 */
struct TaskRetryOptions {
  std::string id;
  bool is_async = false;
  bool quiet = false;
  std::vector<int> indices;
};

/**
 * @brief Control action for task control workflow.
 */
enum class TaskControlAction { Terminate, Pause, Resume };

/**
 * @brief Job cache submit options.
 */
struct JobCacheSubmitOptions {
  bool is_async = false;
  bool quiet = false;
  std::string async_suffix;
};

/**
 * @brief Job cache add result payload.
 */
struct JobCacheAddResult {
  ECM rcm = {EC::Success, ""};
  size_t index = 0;
  UserTransferSet transfer_set;
};

/**
 * @brief Job cache remove result payload.
 */
struct JobCacheRemoveResult {
  ECM rcm = {EC::Success, ""};
  std::vector<size_t> removed_indices;
};

/**
 * @brief Job cache query result payload.
 */
struct JobCacheQueryResult {
  ECM rcm = {EC::Success, ""};
  std::vector<size_t> queried_indices;
};

/**
 * @brief Application gateway for task/job operations.
 */
class ITaskGateway {
public:
  /**
   * @brief Virtual destructor for polymorphic gateway.
   */
  virtual ~ITaskGateway() = default;

  /**
   * @brief List tasks by status filters.
   */
  virtual ECM ListTasks(bool pending, bool suspend, bool finished,
                        bool conducting, amf interrupt_flag = nullptr) = 0;

  /**
   * @brief Show one or more tasks.
   */
  virtual ECM ShowTasks(const std::vector<std::string> &ids,
                        amf interrupt_flag = nullptr) = 0;

  /**
   * @brief Inspect one task.
   */
  virtual ECM InspectTask(const std::string &id, bool show_sets,
                          bool show_entries) = 0;

  /**
   * @brief Inspect only transfer sets of one task.
   */
  virtual ECM InspectTaskSets(const std::string &id) = 0;

  /**
   * @brief Inspect only entries of one task.
   */
  virtual ECM InspectTaskEntries(const std::string &id) = 0;

  /**
   * @brief Query one task entry by entry identifier.
   */
  virtual ECM QueryTaskEntry(const std::string &entry_id) = 0;

  /**
   * @brief Get or set transfer worker thread count.
   */
  virtual ECM Thread(int num = -1) = 0;

  /**
   * @brief Terminate multiple tasks.
   */
  virtual ECM TerminateTasks(const std::vector<std::string> &ids) = 0;

  /**
   * @brief Pause multiple tasks.
   */
  virtual ECM PauseTasks(const std::vector<std::string> &ids) = 0;

  /**
   * @brief Resume multiple tasks.
   */
  virtual ECM ResumeTasks(const std::vector<std::string> &ids) = 0;

  /**
   * @brief Retry one finished task.
   */
  virtual ECM RetryTask(const std::string &id, bool is_async, bool quiet,
                        const std::vector<int> &indices) = 0;

  /**
   * @brief Add one transfer set to cache and return index.
   */
  virtual size_t AddCachedTransferSet(const UserTransferSet &transfer_set) = 0;

  /**
   * @brief Remove cached transfer sets and return removed count.
   */
  virtual size_t
  RemoveCachedTransferSets(const std::vector<size_t> &indices) = 0;

  /**
   * @brief Clear all cached transfer sets.
   */
  virtual void ClearCachedTransferSets() = 0;

  /**
   * @brief Submit cached transfer sets.
   */
  virtual ECM SubmitCachedTransferSets(bool quiet, amf interrupt_flag = nullptr,
                                       bool is_async = false) = 0;

  /**
   * @brief Query one cached transfer set by index.
   */
  virtual ECM QueryCachedTransferSet(size_t index) = 0;

  /**
   * @brief List cached transfer set indices.
   */
  [[nodiscard]] virtual std::vector<size_t> ListCachedTransferSetIds() const = 0;
};

/**
 * @brief Return true when mode requires interactive-only behavior.
 */
[[nodiscard]] bool IsInteractiveMode(const SessionMode &mode);

/**
 * @brief Enforce interactive-only command precondition.
 */
ECM EnsureInteractive(const SessionMode &mode);

/**
 * @brief Run task list workflow.
 */
ECM ExecuteTaskList(ITaskGateway &gateway, const TaskListFilter &filter,
                    const SessionMode &mode, amf interrupt_flag = nullptr);

/**
 * @brief Run task show workflow.
 */
ECM ExecuteTaskShow(ITaskGateway &gateway, const std::vector<std::string> &ids,
                    const SessionMode &mode, amf interrupt_flag = nullptr);

/**
 * @brief Run task inspect workflow.
 */
ECM ExecuteTaskInspect(ITaskGateway &gateway, const TaskInspectOptions &options,
                       const SessionMode &mode);

/**
 * @brief Run task entry query workflow.
 */
ECM ExecuteTaskEntryQuery(ITaskGateway &gateway,
                          const std::vector<std::string> &entry_ids,
                          const SessionMode &mode);

/**
 * @brief Run task thread workflow.
 */
ECM ExecuteTaskThread(ITaskGateway &gateway, int num, const SessionMode &mode);

/**
 * @brief Run task control workflow.
 */
ECM ExecuteTaskControl(ITaskGateway &gateway,
                       const std::vector<std::string> &ids,
                       TaskControlAction action, const SessionMode &mode);

/**
 * @brief Run task retry workflow.
 */
ECM ExecuteTaskRetry(ITaskGateway &gateway, const TaskRetryOptions &options,
                     const SessionMode &mode);

/**
 * @brief Run job cache add workflow.
 */
JobCacheAddResult
ExecuteJobCacheAdd(ITaskGateway &gateway,
                   const TransferWorkflow::TransferBuildArgs &build_args,
                   const TransferWorkflow::IPathSubstitutionPort &substitutor,
                   const SessionMode &mode);

/**
 * @brief Run job cache remove workflow.
 */
JobCacheRemoveResult
ExecuteJobCacheRemove(ITaskGateway &gateway, const std::vector<size_t> &indices,
                      const SessionMode &mode);

/**
 * @brief Run job cache clear workflow.
 */
ECM ExecuteJobCacheClear(ITaskGateway &gateway, const SessionMode &mode);

/**
 * @brief Run job cache submit workflow.
 */
ECM ExecuteJobCacheSubmit(ITaskGateway &gateway,
                          const JobCacheSubmitOptions &options,
                          const SessionMode &mode,
                          amf interrupt_flag = nullptr);

/**
 * @brief Run job cache query workflow.
 */
JobCacheQueryResult
ExecuteJobCacheQuery(ITaskGateway &gateway, const std::vector<size_t> &indices,
                     const SessionMode &mode);
} // namespace AMApplication::TaskWorkflow
