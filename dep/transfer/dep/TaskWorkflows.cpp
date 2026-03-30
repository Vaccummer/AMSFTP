#include "application/transfer/TaskWorkflows.hpp"
#include "application/transfer/TransferWorkflows.hpp"
#include "foundation/tools/enum_related.hpp"
#include "foundation/tools/string.hpp"
#include <unordered_set>

namespace AMApplication::TaskWorkflow {
namespace {
/**
 * @brief Deduplicate a list while preserving first-seen order.
 */
template <typename T>
std::vector<T> DedupKeepOrder_(const std::vector<T> &values) {
  std::vector<T> out;
  out.reserve(values.size());
  std::unordered_set<T> seen;
  for (const auto &value : values) {
    if (seen.insert(value).second) {
      out.push_back(value);
    }
  }
  return out;
}
} // namespace

/**
 * @brief Return true when mode requires interactive-only behavior.
 */
bool IsInteractiveMode(const SessionMode &mode) {
  return mode.enforce_interactive || mode.current_interactive;
}

/**
 * @brief Enforce interactive-only command precondition.
 */
ECM EnsureInteractive(const SessionMode &mode) {
  if (IsInteractiveMode(mode)) {
    return Ok();
  }
  const std::string name =
      mode.command_name.empty() ? std::string("Command") : mode.command_name;
  return Err(EC::OperationUnsupported,
             AMStr::fmt("{} not supported in Non-Interactive mode", name));
}

/**
 * @brief Run task list workflow.
 */
ECM ExecuteTaskList(ITaskGateway &gateway, const TaskListFilter &filter,
                    const SessionMode &mode) {
  ECM ready = EnsureInteractive(mode);
  if (!isok(ready)) {
    return ready;
  }
  return gateway.ListTasks(filter.pending, filter.suspend, filter.finished,
                           filter.conducting);
}

/**
 * @brief Run task show workflow.
 */
ECM ExecuteTaskShow(ITaskGateway &gateway, const std::vector<std::string> &ids,
                    const SessionMode &mode) {
  ECM ready = EnsureInteractive(mode);
  if (!isok(ready)) {
    return ready;
  }
  return gateway.ShowTasks(ids);
}

/**
 * @brief Run task inspect workflow.
 */
ECM ExecuteTaskInspect(ITaskGateway &gateway, const TaskInspectOptions &options,
                       const SessionMode &mode) {
  ECM ready = EnsureInteractive(mode);
  if (!isok(ready)) {
    return ready;
  }
  if (options.id.empty() && !options.set && !options.entry) {
    return Ok();
  }
  if (options.id.empty()) {
    return Err(EC::InvalidArg, "Task id required");
  }

  if (options.set || options.entry) {
    if (options.set) {
      ECM rcm = gateway.InspectTaskSets(options.id);
      if (!isok(rcm)) {
        return rcm;
      }
    }
    if (options.entry) {
      return gateway.InspectTaskEntries(options.id);
    }
    return Ok();
  }
  return gateway.InspectTask(options.id, false, false);
}

/**
 * @brief Run task entry query workflow.
 */
ECM ExecuteTaskEntryQuery(ITaskGateway &gateway,
                          const std::vector<std::string> &entry_ids,
                          const SessionMode &mode) {
  ECM ready = EnsureInteractive(mode);
  if (!isok(ready)) {
    return ready;
  }
  ECM last = Ok();
  for (const auto &entry_id : entry_ids) {
    ECM rcm = gateway.QueryTaskEntry(entry_id);
    if (!isok(rcm)) {
      last = rcm;
    }
  }
  return last;
}

/**
 * @brief Run task thread workflow.
 */
ECM ExecuteTaskThread(ITaskGateway &gateway, int num, const SessionMode &mode) {
  ECM ready = EnsureInteractive(mode);
  if (!isok(ready)) {
    return ready;
  }
  return gateway.Thread(num);
}

/**
 * @brief Run task control workflow.
 */
ECM ExecuteTaskControl(ITaskGateway &gateway,
                       const std::vector<std::string> &ids,
                       TaskControlAction action, const SessionMode &mode) {
  ECM ready = EnsureInteractive(mode);
  if (!isok(ready)) {
    return ready;
  }

  switch (action) {
  case TaskControlAction::Terminate:
    return gateway.TerminateTasks(ids);
  case TaskControlAction::Pause:
    return gateway.PauseTasks(ids);
  case TaskControlAction::Resume:
    return gateway.ResumeTasks(ids);
  default:
    return Err(EC::InvalidArg, "Unknown task control action");
  }
}

/**
 * @brief Run task retry workflow.
 */
ECM ExecuteTaskRetry(ITaskGateway &gateway, const TaskRetryOptions &options,
                     const SessionMode &mode) {
  ECM ready = EnsureInteractive(mode);
  if (!isok(ready)) {
    return ready;
  }
  return gateway.RetryTask(options.id, options.is_async, options.quiet,
                           options.indices);
}

/**
 * @brief Run job cache add workflow.
 */
JobCacheAddResult
ExecuteJobCacheAdd(ITaskGateway &gateway,
                   const TransferWorkflow::TransferBuildArgs &build_args,
                   const SessionMode &mode) {
  JobCacheAddResult out = {};
  ECM ready = EnsureInteractive(mode);
  if (!isok(ready)) {
    out.rcm = ready;
    return out;
  }

  out.rcm = TransferWorkflow::BuildTransferSet(build_args, &out.transfer_set);
  if (!isok(out.rcm)) {
    return out;
  }
  out.index = gateway.AddCachedTransferSet(out.transfer_set);
  return out;
}

/**
 * @brief Run job cache remove workflow.
 */
JobCacheRemoveResult
ExecuteJobCacheRemove(ITaskGateway &gateway, const std::vector<size_t> &indices,
                      const SessionMode &mode) {
  JobCacheRemoveResult out = {};
  ECM ready = EnsureInteractive(mode);
  if (!isok(ready)) {
    out.rcm = ready;
    return out;
  }

  out.removed_indices = DedupKeepOrder_(indices);
  const size_t removed = gateway.RemoveCachedTransferSets(out.removed_indices);
  if (removed < out.removed_indices.size()) {
    out.rcm = Err(EC::InvalidArg, "Cache index not found");
  }
  return out;
}

/**
 * @brief Run job cache clear workflow.
 */
ECM ExecuteJobCacheClear(ITaskGateway &gateway, const SessionMode &mode) {
  ECM ready = EnsureInteractive(mode);
  if (!isok(ready)) {
    return ready;
  }
  gateway.ClearCachedTransferSets();
  return Ok();
}

/**
 * @brief Run job cache submit workflow.
 */
ECM ExecuteJobCacheSubmit(ITaskGateway &gateway,
                          const JobCacheSubmitOptions &options,
                          const SessionMode &mode) {
  ECM ready = EnsureInteractive(mode);
  if (!isok(ready)) {
    return ready;
  }
  bool suffix_async = false;
  ECM rcm =
      TransferWorkflow::ValidateAsyncSuffix(options.async_suffix, &suffix_async);
  if (!isok(rcm)) {
    return rcm;
  }
  return gateway.SubmitCachedTransferSets(options.quiet,
                                          options.is_async || suffix_async);
}

/**
 * @brief Run job cache query workflow.
 */
JobCacheQueryResult
ExecuteJobCacheQuery(ITaskGateway &gateway, const std::vector<size_t> &indices,
                     const SessionMode &mode) {
  JobCacheQueryResult out = {};
  ECM ready = EnsureInteractive(mode);
  if (!isok(ready)) {
    out.rcm = ready;
    return out;
  }

  std::vector<size_t> targets = DedupKeepOrder_(indices);
  if (targets.empty()) {
    targets = gateway.ListCachedTransferSetIds();
  }

  ECM last = Ok();
  for (size_t index : targets) {
    ECM rcm = gateway.QueryCachedTransferSet(index);
    if (!isok(rcm)) {
      last = rcm;
    }
  }
  out.queried_indices = std::move(targets);
  out.rcm = last;
  return out;
}
} // namespace AMApplication::TaskWorkflow
