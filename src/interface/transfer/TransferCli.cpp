#include "foundation/DataClass.hpp"
#include "interface/ApplicationAdapters.hpp"
#include "foundation/Path.hpp"
#include "foundation/tools/time.hpp"
#include "domain/transfer/TransferCacheDomainService.hpp"
#include "application/transfer/runtime/AMWorkManager.hpp"
#include "interface/Prompt.hpp"
#include "domain/transfer/TransferManager.hpp"
#include <algorithm>
#include <atomic>
#include <cctype>
#include <cstddef>
#include <memory>
#include <unordered_set>

namespace {
/**
 * @brief Return shared transfer-cache domain service instance.
 */
AMDomain::transfer::TransferCacheDomainService &TransferCacheService_() {
  static AMDomain::transfer::TransferCacheDomainService service;
  return service;
}

/**
 * @brief Print one transfer task entry.
 */
void PrintTaskEntry_(AMPromptManager &prompt, const TransferTask &task,
                     size_t index) {
  prompt.FmtPrint("[{}]", index);
  prompt.Print("");
  const std::string src_host = task.src_host.empty() ? "local" : task.src_host;
  const std::string dst_host = task.dst_host.empty() ? "local" : task.dst_host;
  prompt.FmtPrint("src: {}@{}", src_host, task.src);
  prompt.Print("");
  prompt.FmtPrint("dst: {}@{}", dst_host, task.dst);
  prompt.Print("");
  prompt.FmtPrint("size: {}", AMStr::FormatSize(task.size));
  prompt.Print("");
  prompt.FmtPrint("transferred: {}", AMStr::FormatSize(task.transferred));
  if (task.IsFinished) {
    std::string rcm_name = std::string(magic_enum::enum_name(task.rcm.first));
    std::string rcm_text = rcm_name;
    if (!task.rcm.second.empty()) {
      rcm_text = AMStr::fmt("{}: {}", rcm_name, task.rcm.second);
    }
    prompt.Print("");
    prompt.FmtPrint("rcm: {}", rcm_text);
  }
}

/**
 * @brief Print task entries from a task info object.
 */
void PrintInspectTaskEntries_(AMPromptManager &prompt,
                              const std::shared_ptr<TaskInfo> &task_info) {
  if (!task_info || !task_info->tasks) {
    return;
  }

  const auto &tasks = *task_info->tasks;
  for (size_t i = 0; i < tasks.size(); ++i) {
    PrintTaskEntry_(prompt, tasks[i], i + 1);
    if (i + 1 < tasks.size()) {
      prompt.Print("");
    }
  }
}

/**
 * @brief Print original user transfer sets from a task info object.
 */
void PrintInspectTransferSets_(AMPromptManager &prompt,
                               const std::shared_ptr<TaskInfo> &task_info) {
  if (!task_info || !task_info->transfer_sets) {
    return;
  }

  const auto &sets = *task_info->transfer_sets;
  const bool show_index = sets.size() > 1;
  for (size_t i = 0; i < sets.size(); ++i) {
    const auto &set = sets[i];
    if (show_index) {
      prompt.FmtPrint("[{}]", i + 1);
      prompt.Print("");
    }
    for (const auto &src : set.srcs) {
      prompt.Print(src);
    }
    prompt.Print("");
    prompt.FmtPrint(" ->  {}", set.dst);
    prompt.Print("");
    prompt.FmtPrint("clone = {}", set.clone ? "true" : "false");
    prompt.FmtPrint("mkdir = {}", set.mkdir ? "true" : "false");
    prompt.FmtPrint("overwrite = {}", set.overwrite ? "true" : "false");
    prompt.FmtPrint("no special = {}",
                    set.ignore_special_file ? "true" : "false");
    prompt.FmtPrint("resume = {}", set.resume ? "true" : "false");
    if (i + 1 < sets.size()) {
      prompt.Print("");
    }
  }
}

/**
 * @brief Print detailed task fields and optional sections.
 */
void PrintInspectTask_(AMPromptManager &prompt,
                       const std::shared_ptr<TaskInfo> &task_info,
                       bool show_task_entries, bool show_transfer_sets) {
  if (!task_info) {
    return;
  }

  const auto status_name =
      std::string(magic_enum::enum_name(task_info->GetStatus()));
  const std::string submit_time =
      task_info->submit_time.load(std::memory_order_relaxed) > 0.0
          ? FormatTime(static_cast<size_t>(
                task_info->submit_time.load(std::memory_order_relaxed)))
          : "-";
  const std::string start_time =
      task_info->start_time.load(std::memory_order_relaxed) > 0.0
          ? FormatTime(static_cast<size_t>(
                task_info->start_time.load(std::memory_order_relaxed)))
          : "-";
  const std::string finished_time =
      task_info->finished_time.load(std::memory_order_relaxed) > 0.0
          ? FormatTime(static_cast<size_t>(
                task_info->finished_time.load(std::memory_order_relaxed)))
          : "-";

  ECM rcm = task_info->GetResult();
  std::string rcm_name = std::string(magic_enum::enum_name(rcm.first));
  std::string rcm_text = rcm_name;
  if (!rcm.second.empty()) {
    rcm_text = AMStr::fmt("{}: {}", rcm_name, rcm.second);
  }

  size_t files_num = task_info->tasks ? task_info->tasks->size() : 0;

  std::vector<std::string> client_names = task_info->nicknames;
  if (client_names.empty()) {
    client_names.emplace_back("local");
  }

  std::vector<std::pair<std::string, std::string>> fields = {
      {"id", task_info->id},
      {"status", status_name},
      {"submit_time", submit_time},
      {"start_time", start_time},
      {"finished_time", finished_time},
      {"rcm", rcm_text},
      {"total_transferred_size",
       AMStr::FormatSize(
           task_info->total_transferred_size.load(std::memory_order_relaxed))},
      {"total_size", AMStr::FormatSize(task_info->total_size.load(
                         std::memory_order_relaxed))},
      {"files_num", std::to_string(files_num)},
      {"quiet", task_info->quiet ? "true" : "false"},
      {"affinity_thread", std::to_string(task_info->affinity_thread.load(
                              std::memory_order_relaxed))},
      {"on_which_thread", std::to_string(task_info->OnWhichThread.load(
                              std::memory_order_relaxed))},
      {"buffer_size",
       std::to_string(task_info->buffer_size.load(std::memory_order_relaxed))},
      {"client_names", AMStr::join(client_names, ", ")}};

  size_t max_len = 0;
  for (const auto &field : fields) {
    max_len = std::max<size_t>(max_len, field.first.size());
  }

  for (const auto &field : fields) {
    std::string label = field.first;
    if (label.size() < max_len) {
      label.append(max_len - label.size(), ' ');
    }
    prompt.FmtPrint("{} : {}", label, field.second);
  }

  if (show_task_entries) {
    PrintInspectTaskEntries_(prompt, task_info);
  }
  if (show_transfer_sets) {
    PrintInspectTransferSets_(prompt, task_info);
  }
}

} // namespace

/**
 * @brief Submit a transfer set into the cache pool.
 */
size_t
AMDomain::transfer::AMTransferManager::SubmitTransferSet(const UserTransferSet &transfer_set) {
  std::lock_guard<std::mutex> lock(cache_mtx_);
  return TransferCacheService_().SubmitTransferSet(&cached_sets_, transfer_set);
}

/**
 * @brief Submit multiple transfer sets into the cache pool.
 */
std::vector<size_t> AMDomain::transfer::AMTransferManager::SubmitTransferSets(
    const std::vector<UserTransferSet> &transfer_sets) {
  std::lock_guard<std::mutex> lock(cache_mtx_);
  return TransferCacheService_().SubmitTransferSets(&cached_sets_,
                                                    transfer_sets);
}

/**
 * @brief Query a cached transfer set by ID.
 */
ECM AMDomain::transfer::AMTransferManager::QueryTransferSet(size_t set_index,
                                        UserTransferSet *out_set) const {
  std::lock_guard<std::mutex> lock(cache_mtx_);
  return TransferCacheService_().QueryTransferSet(cached_sets_, set_index,
                                                  out_set);
}

/**
 * @brief List all cached transfer set IDs.
 */
std::vector<size_t> AMDomain::transfer::AMTransferManager::ListTransferSetIds() const {
  std::lock_guard<std::mutex> lock(cache_mtx_);
  return TransferCacheService_().ListTransferSetIds(cached_sets_);
}

/**
 * @brief List task IDs across pending, conducting, and finished tasks.
 */
std::vector<AMDomain::transfer::AMTransferManager::ID> AMDomain::transfer::AMTransferManager::ListTaskIds() const {
  std::unordered_set<ID> seen;
  std::vector<ID> ids;

  auto add_id = [&seen, &ids](const ID &id) {
    if (id.empty()) {
      return;
    }
    if (seen.insert(id).second) {
      ids.push_back(id);
    }
  };

  auto pending = worker_->GetPendingTasks();
  for (const auto &task : pending) {
    if (task) {
      add_id(task->id);
    }
  }

  auto conducting = worker_->GetConductingTasks();
  for (const auto &task : conducting) {
    if (task) {
      add_id(task->id);
    }
  }

  auto result_ids = worker_->GetResultIds();
  for (const auto &id : result_ids) {
    add_id(id);
  }

  {
    std::lock_guard<std::mutex> lock(history_mtx_);
    for (const auto &task : history_) {
      if (task) {
        add_id(task->id);
      }
    }
  }

  std::sort(ids.begin(), ids.end());
  return ids;
}

/**
 * @brief Get counts of pending and conducting tasks for prompt display.
 *
 * @param pending_count Output count of pending tasks (nullable).
 * @param conducting_count Output count of conducting tasks (nullable).
 */
void AMDomain::transfer::AMTransferManager::GetTaskCounts(size_t *pending_count,
                                      size_t *conducting_count) const {
  if (pending_count) {
    *pending_count = 0;
  }
  if (conducting_count) {
    *conducting_count = 0;
  }
  if (!pending_count && !conducting_count) {
    return;
  }

  const auto pending = worker_->GetPendingTasks();
  const auto conducting = worker_->GetConductingTasks();
  if (pending_count) {
    *pending_count = pending.size();
  }
  if (conducting_count) {
    *conducting_count = conducting.size();
  }
}

/**
 * @brief Delete cached transfer sets by indices.
 */
size_t
AMDomain::transfer::AMTransferManager::DeleteTransferSets(const std::vector<size_t> &set_indices) {
  std::lock_guard<std::mutex> lock(cache_mtx_);
  std::vector<ECM> warnings;
  const size_t removed = TransferCacheService_().DeleteTransferSets(
      &cached_sets_, set_indices, &warnings);
  for (const auto &warning : warnings) {
    AMPromptManager::Instance().ErrorFormat(warning);
  }
  return removed;
}

/**
 * @brief Clear all cached transfer sets.
 */
void AMDomain::transfer::AMTransferManager::ClearCachedTransferSets() {
  std::lock_guard<std::mutex> lock(cache_mtx_);
  TransferCacheService_().Clear(&cached_sets_);
}

/**
 * @brief Submit cached transfer sets as a task.
 */
ECM AMDomain::transfer::AMTransferManager::SubmitCachedTransferSets(
    bool quiet, std::shared_ptr<TaskControlToken> interrupt_flag,
    bool is_async) {
  std::vector<UserTransferSet> transfer_sets;
  {
    std::lock_guard<std::mutex> lock(cache_mtx_);
    transfer_sets = TransferCacheService_().SnapshotValidSets(cached_sets_);
  }

  if (transfer_sets.empty()) {
    std::string msg = "Cached transfer set is empty";
    AMPromptManager::Instance().ErrorFormat(ECM{EC::InvalidArg, msg});
    return {EC::InvalidArg, msg};
  }

  if (!quiet) {
    auto temp = std::make_shared<TaskInfo>(true);
    temp->transfer_sets =
        std::make_shared<std::vector<UserTransferSet>>(transfer_sets);
    PrintInspectTransferSets_(AMPromptManager::Instance(), temp);
    bool canceled = false;
    if (!AMPromptManager::Instance().PromptYesNo(
            "Submit cached transfer sets? (y/N): ", &canceled)) {
      AMPromptManager::Instance().FmtPrint(
          "🚫  {}\n",
          AMInterface::ApplicationAdapters::Runtime::Format("Add Canceled", "abort"));
      return {EC::Terminate, "Task submission canceled"};
    }
  }

  ECM rcm = is_async ? transfer_async(transfer_sets, quiet, interrupt_flag)
                     : transfer(transfer_sets, quiet, interrupt_flag);
  if (rcm.first == EC::Success) {
    ClearCachedTransferSets();
  }
  AMPromptManager::Instance().ErrorFormat(rcm);
  return rcm;
}

/**
 * @brief Inspect a task by ID.
 */
ECM AMDomain::transfer::AMTransferManager::Inspect(const ID &task_id, bool show_sets,
                               bool show_entries) const {
  auto task_info = FindTaskById_(task_id);
  if (!task_info) {
    return {EC::TaskNotFound, AMStr::fmt("Task ID not found: {}", task_id)};
  }
  PrintInspectTask_(AMPromptManager::Instance(), task_info, show_entries,
                    show_sets);
  return {EC::Success, ""};
}

/**
 * @brief Inspect only transfer sets for a task by ID.
 */
ECM AMDomain::transfer::AMTransferManager::InspectTransferSets(const ID &task_id) const {
  auto task_info = FindTaskById_(task_id);
  if (!task_info) {
    return {EC::TaskNotFound, AMStr::fmt("Task ID not found: {}", task_id)};
  }
  PrintInspectTransferSets_(AMPromptManager::Instance(), task_info);
  return {EC::Success, ""};
}

/**
 * @brief Inspect only task entries for a task by ID.
 */
ECM AMDomain::transfer::AMTransferManager::InspectTaskEntries(const ID &task_id) const {
  auto task_info = FindTaskById_(task_id);
  if (!task_info) {
    return {EC::TaskNotFound, AMStr::fmt("Task ID not found: {}", task_id)};
  }
  PrintInspectTaskEntries_(AMPromptManager::Instance(), task_info);
  return {EC::Success, ""};
}

/**
 * @brief Inspect a cached user transfer set by cache ID.
 */
ECM AMDomain::transfer::AMTransferManager::QueryCachedUserSet(size_t set_index) const {
  UserTransferSet transfer_set;
  ECM rcm = QueryTransferSet(set_index, &transfer_set);
  if (rcm.first != EC::Success) {
    AMPromptManager::Instance().ErrorFormat(rcm);
    return rcm;
  }

  auto temp = std::make_shared<TaskInfo>(true);
  temp->transfer_sets = std::make_shared<std::vector<UserTransferSet>>(
      std::vector<UserTransferSet>{transfer_set});
  PrintInspectTransferSets_(AMPromptManager::Instance(), temp);
  return {EC::Success, ""};
}

ECM AMDomain::transfer::AMTransferManager::Thread(int num) {
  static const int max_threads = std::max(
      1, std::min(AMInterface::ApplicationAdapters::Runtime::ResolveSettingInt(
                      {"Options", "TransferManager", "max_thread_num"}, 16),
                  999999));

  if (num == -1) {
    const size_t current = worker_->ThreadCount(0);
    AMPromptManager::Instance().FmtPrint("Current ThreadNum: {}", current);
    return {EC::Success, ""};
  }
  ECM rcm = {EC::Success, ""};
  if (num <= 0) {
    rcm = {EC::InvalidArg,
           AMStr::fmt("ThreadNum must be positive, but receive {}", num)};
    AMPromptManager::Instance().ErrorFormat(rcm);
    return rcm;
  } else if (num > max_threads) {
    rcm = {EC::InvalidArg,
           AMStr::fmt("ThreadNum too large, max is {}, but receive {}",
                      max_threads, num)};
    AMPromptManager::Instance().ErrorFormat(rcm);
    return rcm;
  }

  const size_t applied = worker_->ThreadCount(static_cast<size_t>(num));
  AMPromptManager::Instance().FmtPrint("Set ThreadNum to : {}", applied);
  return rcm;
}

/**
 * @brief Inspect a single task entry by entry ID.
 */
ECM AMDomain::transfer::AMTransferManager::QuerySetEntry(const ID &entry_id) const {
  ID task_id;
  size_t entry_index = 0;
  if (!ParseEntryId_(entry_id, &task_id, &entry_index)) {
    return {EC::InvalidArg,
            "Entry ID format invalid (expected <task_id>:<index>)"};
  }

  auto task_info = FindTaskById_(task_id);
  if (!task_info || !task_info->tasks) {
    return {EC::InvalidArg, AMStr::fmt("Task not found: {}", task_id)};
  }

  if (entry_index == 0 || entry_index > task_info->tasks->size()) {
    return {EC::InvalidArg,
            AMStr::fmt("Entry index out of range: {}", entry_index)};
  }

  const auto &task = task_info->tasks->at(entry_index - 1);
  PrintTaskEntry_(AMPromptManager::Instance(), task, entry_index);
  return {EC::Success, ""};
}

/**
 * @brief Terminate a running task by ID.
 */
ECM AMDomain::transfer::AMTransferManager::Terminate(const ID &task_id, int timeout_ms) {
  auto result = worker_->Terminate(task_id, timeout_ms);
  if (!result.first) {
    if (result.second.first != EC::Success) {
      if (result.second.second.empty()) {
        AMPromptManager::Instance().ErrorFormat(result.second);
      } else {
        AMPromptManager::Instance().ErrorFormat(result.second);
      }
    }
    return result.second;
  }
  if (result.second.first != EC::Success) {
    AMPromptManager::Instance().ErrorFormat(result.second);
    return result.second;
  } else if (!result.second.second.empty()) {
    AMPromptManager::Instance().Print(result.second.second);
  }
  return result.second;
}

/**
 * @brief Pause a running task by ID.
 */
ECM AMDomain::transfer::AMTransferManager::Pause(const ID &task_id) {
  std::vector<ID> ids;
  ids.reserve(2);
  std::string token;
  bool has_sep = false;
  for (const char ch : task_id) {
    if (ch == ',' || ch == ';' ||
        std::isspace(static_cast<unsigned char>(ch))) {
      has_sep = true;
      if (!token.empty()) {
        ids.push_back(token);
        token.clear();
      }
      continue;
    }
    token.push_back(ch);
  }
  if (!token.empty()) {
    ids.push_back(token);
  }
  if (has_sep && ids.size() > 1) {
    return Pause(ids);
  }

  const ID &single_id = ids.empty() ? task_id : ids.front();
  ECM rcm = worker_->Pause(single_id);
  if (rcm.first != EC::Success) {
    if (rcm.second.empty()) {
      AMPromptManager::Instance().ErrorFormat(rcm);
    } else if (!rcm.second.empty()) {
      AMPromptManager::Instance().Print(rcm.second);
    }
  }
  return rcm;
}

/**
 * @brief Resume a paused task by ID.
 */
ECM AMDomain::transfer::AMTransferManager::Resume(const ID &task_id) {
  std::vector<ID> ids;
  ids.reserve(2);
  std::string token;
  bool has_sep = false;
  for (const char ch : task_id) {
    if (ch == ',' || ch == ';' ||
        std::isspace(static_cast<unsigned char>(ch))) {
      has_sep = true;
      if (!token.empty()) {
        ids.push_back(token);
        token.clear();
      }
      continue;
    }
    token.push_back(ch);
  }
  if (!token.empty()) {
    ids.push_back(token);
  }
  if (has_sep && ids.size() > 1) {
    return Resume(ids);
  }

  const ID &single_id = ids.empty() ? task_id : ids.front();
  ECM rcm = worker_->Resume(single_id);
  if (rcm.first != EC::Success) {
    if (rcm.second.empty()) {
      AMPromptManager::Instance().ErrorFormat(rcm);
    } else if (!rcm.second.empty()) {
      AMPromptManager::Instance().Print(rcm.second);
    }
  }
  return rcm;
}

/**
 * @brief Terminate tasks in batch by IDs.
 */
ECM AMDomain::transfer::AMTransferManager::Terminate(const std::vector<ID> &task_ids,
                                 int timeout_ms) {
  ECM last = {EC::Success, ""};
  ECM rcm = {EC::Success, ""};
  std::unordered_set<ID> seen;
  seen.reserve(task_ids.size());
  for (const auto &id : task_ids) {
    if (id.empty()) {
      continue;
    }
    if (!seen.insert(id).second) {
      continue;
    }
    rcm = Terminate(id, timeout_ms);
    if (rcm.first != EC::Success) {
      last = rcm;
    }
  }
  return last;
}

/**
 * @brief Pause tasks in batch by IDs.
 */
ECM AMDomain::transfer::AMTransferManager::Pause(const std::vector<ID> &task_ids) {
  ECM last = {EC::Success, ""};
  ECM rcm = {EC::Success, ""};
  std::unordered_set<ID> seen;
  seen.reserve(task_ids.size());
  for (const auto &id : task_ids) {
    if (id.empty()) {
      continue;
    }
    if (!seen.insert(id).second) {
      continue;
    }
    rcm = Pause(id);
    if (rcm.first != EC::Success) {
      last = rcm;
    }
  }
  return last;
}

/**
 * @brief Resume tasks in batch by IDs.
 */
ECM AMDomain::transfer::AMTransferManager::Resume(const std::vector<ID> &task_ids) {
  ECM last = {EC::Success, ""};
  ECM rcm = {EC::Success, ""};
  std::unordered_set<ID> seen;
  seen.reserve(task_ids.size());
  for (const auto &id : task_ids) {
    if (id.empty()) {
      continue;
    }
    if (!seen.insert(id).second) {
      continue;
    }
    rcm = Resume(id);
    if (rcm.first != EC::Success) {
      last = rcm;
    }
  }
  return last;
}

/**
 * @brief Retry a completed task by rebuilding failed entries.
 */
ECM AMDomain::transfer::AMTransferManager::retry(const ID &task_id, bool is_async, bool quiet,
                             const std::vector<int> &indices) {

  auto original = FindTaskById_(task_id);
  if (!original || !original->tasks) {
    ECM rcm = {EC::TaskNotFound, AMStr::fmt("Task not found: {}", task_id)};
    AMPromptManager::Instance().ErrorFormat(rcm);
    return rcm;
  }

  const TaskStatus status = original->GetStatus();
  if (status != TaskStatus::Finished) {
    const std::string status_name = std::string(magic_enum::enum_name(status));
    ECM rcm = {EC::InvalidArg, AMStr::fmt("Task not finished: {} (status {})",
                                          task_id, status_name)};
    AMPromptManager::Instance().ErrorFormat(rcm);
    return rcm;
  }

  const size_t total_tasks = original->tasks->size();
  std::vector<size_t> selected_indices;
  std::vector<int> invalid_indices;

  if (!indices.empty()) {
    std::unordered_set<size_t> seen;
    selected_indices.reserve(indices.size());
    for (int idx : indices) {
      if (idx <= 0 || static_cast<size_t>(idx) > total_tasks) {
        invalid_indices.push_back(idx);
        continue;
      }
      size_t pos = static_cast<size_t>(idx - 1);
      if (seen.insert(pos).second) {
        selected_indices.push_back(pos);
      }
    }
    if (!invalid_indices.empty()) {
      std::vector<std::string> invalid_text;
      invalid_text.reserve(invalid_indices.size());
      for (int idx : invalid_indices) {
        invalid_text.push_back(std::to_string(idx));
      }
      AMPromptManager::Instance().FmtPrint(
          "Warning: invalid retry indices ignored: {}",
          AMStr::join(invalid_text, ", "));
    }
    if (selected_indices.empty()) {
      ECM rcm = {EC::InvalidArg, "No valid task indices to retry"};
      AMPromptManager::Instance().ErrorFormat(rcm);
      return {EC::InvalidArg, "No valid task indices to retry"};
    }
  }

  auto tasks_ptr = std::make_shared<TASKS>();
  auto append_task = [&](const TransferTask &task) {
    if (task.rcm.first == EC::Success) {
      return;
    }
    TransferTask copy = task;
    copy.IsFinished = false;
    copy.rcm = {EC::Success, ""};
    tasks_ptr->push_back(std::move(copy));
  };

  if (indices.empty()) {
    tasks_ptr->reserve(total_tasks);
    for (const auto &task : *original->tasks) {
      append_task(task);
    }
  } else {
    tasks_ptr->reserve(selected_indices.size());
    for (size_t idx : selected_indices) {
      append_task(original->tasks->at(idx));
    }
  }

  if (tasks_ptr->empty()) {
    AMPromptManager::Instance().Print(
        "retry: all selected tasks already succeeded");
    return {EC::Success, ""};
  }

  std::vector<std::string> nickname_list;
  std::unordered_set<std::string> nickname_seen;
  bool local_used = false;
  auto record_nickname = [&](const std::string &name) {
    if (name.empty() || name == "local") {
      local_used = true;
      return;
    }
    if (nickname_seen.insert(name).second) {
      nickname_list.push_back(name);
    }
  };
  for (const auto &task : *tasks_ptr) {
    record_nickname(task.src_host);
    record_nickname(task.dst_host);
  }

  std::vector<std::string> display_names = nickname_list;
  if (local_used || display_names.empty()) {
    display_names.push_back("local");
  }

  auto [host_rcm, hostm] = CollectClients(nickname_list, nullptr);
  if (host_rcm.first != EC::Success || !hostm) {
    AMPromptManager::Instance().ErrorFormat(host_rcm);
    return host_rcm;
  }

  const ssize_t buffer_size =
      original->buffer_size.load(std::memory_order_relaxed);
  const int affinity_thread =
      original->affinity_thread.load(std::memory_order_relaxed);
  auto task_info = worker_->CreateTaskInfo(tasks_ptr, hostm, original->callback,
                                        buffer_size, quiet, affinity_thread);
  if (original->transfer_sets) {
    task_info->transfer_sets = original->transfer_sets;
  }
  task_info->nicknames = std::move(display_names);

  if (is_async) {
    return transfer_async(task_info);
  }
  return transfer(task_info);
}








