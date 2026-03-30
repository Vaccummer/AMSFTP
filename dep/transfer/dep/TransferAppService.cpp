#include "application/transfer/TransferAppService.hpp"
#include "TransferBackendPort.hpp"
#include "application/client/ClientAppService.hpp"
#include "application/filesystem/FilesystemAppService.hpp"
#include "domain/client/ClientDomainService.hpp"
#include "domain/host/HostDomainService.hpp"
#include "foundation/tools/enum_related.hpp"
#include <sstream>
#include <unordered_set>
#include <utility>

namespace AMApplication::TransferWorkflow {
namespace {
using amf = AMDomain::client::amf;

/**
 * @brief Build a unique key for transfer-task deduplication.
 */
std::string BuildTaskKey_(const TransferTask &task) {
  std::ostringstream oss;
  oss << task.src_host << '\t' << task.src << '\t' << task.dst_host << '\t'
      << task.dst << '\t' << static_cast<int>(task.path_type);
  return oss.str();
}

/**
 * @brief Remove duplicate tasks while preserving original order.
 */
void DeduplicateTasks_(TASKS *tasks) {
  if (!tasks || tasks->empty()) {
    return;
  }
  std::unordered_set<std::string> seen = {};
  seen.reserve(tasks->size());
  TASKS unique = {};
  unique.reserve(tasks->size());
  for (const auto &task : *tasks) {
    const std::string key = BuildTaskKey_(task);
    if (seen.insert(key).second) {
      unique.push_back(task);
    }
  }
  tasks->swap(unique);
}

/**
 * @brief Detect wildcard path syntax.
 */
bool HasWildcard_(const std::string &path) {
  return path.find('*') != std::string::npos ||
         (path.find('<') != std::string::npos &&
          path.find('>') != std::string::npos);
}

/**
 * @brief Normalize nickname using domain client naming policy.
 */
std::string NormalizeNickname_(const std::string &nickname) {
  return AMDomain::client::ClientDomainService::NormalizeNickname(nickname);
}

/**
 * @brief Ensure one endpoint nickname has a ready client handle.
 */
std::pair<ECM, AMDomain::client::ClientHandle>
ResolveReadyClient_(AMApplication::client::ClientAppService &client_service,
                    const std::string &nickname, amf control_token,
                    int timeout_ms, int64_t start_time) {
  (void)start_time;
  if (control_token && control_token->IsInterrupted()) {
    return {Err(EC::Terminate, "Interrupted during client preparation"),
            nullptr};
  }
  const AMDomain::client::ClientControlComponent control =
      AMDomain::client::MakeClientControlComponent(control_token);

  const std::string normalized = NormalizeNickname_(nickname);
  if (AMDomain::host::HostManagerService::IsLocalNickname(normalized)) {
    auto client = client_service.GetLocalClient();
    if (!client) {
      return {Err(EC::ClientNotFound, "Local client not found"), nullptr};
    }
    const auto check_result =
        client_service.CheckClient("local", false, false, control, timeout_ms);
    if (!isok(check_result.rcm)) {
      return {check_result.rcm, client};
    }
    return {Ok(), client};
  }

  auto [ensure_rcm, ensured_client] =
      client_service.EnsureClient(normalized, control, timeout_ms);
  if (!isok(ensure_rcm) || !ensured_client) {
    return {ensure_rcm, ensured_client};
  }

  const auto check_result =
      client_service.CheckClient(normalized, false, false, control, timeout_ms);
  if (!isok(check_result.rcm)) {
    return {check_result.rcm, ensured_client};
  }
  return {Ok(), ensured_client};
}

/**
 * @brief Build task summary DTO from one task info snapshot.
 */
TaskSummaryView
BuildTaskSummaryView_(const std::shared_ptr<TaskInfo> &task_info) {
  TaskSummaryView view = {};
  if (!task_info) {
    return view;
  }
  view.id = task_info->id;
  view.status = task_info->GetStatus();
  view.result = task_info->GetResult();
  view.success_filenum =
      task_info->success_filenum.load(std::memory_order_relaxed);
  view.filenum = task_info->filenum.load(std::memory_order_relaxed);
  view.total_transferred_size =
      task_info->total_transferred_size.load(std::memory_order_relaxed);
  view.total_size = task_info->total_size.load(std::memory_order_relaxed);
  view.submit_time = task_info->submit_time.load(std::memory_order_relaxed);
  view.start_time = task_info->start_time.load(std::memory_order_relaxed);
  view.finished_time = task_info->finished_time.load(std::memory_order_relaxed);
  view.running_thread =
      task_info->OnWhichThread.load(std::memory_order_relaxed);
  return view;
}

/**
 * @brief Build task-entry DTO from one transfer task item.
 */
TaskEntryView BuildTaskEntryView_(const TransferTask &task_entry,
                                  size_t index) {
  TaskEntryView view = {};
  view.index = index;
  view.path_type = task_entry.path_type;
  view.src_host = task_entry.src_host;
  view.src = task_entry.src;
  view.dst_host = task_entry.dst_host;
  view.dst = task_entry.dst;
  view.size = task_entry.size;
  view.transferred = task_entry.transferred;
  view.result = task_entry.rcm;
  return view;
}

/**
 * @brief Convert transfer scoped path model into canonical client path.
 */
AMDomain::filesystem::ClientPath
ToClientPath_(const AMDomain::client::ScopedPath &endpoint) {
  AMDomain::filesystem::ClientPath out = {};
  out.nickname = endpoint.nickname;
  out.path = endpoint.path;
  return out;
}

/**
 * @brief Build transfer-set DTO from user transfer-set data.
 */
TransferSetView BuildTransferSetView_(const UserTransferSet &set,
                                      size_t index) {
  TransferSetView view = {};
  view.index = index;
  view.srcs.reserve(set.srcs.size());
  for (const auto &src : set.srcs) {
    view.srcs.push_back(ToClientPath_(src));
  }
  view.dst = ToClientPath_(set.dst);
  view.clone = set.clone;
  view.mkdir = set.mkdir;
  view.overwrite = set.overwrite;
  view.ignore_special_file = set.ignore_special_file;
  view.resume = set.resume;
  return view;
}
} // namespace

/**
 * @brief Construct service with an internally created default backend.
 */
TransferAppService::TransferAppService(
    AMApplication::client::ClientAppService &client_service,
    std::shared_ptr<AMApplication::TransferRuntime::ITransferClientPoolPort>
        transfer_pool,
    std::shared_ptr<AMApplication::filesystem::FilesystemAppService>
        filesystem_service)
    : TransferAppService(
          AMApplication::TransferRuntime::CreateDefaultTransferBackend(
              {}, [transfer_pool]() { return transfer_pool; }),
          client_service, std::move(transfer_pool),
          std::move(filesystem_service)) {}

/**
 * @brief Construct service from transfer backend port.
 */
TransferAppService::TransferAppService(
    std::shared_ptr<AMApplication::TransferRuntime::ITransferBackendPort>
        backend,
    AMApplication::client::ClientAppService &client_service,
    std::shared_ptr<AMApplication::TransferRuntime::ITransferClientPoolPort>
        transfer_pool,
    std::shared_ptr<AMApplication::filesystem::FilesystemAppService>
        filesystem_service)
    : backend_(std::move(backend)), client_service_(&client_service),
      filesystem_service_(std::move(filesystem_service)),
      transfer_pool_(std::move(transfer_pool)) {}

/**
 * @brief Initialize the underlying transfer runtime.
 */
TransferAppService::ECM TransferAppService::Init() {
  if (!backend_) {
    return {EC::InvalidHandle, "Transfer backend is unavailable"};
  }
  return backend_->Init();
}

/**
 * @brief Execute transfer sets synchronously.
 */
TransferAppService::ECM
TransferAppService::Transfer(const std::vector<UserTransferSet> &transfer_sets,
                             bool quiet) {
  return TransferWithControl(transfer_sets, quiet, nullptr,
                             TransferConfirmPolicy::AutoApprove, {}, nullptr);
}

/**
 * @brief Execute transfer sets synchronously with explicit control context.
 */
TransferAppService::ECM TransferAppService::TransferWithControl(
    const std::vector<UserTransferSet> &transfer_sets, bool quiet,
    amf control_token, TransferConfirmPolicy confirm_policy,
    const WildcardConfirmFn &confirm_wildcard, std::vector<ECM> *warnings) {
  bool has_resume = false;
  for (const auto &set : transfer_sets) {
    if (!set.resume) {
      continue;
    }
    has_resume = true;
    if (set.srcs.size() != 1 || set.dst.path.empty()) {
      return {EC::InvalidArg,
              "Resume transfer requires exactly one src and one dst"};
    }
  }
  if (has_resume && transfer_sets.size() != 1) {
    return {EC::InvalidArg, "Resume transfer requires a single transfer set"};
  }

  std::vector<WildcardConfirmRequest> confirm_requests = {};
  auto [rcm, task_info] = PrepareTasks_(transfer_sets, quiet, control_token,
                                        &confirm_requests, warnings);
  if (rcm.first != EC::Success) {
    return rcm;
  }
  if (!task_info) {
    return {EC::Success, ""};
  }
  rcm = ResolveWildcardConfirm_(confirm_requests, confirm_policy,
                                confirm_wildcard);
  if (rcm.first != EC::Success) {
    return rcm;
  }
  if (!backend_) {
    return {EC::InvalidHandle, "Transfer backend is unavailable"};
  }
  return backend_->TransferTaskSync(task_info, std::move(control_token));
}

/**
 * @brief Execute transfer sets asynchronously.
 */
TransferAppService::ECM TransferAppService::TransferAsync(
    const std::vector<UserTransferSet> &transfer_sets, bool quiet) {
  return TransferAsyncWithControl(transfer_sets, quiet, nullptr,
                                  TransferConfirmPolicy::AutoApprove, {},
                                  nullptr);
}

/**
 * @brief Execute transfer sets asynchronously with explicit control context.
 */
TransferAppService::ECM TransferAppService::TransferAsyncWithControl(
    const std::vector<UserTransferSet> &transfer_sets, bool quiet,
    amf control_token, TransferConfirmPolicy confirm_policy,
    const WildcardConfirmFn &confirm_wildcard, std::vector<ECM> *warnings) {
  bool has_resume = false;
  for (const auto &set : transfer_sets) {
    if (!set.resume) {
      continue;
    }
    has_resume = true;
    if (set.srcs.size() != 1 || set.dst.path.empty()) {
      return {EC::InvalidArg,
              "Resume transfer requires exactly one src and one dst"};
    }
  }
  if (has_resume && transfer_sets.size() != 1) {
    return {EC::InvalidArg, "Resume transfer requires a single transfer set"};
  }

  std::vector<WildcardConfirmRequest> confirm_requests = {};
  auto [rcm, task_info] = PrepareTasks_(transfer_sets, quiet, control_token,
                                        &confirm_requests, warnings);
  if (rcm.first != EC::Success) {
    return rcm;
  }
  if (!task_info) {
    return {EC::Success, ""};
  }
  rcm = ResolveWildcardConfirm_(confirm_requests, confirm_policy,
                                confirm_wildcard);
  if (rcm.first != EC::Success) {
    return rcm;
  }
  if (!backend_) {
    return {EC::InvalidHandle, "Transfer backend is unavailable"};
  }
  return backend_->TransferTaskAsync(task_info, std::move(control_token));
}

/**
 * @brief Prepare pooled task info from user transfer sets.
 */
std::pair<TransferAppService::ECM, std::shared_ptr<TaskInfo>>
TransferAppService::PrepareTasks_(
    const std::vector<UserTransferSet> &transfer_sets, bool quiet, amf flag,
    std::vector<WildcardConfirmRequest> *confirm_requests,
    std::vector<ECM> *warnings) {
  if (transfer_sets.empty()) {
    return {ECM{EC::Success, ""}, nullptr};
  }

  if (!client_service_) {
    return {ECM{EC::InvalidHandle, "Transfer client app service is not bound"},
            nullptr};
  }
  if (!transfer_pool_) {
    return {ECM{EC::InvalidHandle, "Transfer client pool is unavailable"},
            nullptr};
  }
  if (!filesystem_service_) {
    return {ECM{EC::InvalidHandle, "Filesystem app service is unavailable"},
            nullptr};
  }

  std::vector<std::string> display_names = {};
  std::unordered_set<std::string> nickname_seen = {};
  bool local_used = false;
  auto record_nickname = [&](const std::string &nickname) {
    if (nickname.empty()) {
      return;
    }
    if (AMDomain::host::HostManagerService::IsLocalNickname(nickname)) {
      local_used = true;
      return;
    }
    if (nickname_seen.insert(nickname).second) {
      display_names.push_back(nickname);
    }
  };

  auto tasks_ptr = std::make_shared<TASKS>();
  for (const auto &set : transfer_sets) {
    if (flag && flag->IsInterrupted()) {
      return {ECM{EC::Terminate, "Interrupted before task generation"}, nullptr};
    }

    const AMDomain::client::ClientControlComponent control =
        AMDomain::client::MakeClientControlComponent(flag, 10000);
    AMDomain::transfer::TransferClientContainer task_clients = {};

    auto dst_result = filesystem_service_->ResolveTransferDst(set.dst, control);
    if (!isok(dst_result.rcm) || !dst_result.data.client) {
      return {dst_result.rcm, nullptr};
    }
    const auto &dst_transfer = dst_result.data;
    const std::string dst_host = dst_transfer.target.nickname;
    record_nickname(dst_host);

    auto src_result =
        filesystem_service_->ResolveTransferSrc(set.srcs, &task_clients, control,
                                                false);
    if (!isok(src_result.rcm) && warnings) {
      warnings->push_back(src_result.rcm);
    }
    for (const auto &[nickname, error_path] : src_result.data.error_data) {
      (void)nickname;
      if (warnings) {
        warnings->push_back(error_path.rcm);
      }
    }

    const bool has_wildcard =
        std::any_of(set.srcs.begin(), set.srcs.end(), [](const auto &src_path) {
          return src_path.is_wildcard || HasWildcard_(src_path.path);
        });
    if (has_wildcard && confirm_requests) {
      for (const auto &[src_host, transfer_path] : src_result.data.data) {
        if (transfer_path.raw_paths.empty()) {
          continue;
        }
        WildcardConfirmRequest request = {};
        request.matches = transfer_path.raw_paths;
        request.src_host = src_host;
        request.dst_host = dst_host;
        confirm_requests->push_back(std::move(request));
      }
    }

    for (const auto &[src_host, transfer_path] : src_result.data.data) {
      (void)transfer_path;
      record_nickname(src_host);
    }

    AMApplication::filesystem::BuildTransferTaskOptions build_opt = {};
    build_opt.clone = set.clone;
    build_opt.mkdir = set.mkdir;
    build_opt.ignore_special_file = set.ignore_special_file;
    build_opt.resume = set.resume;

    auto build_result = filesystem_service_->BuildTransferTasks(
        src_result.data, dst_transfer, control, build_opt);
    if (!isok(build_result.rcm)) {
      if (warnings) {
        warnings->push_back(build_result.rcm);
      }
      if (build_result.rcm.first == EC::Terminate ||
          build_result.rcm.first == EC::OperationTimeout) {
        return {build_result.rcm, nullptr};
      }
    }
    for (const auto &warn : build_result.data.warnings) {
      if (warnings) {
        warnings->push_back(warn.rcm);
      }
    }
    tasks_ptr->insert(tasks_ptr->end(), build_result.data.dir_tasks.begin(),
                      build_result.data.dir_tasks.end());
    tasks_ptr->insert(tasks_ptr->end(), build_result.data.file_tasks.begin(),
                      build_result.data.file_tasks.end());
  }

  if (local_used) {
    display_names.emplace_back("local");
  }

  DeduplicateTasks_(tasks_ptr.get());
  if (tasks_ptr->empty()) {
    return {ECM{EC::Success, ""}, nullptr};
  }

  if (!backend_) {
    return {ECM{EC::InvalidHandle, "Transfer backend is unavailable"}, nullptr};
  }
  auto task_info = backend_->CreateTaskInfo(tasks_ptr, transfer_pool_,
                                            TransferCallback(), -1, quiet, -1);
  if (!task_info) {
    return {ECM{EC::InvalidHandle, "Transfer worker backend is unavailable"},
            nullptr};
  }
  task_info->transfer_sets =
      std::make_shared<std::vector<UserTransferSet>>(std::move(transfer_sets));
  task_info->nicknames = std::move(display_names);
  return {ECM{EC::Success, ""}, task_info};
}

/**
 * @brief Apply explicit wildcard confirm policy on pre-confirm requests.
 */
TransferAppService::ECM TransferAppService::ResolveWildcardConfirm_(
    const std::vector<WildcardConfirmRequest> &confirm_requests,
    TransferConfirmPolicy confirm_policy,
    const WildcardConfirmFn &confirm_wildcard) const {
  if (confirm_requests.empty()) {
    return Ok();
  }
  switch (confirm_policy) {
  case TransferConfirmPolicy::AutoApprove:
    return Ok();
  case TransferConfirmPolicy::DenyIfConfirmNeeded:
    return Err(EC::OperationUnsupported,
               "Transfer confirmation required but denied by policy");
  case TransferConfirmPolicy::RequireConfirm:
    if (!confirm_wildcard) {
      return Err(EC::OperationUnsupported,
                 "Transfer confirmation callback is required by policy");
    }
    for (const auto &request : confirm_requests) {
      if (request.matches.empty()) {
        continue;
      }
      if (!confirm_wildcard(request.matches, request.src_host,
                            request.dst_host)) {
        return Err(EC::Terminate, "Wildcard transfer canceled by user");
      }
    }
    return Ok();
  default:
    break;
  }
  return Err(EC::InvalidArg, "Unknown transfer confirm policy");
}

/**
 * @brief Return tracked transfer task identifiers.
 */
std::vector<TransferAppService::ID> TransferAppService::ListTaskIds() const {
  if (!backend_) {
    return {};
  }
  return backend_->ListTaskIds();
}

/**
 * @brief Return task summaries for interface read/query flows.
 */
TransferAppService::ECM TransferAppService::ListTaskSummaries(
    std::vector<TaskSummaryView> *out_summaries) const {
  if (!out_summaries) {
    return Err(EC::InvalidArg, "null task summary output");
  }
  out_summaries->clear();
  for (const auto &task_id : ListTaskIds()) {
    auto task_info = FindTask(task_id);
    if (!task_info) {
      continue;
    }
    out_summaries->push_back(BuildTaskSummaryView_(task_info));
  }
  return Ok();
}

/**
 * @brief Return one task detail view.
 */
TransferAppService::ECM
TransferAppService::GetTaskView(const ID &task_id, bool include_sets,
                                bool include_entries,
                                TaskView *out_view) const {
  if (!out_view) {
    return Err(EC::InvalidArg, "null task view output");
  }
  auto task_info = FindTask(task_id);
  if (!task_info) {
    return Err(EC::TaskNotFound, AMStr::fmt("Task not found: {}", task_id));
  }
  out_view->summary = BuildTaskSummaryView_(task_info);
  out_view->entries.clear();
  out_view->transfer_sets.clear();

  if (include_entries && task_info->tasks) {
    out_view->entries.reserve(task_info->tasks->size());
    size_t index = 1;
    for (const auto &entry : *(task_info->tasks)) {
      out_view->entries.push_back(BuildTaskEntryView_(entry, index));
      ++index;
    }
  }
  if (include_sets && task_info->transfer_sets) {
    out_view->transfer_sets.reserve(task_info->transfer_sets->size());
    size_t index = 1;
    for (const auto &set : *(task_info->transfer_sets)) {
      out_view->transfer_sets.push_back(BuildTransferSetView_(set, index));
      ++index;
    }
  }
  return Ok();
}

/**
 * @brief Resolve one task by identifier.
 */
std::shared_ptr<TaskInfo>
TransferAppService::FindTask(const ID &task_id) const {
  if (!backend_) {
    return nullptr;
  }
  return backend_->FindTask(task_id);
}

/**
 * @brief Return counts of pending and conducting tasks.
 */
void TransferAppService::GetTaskCounts(size_t *pending_count,
                                       size_t *conducting_count) const {
  if (!backend_) {
    if (pending_count) {
      *pending_count = 0;
    }
    if (conducting_count) {
      *conducting_count = 0;
    }
    return;
  }
  backend_->GetTaskCounts(pending_count, conducting_count);
}

/**
 * @brief Get or set worker thread count.
 */
TransferAppService::ECM TransferAppService::Thread(int num) {
  if (!backend_) {
    return {EC::InvalidHandle, "Transfer backend is unavailable"};
  }
  return backend_->Thread(num);
}

/**
 * @brief Apply worker thread count without CLI presentation side effects.
 */
TransferAppService::ECM TransferAppService::SetWorkerThreadCount(size_t count) {
  if (!backend_) {
    return {EC::InvalidHandle, "Transfer backend is unavailable"};
  }
  if (count == 0) {
    return {EC::InvalidArg, "Thread count must be >= 1"};
  }
  return backend_->SetWorkerThreadCount(count);
}

/**
 * @brief Terminate tasks by ids.
 */
TransferAppService::ECM
TransferAppService::Terminate(const std::vector<ID> &task_ids, int timeout_ms) {
  if (!backend_) {
    return {EC::InvalidHandle, "Transfer backend is unavailable"};
  }
  return backend_->Terminate(task_ids, timeout_ms);
}

/**
 * @brief Terminate one task by identifier.
 */
TransferAppService::ECM TransferAppService::Terminate(const ID &task_id,
                                                      int timeout_ms) {
  if (!backend_) {
    return {EC::InvalidHandle, "Transfer backend is unavailable"};
  }
  return backend_->Terminate(task_id, timeout_ms);
}

/**
 * @brief Pause tasks by ids.
 */
TransferAppService::ECM
TransferAppService::Pause(const std::vector<ID> &task_ids) {
  if (!backend_) {
    return {EC::InvalidHandle, "Transfer backend is unavailable"};
  }
  return backend_->Pause(task_ids);
}

/**
 * @brief Pause one task by identifier.
 */
TransferAppService::ECM TransferAppService::Pause(const ID &task_id) {
  if (!backend_) {
    return {EC::InvalidHandle, "Transfer backend is unavailable"};
  }
  return backend_->Pause(task_id);
}

/**
 * @brief Resume tasks by ids.
 */
TransferAppService::ECM
TransferAppService::Resume(const std::vector<ID> &task_ids) {
  if (!backend_) {
    return {EC::InvalidHandle, "Transfer backend is unavailable"};
  }
  return backend_->Resume(task_ids);
}

/**
 * @brief Resume one task by identifier.
 */
TransferAppService::ECM TransferAppService::Resume(const ID &task_id) {
  if (!backend_) {
    return {EC::InvalidHandle, "Transfer backend is unavailable"};
  }
  return backend_->Resume(task_id);
}

/**
 * @brief Retry one finished task.
 */
TransferAppService::ECM
TransferAppService::Retry(const ID &task_id, bool is_async, bool quiet,
                          const std::vector<int> &indices) {
  if (!backend_) {
    return {EC::InvalidHandle, "Transfer backend is unavailable"};
  }
  return backend_->Retry(task_id, is_async, quiet, indices);
}

/**
 * @brief Add one transfer set into the cached job list.
 */
size_t
TransferAppService::AddCachedTransferSet(const UserTransferSet &transfer_set) {
  std::lock_guard<std::mutex> lock(cache_mtx_);
  return transfer_cache_domain_service_.AddTransferSet(&cached_sets_,
                                                       transfer_set);
}

/**
 * @brief Remove cached transfer sets by indices.
 */
size_t TransferAppService::RemoveCachedTransferSets(
    const std::vector<size_t> &set_indices) {
  return RemoveCachedTransferSets(set_indices, nullptr);
}

/**
 * @brief Remove cached transfer sets and return warning payloads.
 */
size_t TransferAppService::RemoveCachedTransferSets(
    const std::vector<size_t> &set_indices, std::vector<ECM> *warnings) {
  std::lock_guard<std::mutex> lock(cache_mtx_);
  size_t removed = 0;
  for (size_t set_index : set_indices) {
    ECM warning = {EC::Success, ""};
    const size_t one_removed = transfer_cache_domain_service_.DeleteTransferSet(
        &cached_sets_, set_index, warnings ? &warning : nullptr);
    if (one_removed == 0 && warnings && warning.first != EC::Success) {
      warnings->push_back(std::move(warning));
    }
    removed += one_removed;
  }
  return removed;
}

/**
 * @brief Clear all cached transfer sets.
 */
void TransferAppService::ClearCachedTransferSets() {
  std::lock_guard<std::mutex> lock(cache_mtx_);
  transfer_cache_domain_service_.Clear(&cached_sets_);
}

/**
 * @brief Submit cached transfer sets.
 */
TransferAppService::ECM
TransferAppService::SubmitCachedTransferSets(bool quiet, bool is_async) {
  return SubmitCachedTransferSetsWithControl(quiet, is_async, nullptr,
                                             TransferConfirmPolicy::AutoApprove,
                                             {}, nullptr);
}

/**
 * @brief Submit cached transfer sets with explicit control and confirm policy.
 */
TransferAppService::ECM TransferAppService::SubmitCachedTransferSetsWithControl(
    bool quiet, bool is_async, amf control_token,
    TransferConfirmPolicy confirm_policy,
    const WildcardConfirmFn &confirm_wildcard, std::vector<ECM> *warnings) {
  auto transfer_sets = SnapshotCachedTransferSets();
  if (transfer_sets.empty()) {
    return {EC::InvalidArg, "Cached transfer set is empty"};
  }
  ECM rcm =
      is_async
          ? TransferAsyncWithControl(transfer_sets, quiet,
                                     std::move(control_token), confirm_policy,
                                     confirm_wildcard, warnings)
          : TransferWithControl(transfer_sets, quiet, std::move(control_token),
                                confirm_policy, confirm_wildcard, warnings);
  if (rcm.first == EC::Success) {
    ClearCachedTransferSets();
  }
  return rcm;
}

/**
 * @brief Query one cached transfer set.
 */
TransferAppService::ECM
TransferAppService::QueryCachedTransferSet(size_t set_index) const {
  return GetCachedTransferSet(set_index, nullptr);
}

/**
 * @brief Query one cached transfer set into output payload.
 */
TransferAppService::ECM
TransferAppService::GetCachedTransferSet(size_t set_index,
                                         UserTransferSet *out_set) const {
  std::lock_guard<std::mutex> lock(cache_mtx_);
  UserTransferSet tmp = {};
  ECM rcm = transfer_cache_domain_service_.QueryTransferSet(cached_sets_,
                                                            set_index, &tmp);
  if (!isok(rcm)) {
    return rcm;
  }
  if (out_set) {
    *out_set = std::move(tmp);
  }
  return Ok();
}

/**
 * @brief Query one cached transfer set into application DTO.
 */
TransferAppService::ECM
TransferAppService::GetCachedTransferSetView(size_t set_index,
                                             TransferSetView *out_view) const {
  if (!out_view) {
    return Err(EC::InvalidArg, "null transfer-set view output");
  }
  UserTransferSet transfer_set = {};
  ECM rcm = GetCachedTransferSet(set_index, &transfer_set);
  if (!isok(rcm)) {
    return rcm;
  }
  *out_view = BuildTransferSetView_(transfer_set, set_index);
  return Ok();
}

/**
 * @brief List cached transfer-set identifiers.
 */
std::vector<size_t> TransferAppService::ListCachedTransferSetIds() const {
  std::lock_guard<std::mutex> lock(cache_mtx_);
  return transfer_cache_domain_service_.ListTransferSetIds(cached_sets_);
}

/**
 * @brief Snapshot all valid cached transfer sets.
 */
std::vector<UserTransferSet>
TransferAppService::SnapshotCachedTransferSets() const {
  std::lock_guard<std::mutex> lock(cache_mtx_);
  return transfer_cache_domain_service_.SnapshotValidSets(cached_sets_);
}

/**
 * @brief Snapshot cached transfer sets in application DTO shape.
 */
std::vector<TransferSetView>
TransferAppService::SnapshotCachedTransferSetViews() const {
  std::lock_guard<std::mutex> lock(cache_mtx_);
  std::vector<TransferSetView> out = {};
  out.reserve(cached_sets_.size());
  for (size_t i = 0; i < cached_sets_.size(); ++i) {
    const auto &entry = cached_sets_[i];
    if (!entry.has_value()) {
      continue;
    }
    out.push_back(BuildTransferSetView_(*entry, i));
  }
  return out;
}
} // namespace AMApplication::TransferWorkflow
