#include "domain/transfer/TransferDomainService.hpp"
#include "foundation/tools/string.hpp"

namespace AMDomain::transfer {
size_t CacheService::AddTransferSet(Cache *cache,
                                    const UserTransferSet &transfer_set) {
  if (!cache) {
    return 0;
  }
  cache->emplace_back(transfer_set);
  return cache->size() - 1;
}

ECM CacheService::QueryTransferSet(const Cache &cache, size_t set_index,
                                   UserTransferSet *out_set) {
  if (!out_set) {
    return {EC::InvalidArg, "Output receiver is nullptr"};
  }
  if (set_index >= cache.size()) {
    if (cache.empty()) {
      return {EC::IndexOutOfRange, "cache is empty"};
    }
    return {EC::IndexOutOfRange, AMStr::fmt("index {} out of range [0, {}]",
                                            set_index, cache.size() - 1)};
  }
  const auto &entry = cache[set_index];
  if (!entry.has_value()) {
    return {EC::TaskNotFound,
            AMStr::fmt("index {} is already deleted", set_index)};
  }
  *out_set = *entry;
  return {EC::Success, ""};
}

std::vector<size_t> CacheService::ListTransferSetIds(const Cache &cache) {
  std::vector<size_t> indices;
  indices.reserve(cache.size());
  for (size_t i = 0; i < cache.size(); ++i) {
    if (cache[i].has_value()) {
      indices.push_back(i);
    }
  }
  return indices;
}

size_t CacheService::DeleteTransferSet(Cache *cache, size_t set_index,
                                       ECM *warning) {
  if (!cache) {
    return 0;
  }

  if (set_index >= cache->size()) {
    if (warning) {
      if (cache->empty()) {
        *warning = {
            EC::IndexOutOfRange,
            AMStr::fmt("index {} out of range: cache is empty", set_index)};
      } else {
        *warning = {EC::IndexOutOfRange,
                    AMStr::fmt("index {} out of range [0, {}]", set_index,
                               cache->size() - 1)};
      }
    }
    return 0;
  }
  if (!(*cache)[set_index].has_value()) {
    if (warning) {
      *warning = {EC::TaskNotFound,
                  AMStr::fmt("index {} is already deleted", set_index)};
    }
    return 0;
  }
  (*cache)[set_index].reset();
  return 1;
}

void CacheService::Clear(Cache *cache) {
  if (!cache) {
    return;
  }
  cache->clear();
}

std::vector<UserTransferSet>
CacheService::SnapshotValidSets(const Cache &cache) {
  std::vector<UserTransferSet> transfer_sets;
  transfer_sets.reserve(cache.size());
  for (const auto &entry : cache) {
    if (entry.has_value()) {
      transfer_sets.push_back(*entry);
    }
  }
  return transfer_sets;
}

sptr<TaskInfo> TaskService::GetHistoryTask(const TaskHistory &history,
                                           const TaskInfo::ID &task_id) {
  auto it = history.find(task_id);
  if (it == history.end()) {
    return nullptr;
  }
  return it->second;
}

std::vector<TaskInfo::ID>
TaskService::GetHistoryIDs(const TaskHistory &history) {
  std::vector<TaskInfo::ID> ids = {};
  ids.reserve(history.size());
  for (const auto &[task_id, task_info] : history) {
    (void)task_info;
    ids.push_back(task_id);
  }
  return ids;
}
} // namespace AMDomain::transfer
