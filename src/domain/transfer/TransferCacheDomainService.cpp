#include "domain/transfer/TransferCacheDomainService.hpp"
#include "foundation/tools/string.hpp"
#include <algorithm>

namespace AMDomain::transfer {
size_t TransferCacheDomainService::SubmitTransferSet(
    Cache *cache, const UserTransferSet &transfer_set) const {
  if (!cache) {
    return 0;
  }
  cache->emplace_back(transfer_set);
  return cache->size() - 1;
}

std::vector<size_t> TransferCacheDomainService::SubmitTransferSets(
    Cache *cache, const std::vector<UserTransferSet> &transfer_sets) const {
  std::vector<size_t> ids;
  if (!cache) {
    return ids;
  }
  ids.reserve(transfer_sets.size());
  for (const auto &set : transfer_sets) {
    cache->emplace_back(set);
    ids.push_back(cache->size() - 1);
  }
  return ids;
}

ECM TransferCacheDomainService::QueryTransferSet(const Cache &cache,
                                                 size_t set_index,
                                                 UserTransferSet *out_set) const {
  if (!out_set) {
    return {EC::InvalidArg, "Output receiver is nullptr"};
  }
  if (set_index >= cache.size()) {
    if (cache.empty()) {
      return {EC::IndexOutOfRange, "cache is empty"};
    }
    return {EC::IndexOutOfRange,
            AMStr::fmt("index {} out of range [0, {}]", set_index,
                       cache.size() - 1)};
  }
  const auto &entry = cache[set_index];
  if (!entry.has_value()) {
    return {EC::TaskNotFound,
            AMStr::fmt("index {} is already deleted", set_index)};
  }
  *out_set = *entry;
  return {EC::Success, ""};
}

std::vector<size_t>
TransferCacheDomainService::ListTransferSetIds(const Cache &cache) const {
  std::vector<size_t> indices;
  indices.reserve(cache.size());
  for (size_t i = 0; i < cache.size(); ++i) {
    if (cache[i].has_value()) {
      indices.push_back(i);
    }
  }
  return indices;
}

size_t TransferCacheDomainService::DeleteTransferSets(
    Cache *cache, const std::vector<size_t> &set_indices,
    std::vector<ECM> *warnings) const {
  if (!cache || set_indices.empty()) {
    return 0;
  }

  std::vector<size_t> unique_indices;
  unique_indices.reserve(set_indices.size());
  std::unordered_set<size_t> seen;
  seen.reserve(set_indices.size());
  for (size_t index : set_indices) {
    if (seen.insert(index).second) {
      unique_indices.push_back(index);
    }
  }

  size_t removed = 0;
  for (size_t index : unique_indices) {
    if (index >= cache->size()) {
      if (warnings) {
        if (cache->empty()) {
          warnings->push_back(
              {EC::IndexOutOfRange,
               AMStr::fmt("index {} out of range: cache is empty", index)});
        } else {
          warnings->push_back(
              {EC::IndexOutOfRange,
               AMStr::fmt("index {} out of range [0, {}]", index,
                          cache->size() - 1)});
        }
      }
      continue;
    }
    if (!(*cache)[index].has_value()) {
      if (warnings) {
        warnings->push_back(
            {EC::TaskNotFound,
             AMStr::fmt("index {} is already deleted", index)});
      }
      continue;
    }
    (*cache)[index].reset();
    ++removed;
  }
  return removed;
}

void TransferCacheDomainService::Clear(Cache *cache) const {
  if (!cache) {
    return;
  }
  cache->clear();
}

std::vector<UserTransferSet>
TransferCacheDomainService::SnapshotValidSets(const Cache &cache) const {
  std::vector<UserTransferSet> transfer_sets;
  transfer_sets.reserve(cache.size());
  for (const auto &entry : cache) {
    if (entry.has_value()) {
      transfer_sets.push_back(*entry);
    }
  }
  return transfer_sets;
}
} // namespace AMDomain::transfer
