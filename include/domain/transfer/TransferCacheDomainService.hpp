#pragma once
#include "foundation/DataClass.hpp"
#include <optional>
#include <unordered_set>
#include <vector>

namespace AMDomain::transfer {
/**
 * @brief Pure domain service for cached transfer-set bookkeeping.
 */
class TransferCacheDomainService {
public:
  using Cache = std::vector<std::optional<UserTransferSet>>;

  /**
   * @brief Append one transfer set and return new cache index.
   */
  size_t SubmitTransferSet(Cache *cache, const UserTransferSet &transfer_set) const;

  /**
   * @brief Append multiple transfer sets and return their cache indices.
   */
  std::vector<size_t>
  SubmitTransferSets(Cache *cache,
                     const std::vector<UserTransferSet> &transfer_sets) const;

  /**
   * @brief Query one cached transfer set by index.
   */
  ECM QueryTransferSet(const Cache &cache, size_t set_index,
                       UserTransferSet *out_set) const;

  /**
   * @brief Return valid cache indices.
   */
  std::vector<size_t> ListTransferSetIds(const Cache &cache) const;

  /**
   * @brief Delete cached transfer sets by indices.
   *
   * @param cache Cache storage to mutate.
   * @param set_indices Requested indices (duplicates allowed).
   * @param warnings Optional warnings for invalid/already-deleted indices.
   * @return Number of entries that transitioned from valid to deleted.
   */
  size_t DeleteTransferSets(Cache *cache, const std::vector<size_t> &set_indices,
                            std::vector<ECM> *warnings = nullptr) const;

  /**
   * @brief Clear cache.
   */
  void Clear(Cache *cache) const;

  /**
   * @brief Snapshot all valid cached transfer sets.
   */
  std::vector<UserTransferSet> SnapshotValidSets(const Cache &cache) const;
};
} // namespace AMDomain::transfer
