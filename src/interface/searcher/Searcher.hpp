#pragma once
#include "foundation/core/DataClass.hpp"
#include "interface/completion/Engine.hpp"
#include <memory>
#include <chrono>
#include <functional>
#include <list>
#include <mutex>
#include <unordered_map>
#include <vector>

namespace AMInterface::completion {
class ICompletionRuntime;
}
namespace AMInterface::searcher {
using AMInterface::completer::AMCompletionArgs;
using AMInterface::completer::AMCompletionCandidate;
using AMInterface::completer::AMCompletionCandidates;
using AMInterface::completer::AMCompletionContext;
using AMInterface::completer::AMCompletionKind;
using AMInterface::completer::AMCompletionSearchEngine;
using AMInterface::completer::AMCompletionTarget;
using AMInterface::completer::AMSearchEngineRegistration;

/**
 * @brief Command and option completion search engine.
 */
class AMCommandSearchEngine : public AMCompletionSearchEngine {
public:
  /**
   * @brief Construct command search engine.
   */
  AMCommandSearchEngine() = default;
  /**
   * @brief Collect command-related candidates.
   */
  AMCompletionCandidates
  CollectCandidates(const AMCompletionContext &ctx) override;

  std::shared_ptr<AMInterface::completer::ICompletionTask>
  CreateTask(const AMCompletionContext &ctx) override;

  /**
   * @brief Sort command-related candidates.
   */
  void SortCandidates(const AMCompletionContext &ctx,
                      std::vector<AMCompletionCandidate> &items) override;

private:
  using CommandNode = AMInterface::parser::CommandNode;

  /**
   * @brief Build styled command/module display text.
   */
  std::string FormatCommandDisplay_(const std::string &name,
                                    const std::string &style_key,
                                    size_t pad_width,
                                    const AMCompletionArgs *args) const;

  /**
   * @brief Parse command path from tokens before cursor.
   */
  void ParseCommandPath_(const AMCompletionContext &ctx, std::string *out_path,
                         const CommandNode **out_node,
                         size_t *out_consumed) const;

};

/**
 * @brief Internal-value completion search engine (vars/hosts/clients/tasks).
 */
class AMInternalSearchEngine : public AMCompletionSearchEngine {
public:
  /**
   * @brief Construct internal-value search engine.
   */
  explicit AMInternalSearchEngine(
      std::shared_ptr<AMInterface::completion::ICompletionRuntime> runtime =
          nullptr)
      : runtime_(std::move(runtime)) {}

  /**
   * @brief Collect internal-value candidates.
   */
  AMCompletionCandidates
  CollectCandidates(const AMCompletionContext &ctx) override;

  std::shared_ptr<AMInterface::completer::ICompletionTask>
  CreateTask(const AMCompletionContext &ctx) override;

  /**
   * @brief Sort internal-value candidates.
   */
  void SortCandidates(const AMCompletionContext &ctx,
                      std::vector<AMCompletionCandidate> &items) override;

private:
  std::shared_ptr<AMInterface::completion::ICompletionRuntime> runtime_ =
      nullptr;
};

/**
 * @brief Path completion search engine with internal cache support.
 */
class AMPathSearchEngine : public AMCompletionSearchEngine {
public:
  /**
   * @brief Construct path search engine.
   */
  explicit AMPathSearchEngine(
      std::shared_ptr<AMInterface::completion::ICompletionRuntime> runtime =
          nullptr)
      : runtime_(std::move(runtime)) {}

  /**
   * @brief Collect path candidates.
   */
  AMCompletionCandidates
  CollectCandidates(const AMCompletionContext &ctx) override;

  std::shared_ptr<AMInterface::completer::ICompletionTask>
  CreateTask(const AMCompletionContext &ctx) override;

  /**
   * @brief Sort path candidates.
   */
  void SortCandidates(const AMCompletionContext &ctx,
                      std::vector<AMCompletionCandidate> &items) override;

  /**
   * @brief Clear internal path cache.
   */
  void ClearCache() override;

  /**
   * @brief Clear cached path entries for a specific nickname.
   */
  void ClearCacheForNickname(const std::string &nickname);

  /**
   * @brief Clear cached path entries for all nicknames.
   */
  void ClearCacheForAll();

  /**
   * @brief Cache status summary for a nickname.
   */
  struct CacheStatus {
    size_t entry_count = 0;
    size_t item_count = 0;
  };

  /**
   * @brief Query cache status for a nickname.
   */
  bool GetCacheStatusForNickname(const std::string &nickname,
                                 CacheStatus *status) const;

  /**
   * @brief Query cache status for all nicknames.
   */
  std::unordered_map<std::string, CacheStatus> GetCacheStatusAll() const;

private:
  /**
   * @brief Cache key for path results.
   */
  struct CacheKey {
    std::string nickname;
    std::string dir;

    /**
     * @brief Compare cache keys.
     */
    bool operator==(const CacheKey &other) const = default;
  };

  /**
   * @brief Cache entry for path results.
   */
  struct CacheEntry {
    std::vector<PathInfo> items;
    std::chrono::steady_clock::time_point timestamp;
  };

  /**
   * @brief Temporary cache entry for one prompt session.
   */
  struct TempCacheEntry {
    std::vector<PathInfo> items;
  };

  /**
   * @brief Parsed path context derived from input token.
   */
  struct PathContext {
    bool valid = false;
    bool remote = false;
    std::string nickname;
    std::string header;
    std::string raw_path;
    std::string dir_raw;
    std::string leaf_prefix;
    std::string base;
    std::string dir_abs;
    char sep = '/';
    bool trailing_sep = false;
  };

  /**
   * @brief Style a path entry for display.
   */
  [[nodiscard]] std::string FormatPathDisplay_(const PathInfo &info,
                                               const std::string &name) const;

  /**
   * @brief Build path context from completion token and mode.
   */
  [[nodiscard]] PathContext BuildPathContext_(const std::string &token_prefix,
                                              bool force_path) const;

  /**
   * @brief Append filtered path candidates from listed items.
   */
  void AppendPathCandidates_(const PathContext &path_ctx,
                             const std::vector<PathInfo> &items,
                             std::vector<AMCompletionCandidate> *out) const;

  /**
   * @brief Lookup path cache entries.
   */
  bool LookupCache_(const CacheKey &key, std::vector<PathInfo> *items);

  /**
   * @brief Lookup temporary path cache entries.
   */
  bool LookupTempCache_(const CacheKey &key, std::vector<PathInfo> *items);

  /**
   * @brief Store path cache entries and prune old entries.
   */
  void StoreCache_(const CacheKey &key, const std::vector<PathInfo> &items,
                   size_t max_entries);

  /**
   * @brief Store temporary path cache entries.
   */
  void StoreTempCache_(const CacheKey &key, const std::vector<PathInfo> &items);

  mutable std::mutex cache_mtx_;
  std::unordered_map<std::string, std::unordered_map<std::string, CacheEntry>>
      cache_;
  std::unordered_map<std::string, std::list<std::string>> cache_order_;
  std::unordered_map<std::string,
                     std::unordered_map<std::string, TempCacheEntry>>
      temp_cache_;
  std::shared_ptr<AMInterface::completion::ICompletionRuntime> runtime_ =
      nullptr;
};

} // namespace AMInterface::searcher
