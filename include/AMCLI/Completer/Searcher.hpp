#pragma once
#include "AMBase/DataClass.hpp"
#include "AMCLI/Completer/Engine.hpp"
#include "AMCLI/TokenTypeAnalyzer.hpp"
#include "AMManager/Client.hpp"
#include "AMManager/Host.hpp"
#include "AMManager/Set.hpp"
#include "AMManager/Transfer.hpp"
#include <chrono>
#include <list>
#include <mutex>
#include <unordered_map>
#include <vector>

class AMConfigManager;
class AMFileSystem;
class AMTransferManager;
namespace AMClientManage {
class Manager;
}

/**
 * @brief Registration tuple used to bind targets to search engines.
 */
struct AMSearchEngineRegistration {
  std::vector<AMCompletionTarget> targets;
  std::shared_ptr<AMCompletionSearchEngine> engine;
};

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
  AMCompletionCollectResult
  CollectCandidates(const AMCompletionContext &ctx) override;

  /**
   * @brief Sort command-related candidates.
   */
  void SortCandidates(const AMCompletionContext &ctx,
                      std::vector<AMCompletionCandidate> &items) override;

private:
  using CommandNode = CommandTree::CommandNode;

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

  std::shared_ptr<CommandTree> command_tree_;
};

/**
 * @brief Internal-value completion search engine (vars/hosts/clients/tasks).
 */
class AMInternalSearchEngine : public AMCompletionSearchEngine {
public:
  /**
   * @brief Construct internal-value search engine.
   */
  AMInternalSearchEngine() = default;

  /**
   * @brief Collect internal-value candidates.
   */
  AMCompletionCollectResult
  CollectCandidates(const AMCompletionContext &ctx) override;

  /**
   * @brief Sort internal-value candidates.
   */
  void SortCandidates(const AMCompletionContext &ctx,
                      std::vector<AMCompletionCandidate> &items) override;

private:
  AMHostManager &host_manager_ = AMHostManager::Instance();
  AMClientManager &client_manager_ = AMClientManager::Instance();
  AMTransferManager &transfer_manager_ = AMTransferManager::Instance();
};

/**
 * @brief Path completion search engine with internal cache support.
 */
class AMPathSearchEngine : public AMCompletionSearchEngine {
public:
  /**
   * @brief Construct path search engine.
   */
  AMPathSearchEngine();

  /**
   * @brief Collect path candidates or async path requests.
   */
  AMCompletionCollectResult
  CollectCandidates(const AMCompletionContext &ctx) override;

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
    bool operator==(const CacheKey &other) const {
      return nickname == other.nickname && dir == other.dir;
    }
  };

  /**
   * @brief Cache entry for path results.
   */
  struct CacheEntry {
    std::vector<PathInfo> items;
    std::chrono::steady_clock::time_point timestamp;
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
   * @brief Load per-nickname path-engine configuration.
   */
  void LoadPathEngineConfigs_();

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
   * @brief Store path cache entries and prune old entries.
   */
  void StoreCache_(const CacheKey &key, const std::vector<PathInfo> &items,
                   size_t max_entries);

  AMConfigManager &config_manager_;
  AMClientManage::Manager &client_manager_;
  AMFileSystem &filesystem_;
  AMTokenTypeAnalyzer &token_analyzer_ = AMTokenTypeAnalyzer::Instance();
  AMSetManager &set_manager_ = AMSetManager::Instance();
  mutable std::mutex cache_mtx_;
  std::unordered_map<std::string, std::unordered_map<std::string, CacheEntry>>
      cache_;
  std::unordered_map<std::string, std::list<std::string>> cache_order_;
};

/**
 * @brief Build the default completion search-engine registration set.
 */
std::vector<AMSearchEngineRegistration>
AMBuildDefaultSearchEngineRegistrations();
