#pragma once
#include "AMCLI/Completer/Engine.hpp"
#include "AMManager/Client.hpp"
#include "AMManager/Host.hpp"
#include "AMManager/Transfer.hpp"
#include <chrono>
#include <mutex>
#include <unordered_map>
#include <unordered_set>
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
  /**
   * @brief Command tree node used for completion lookups.
   */
  struct CommandNode {
    std::unordered_map<std::string, std::string> subcommands;
    std::unordered_map<std::string, std::string> long_options;
    std::unordered_map<char, std::string> short_options;
  };

  /**
   * @brief CLI command tree used for command completion lookups.
   */
  class CommandTree {
  public:
    /**
     * @brief Construct and build the command tree.
     */
    CommandTree();

    /**
     * @brief Return true when name is a top-level command.
     */
    bool IsTopCommand(const std::string &name) const;

    /**
     * @brief Return true when name is a module (has subcommands).
     */
    bool IsModule(const std::string &name) const;

    /**
     * @brief Find a node by command path.
     */
    const CommandNode *FindNode(const std::string &path) const;

    /**
     * @brief List top-level commands with help text.
     */
    std::vector<std::pair<std::string, std::string>> ListTopCommands() const;

    /**
     * @brief List subcommands for a command path.
     */
    std::vector<std::pair<std::string, std::string>>
    ListSubcommands(const std::string &path) const;

    /**
     * @brief List long options for a command path.
     */
    std::vector<std::pair<std::string, std::string>>
    ListLongOptions(const std::string &path) const;

    /**
     * @brief List short options for a command path.
     */
    std::vector<std::pair<char, std::string>>
    ListShortOptions(const std::string &path) const;

  private:
    /**
     * @brief Build tree structure from CLI metadata.
     */
    void Build();

    /**
     * @brief Register a command path as top-level command.
     */
    void RegisterCommand_(const std::string &path, const std::string &help);

    std::unordered_map<std::string, CommandNode> nodes_;
    std::unordered_set<std::string> top_commands_;
    std::unordered_set<std::string> modules_;
    std::unordered_map<std::string, std::string> top_help_;
  };

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

  CommandTree command_tree_;
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
   * @brief Hash helper for CacheKey.
   */
  struct CacheKeyHash {
    /**
     * @brief Hash cache key.
     */
    std::size_t operator()(const CacheKey &key) const {
      return std::hash<std::string>()(key.nickname) ^
             (std::hash<std::string>()(key.dir) << 1);
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
   * @brief Style a path entry for display.
   */
  std::string FormatPathDisplay_(const PathInfo &info,
                                 const std::string &name) const;

  /**
   * @brief Build path context from completion token and mode.
   */
  PathContext BuildPathContext_(const std::string &token_prefix,
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
  std::mutex cache_mtx_;
  std::unordered_map<CacheKey, CacheEntry, CacheKeyHash> cache_;
};

/**
 * @brief Build the default completion search-engine registration set.
 */
std::vector<AMSearchEngineRegistration>
AMBuildDefaultSearchEngineRegistrations();
