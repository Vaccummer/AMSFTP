#pragma once
#include "AMCLI/CompleteEngine.hpp"
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <mutex>
#include <optional>
#include <thread>
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
 * @brief Completion sources for commands, internal values, and paths.
 */
class AMCompleteSources {
public:
  /**
   * @brief Construct completion sources with required managers.
   */
  AMCompleteSources(AMCompleteEngine *engine, AMConfigManager &config_manager,
                    AMClientManage::Manager &client_manager,
                    AMFileSystem &filesystem,
                    AMTransferManager &transfer_manager);

  /**
   * @brief Default destructor.
   */
  ~AMCompleteSources();

  /**
   * @brief Clear completion caches.
   */
  void ClearCache();

  /**
   * @brief Reset async results for a new request.
   */
  void ResetAsyncResult();

  /**
   * @brief Return true when name is a top-level command.
   */
  bool IsTopCommand(const std::string &name) const;

  /**
   * @brief Return true when name is a module (has subcommands).
   */
  bool IsModule(const std::string &name) const;

  /**
   * @brief Find a command node by its path.
   */
  const AMCompleteEngine::CommandNode *FindNode(const std::string &path) const;

  /**
   * @brief Collect command/option candidates.
   */
  void CollectCommandCandidates_(
      const AMCompleteEngine::CompletionContext &ctx,
      std::vector<AMCompleteEngine::CompletionCandidate> &out);

  /**
   * @brief Collect internal candidates (vars, hosts, clients, tasks).
   */
  void CollectInternalCandidates_(
      const AMCompleteEngine::CompletionContext &ctx,
      std::vector<AMCompleteEngine::CompletionCandidate> &out);

  /**
   * @brief Collect path candidates.
   */
  void CollectPathCandidates_(
      const AMCompleteEngine::CompletionContext &ctx,
      std::vector<AMCompleteEngine::CompletionCandidate> &out);

private:
  /**
   * @brief CLI command tree used for completion lookups.
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
     * @brief Find a node by its command path.
     */
    const AMCompleteEngine::CommandNode *
    FindNode(const std::string &path) const;

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
     * @brief Build the command tree from CLI metadata.
     */
    void Build();

    /**
     * @brief Merge command metadata into a node.
     */
    void MergeCommand_(const std::string &path, const std::string &help,
                       const std::vector<std::string> &commands,
                       const std::vector<std::string> &long_opts,
                       const std::vector<std::string> &short_opts);

    /**
     * @brief Register a command path as a top-level command.
     */
    void RegisterCommand_(const std::string &path, const std::string &help);

    std::unordered_map<std::string, AMCompleteEngine::CommandNode> nodes_;
    std::unordered_set<std::string> top_commands_;
    std::unordered_set<std::string> modules_;
    std::unordered_map<std::string, std::string> top_help_;
  };

  /**
   * @brief Cache key for path results.
   */
  struct CacheKey {
    std::string nickname;
    std::string dir;

    /**
     * @brief Compare two cache keys.
     */
    bool operator==(const CacheKey &other) const {
      return nickname == other.nickname && dir == other.dir;
    }
  };

  /**
   * @brief Hash for CacheKey.
   */
  struct CacheKeyHash {
    /**
     * @brief Hash a cache key for unordered_map usage.
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
   * @brief Async path completion result.
   */
  struct AsyncResult {
    uint64_t request_id = 0;
    CacheKey key;
    std::string base;
    std::string leaf_prefix;
    char sep = '/';
    bool remote = false;
    std::vector<PathInfo> items;
  };

  /**
   * @brief Build a styled and padded command/module display string.
   */
  std::string FormatCommandDisplay_(const std::string &name,
                                    const std::string &style_key,
                                    size_t pad_width) const;

  /**
   * @brief Style a path entry for display.
   */
  std::string FormatPathDisplay_(const PathInfo &info,
                                 const std::string &name) const;

  /**
   * @brief Filter and append path candidates from a list.
   */
  void AppendPathCandidates_(
      const AMCompleteEngine::CompletionContext &ctx,
      const std::vector<PathInfo> &items,
      std::vector<AMCompleteEngine::CompletionCandidate> &out);

  /**
   * @brief Lookup cache entries for a path key.
   */
  bool LookupCache_(const CacheKey &key, std::vector<PathInfo> *items);

  /**
   * @brief Store cache entries and prune if needed.
   */
  void StoreCache_(const CacheKey &key, const std::vector<PathInfo> &items);

  /**
   * @brief Attempt to use async results for the current request.
   */
  bool TryConsumeAsyncResult_(const AMCompleteEngine::CompletionContext &ctx,
                              std::vector<PathInfo> *items);

  /**
   * @brief Schedule a remote async completion request.
   */
  void ScheduleAsyncRequest_(const AMCompleteEngine::CompletionContext &ctx);

  /**
   * @brief Start the async worker thread.
   */
  void StartAsyncWorker();

  /**
   * @brief Stop the async worker thread.
   */
  void StopAsyncWorker();

  /**
   * @brief Run the async worker loop.
   */
  void AsyncWorkerLoop_();

  AMCompleteEngine *engine_ = nullptr;
  AMConfigManager &config_manager_;
  AMClientManage::Manager &client_manager_;
  AMFileSystem &filesystem_;
  AMTransferManager &transfer_manager_;
  CommandTree command_tree_;

  std::mutex cache_mtx_;
  std::unordered_map<CacheKey, CacheEntry, CacheKeyHash> cache_;

  std::atomic<bool> async_stop_{false};
  std::thread async_thread_;
  std::mutex async_mtx_;
  std::condition_variable async_cv_;
  std::optional<AMCompleteEngine::AsyncRequest> pending_request_;

  std::mutex async_result_mtx_;
  std::optional<AsyncResult> async_result_;
};
