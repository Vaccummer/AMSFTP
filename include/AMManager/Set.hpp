#pragma once
#include "AMBase/DataClass.hpp"
#include "AMBase/tools/json.hpp"
#include <cstddef>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace hostsetkn {
inline constexpr const char *kHostSetRoot = "HostSet";
inline constexpr const char *kDefaultHost = "*";
} // namespace hostsetkn

/**
 * @brief Typed HostSet fields used by path completion/highlight.
 */
struct AMHostSetPathConfig {
  bool use_async = false;
  bool use_cache = false;
  size_t cache_items_threshold = 50;
  size_t cache_max_entries = 15;
  size_t timeout_ms = 3000;
  bool highlight_use_check = true;
  size_t highlight_timeout_ms = 1000;

  /**
   * @brief Serialize path-set config into HostSet JSON shape.
   */
  [[nodiscard]] Json GetJson() const;

  /**
   * @brief Build path-set config from JSON with fallback defaults.
   */
  static AMHostSetPathConfig FromJson(const Json &jsond,
                                      const AMHostSetPathConfig &defaults);
};

/**
 * @brief Result wrapper for resolving path-related HostSet config.
 */
struct AMHostSetAttrResult {
  AMHostSetPathConfig value{};
  bool fallback_to_default = false;
};

/**
 * @brief Result wrapper for resolving one host HostSet table.
 */
struct AMHostSetTableResult {
  Json value = Json::object();
  bool fallback_to_default = false;
};

class AMSetCLI;

/**
 * @brief Manager for [HostSet] data inside settings.toml.
 */
class AMSetManager : public NonCopyableNonMovable {
public:
  /**
   * @brief Return the shared HostSet manager.
   */
  static AMSetManager &Instance();

  /**
   * @brief Load HostSet cache from settings.toml.
   */
  ECM Init() override { return Reload(); }

  /**
   * @brief Reload HostSet from ConfigManager settings JSON.
   */
  ECM Reload();

  /**
   * @brief Return a read-only copy of the cached HostSet object.
   */
  [[nodiscard]] Json Snapshot() const;

  /**
   * @brief Resolve merged host set table (host overrides "*").
   */
  [[nodiscard]] AMHostSetTableResult
  ResolveHostSet(const std::string &nickname) const;

  /**
   * @brief Resolve path-related typed HostSet configuration.
   */
  [[nodiscard]] AMHostSetAttrResult
  ResolvePathSet(const std::string &nickname) const;

  /**
   * @brief Return whether a specific host set table exists in cache.
   */
  [[nodiscard]] bool HasHostSet(const std::string &nickname) const;

  /**
   * @brief List HostSet table names.
   */
  [[nodiscard]] std::vector<std::string>
  ListSetNames(bool include_default = false) const;

  /**
   * @brief Create one host set table in cache.
   */
  ECM CreateHostSet(const std::string &nickname,
                    const AMHostSetPathConfig &set_config,
                    bool overwrite = false);

  /**
   * @brief Replace one host set table in cache.
   */
  ECM ModifyHostSet(const std::string &nickname,
                    const AMHostSetPathConfig &set_config,
                    bool create_when_missing = false);

  /**
   * @brief Delete one host set table from cache.
   */
  ECM DeleteHostSet(const std::string &nickname);

  /**
   * @brief Write cached HostSet back to settings and dump settings.toml.
   */
  ECM Save(bool async = true);

protected:
  /**
   * @brief Construct a HostSet manager.
   */
  AMSetManager() = default;

private:
  /**
   * @brief Ensure HostSet cache is initialized.
   */
  void EnsureLoaded_();

  /**
   * @brief Return host table pointer while lock is held.
   */
  [[nodiscard]] const AMHostSetPathConfig *
  FindHostEntryNoLock_(const std::string &nickname) const;

  /**
   * @brief Return default "*" table pointer while lock is held.
   */
  [[nodiscard]] const AMHostSetPathConfig *FindDefaultEntryNoLock_() const;

  mutable std::mutex mtx_;
  bool ready_ = false;
  bool dirty_ = false;
  std::unordered_map<std::string, AMHostSetPathConfig> host_sets_ = {};
};

/**
 * @brief CLI helper built on AMSetManager for config hostset commands.
 */
class AMSetCLI : public AMSetManager {
public:
  /**
   * @brief Return the shared HostSet CLI helper.
   */
  static AMSetCLI &Instance() {
    static AMSetCLI instance;
    return instance;
  }

  /**
   * @brief Create one host set using interactive prompts.
   */
  ECM Add(const std::string &nickname);

  /**
   * @brief Modify one host set using interactive prompts.
   */
  ECM Modify(const std::string &nickname);

  /**
   * @brief Delete one host set entry.
   */
  ECM Delete(const std::string &nickname);

  /**
   * @brief Delete multiple host set entries.
   */
  ECM Delete(const std::vector<std::string> &targets);

  /**
   * @brief Persist cached HostSet data to settings.toml.
   */
  ECM SaveSettings();

private:
  /**
   * @brief Construct a HostSet CLI helper.
   */
  AMSetCLI() = default;

  /**
   * @brief Prompt a full typed path-set payload.
   */
  ECM PromptPathSet_(const std::string &nickname,
                     const AMHostSetPathConfig &base,
                     AMHostSetPathConfig *output) const;
};
