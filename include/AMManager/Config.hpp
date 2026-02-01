#pragma once
#include "AMBase/CommonTools.hpp"
#include "AMBase/DataClass.hpp"
#include "AMBase/Enum.hpp"
#include "AMBase/cfgffi.h"
#include <atomic>
#include <condition_variable>
#include <deque>
#include <filesystem>
#include <functional>
#include <map>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <utility>
#include <vector>

class AMConfigManager {
public:
  using Path = AMConfigProcessor::Path;
  using Value = AMConfigProcessor::Value;
  using FlatMap = AMConfigProcessor::FlatMap;
  using FormatPath = AMConfigProcessor::FormatPath;

  struct ClientConfig {
    ConRequst request;
    ClientProtocol protocol = ClientProtocol::SFTP;
    int64_t buffer_size = -1;
    std::string login_dir = "";
  };

  /**
   * @brief Known host entry for SSH fingerprint verification.
   */
  struct KnownHostEntry {
    std::string nickname;
    std::string hostname;
    int port = 0;
    std::string protocol;
    std::string fingerprint;
    std::string fingerprint_sha256;
  };

  using KnownHostCallback =
      std::function<ECM(AMConfigManager::KnownHostEntry)>;

  static AMConfigManager &Instance();

  AMConfigManager(const AMConfigManager &) = delete;
  AMConfigManager &operator=(const AMConfigManager &) = delete;
  AMConfigManager(AMConfigManager &&) = delete;
  AMConfigManager &operator=(AMConfigManager &&) = delete;

  /** @brief Stop the background writer and release config handles. */
  ~AMConfigManager();

  ECM Init();
  ECM Dump();

  [[nodiscard]] std::string Format(const std::string &ori_str,
                                   const std::string &style_name) const;

  [[nodiscard]] ECM List() const;
  [[nodiscard]] ECM ListName() const;
  /** Return a list of configured host nicknames. */
  [[nodiscard]] std::vector<std::string> ListHostnames() const;
  [[nodiscard]] std::pair<ECM, std::vector<std::string>>
  PrivateKeys(bool print_sign = false) const;
  /**
   * @brief Find a known host entry by hostname, port, and protocol.
   */
  [[nodiscard]] std::pair<ECM, std::optional<KnownHostEntry>>
  FindKnownHost(const std::string &hostname, int port,
                const std::string &protocol) const;
  /**
   * @brief Insert or update a known host entry and optionally persist it.
   */
  ECM UpsertKnownHost(const KnownHostEntry &entry, bool dump_now = true);
  /**
   * @brief Build a known host verification callback for SFTP clients.
   */
  KnownHostCallback BuildKnownHostCallback();
  /** Return the project root directory path. */
  [[nodiscard]] std::filesystem::path ProjectRoot() const { return root_dir_; }
  [[nodiscard]] std::pair<ECM, ClientConfig>
  GetClientConfig(const std::string &nickname, bool use_compression = false);
  [[nodiscard]] int GetSettingInt(const Path &path, int default_value) const;
  /**
   * @brief Resolve network timeout from settings with a default fallback.
   */
  [[nodiscard]] int ResolveTimeoutMs(int default_timeout_ms = 5000) const;
  /** Return a string setting value or the provided default. */
  [[nodiscard]] std::string
  GetSettingString(const Path &path, const std::string &default_value) const;
  /**
   * @brief Query a UserPaths entry by name.
   */
  bool GetUserPath(const std::string &name, std::string *value) const;
  /**
   * @brief List all UserPaths entries.
   */
  [[nodiscard]] std::vector<std::pair<std::string, std::string>>
  ListUserPaths() const;
  /**
   * @brief Set a UserPaths entry and optionally persist to settings.
   */
  ECM SetUserPath(const std::string &name, const std::string &value,
                  bool dump_now = true);
  /**
   * @brief Remove a UserPaths entry and optionally persist to settings.
   */
  ECM RemoveUserPath(const std::string &name, bool dump_now = true);
  [[nodiscard]] ECM Src() const;
  [[nodiscard]] ECM Delete(const std::string &targets);
  /**
   * @brief Delete hosts by nickname list without parsing input.
   */
  [[nodiscard]] ECM Delete(const std::vector<std::string> &targets);
  [[nodiscard]] ECM Rename(const std::string &old_nickname,
                           const std::string &new_nickname);
  [[nodiscard]] ECM Query(const std::string &targets) const;
  /**
   * @brief Query hosts by nickname list without parsing input.
   */
  [[nodiscard]] ECM Query(const std::vector<std::string> &targets) const;
  [[nodiscard]] ECM Add();
  [[nodiscard]] ECM Modify(const std::string &nickname);
  /**
   * @brief Validate whether a nickname is legal and not already used.
   */
  bool ValidateNickname(const std::string &nickname, std::string *error) const;
  /**
   * @brief Persist an encrypted password for a given client nickname.
   */
  ECM SetClientPasswordEncrypted(const std::string &nickname,
                                 const std::string &encrypted_password,
                                 bool dump_now = true);
  /** Set a host field and optionally dump config. */
  ECM SetHostField(const std::string &nickname, const std::string &field,
                   const Value &value, bool dump_now = true);

  /**
   * @brief Load history data from .AMSFTP_History.toml into memory.
   */
  ECM LoadHistory();

  /**
   * @brief Fetch history commands for a nickname.
   */
  ECM GetHistoryCommands(const std::string &nickname,
                         std::vector<std::string> *out);

  /**
   * @brief Store history commands for a nickname and optionally persist.
   */
  ECM SetHistoryCommands(const std::string &nickname,
                         const std::vector<std::string> &commands,
                         bool dump_now = true);

  /**
   * @brief Resolve history size limit from settings with minimum 10.
   */
  [[nodiscard]] int ResolveMaxHistoryCount(int default_value = 10) const;

  /**
   * @brief Submit a no-arg write task to the background writer thread.
   */
  void SubmitWriteTask(std::function<void()> task);

  /**
   * @brief Backup config/settings/known_hosts when the interval elapses.
   */
  ECM ConfigBackupIfNeeded();

  /** Query a value at path for config/settings JSON. */
  bool QueryKey(const nlohmann::ordered_json &root, const Path &path,
                Value *value) const;
  /** Set or create a value at path for config/settings JSON. */
  template <typename T>
  bool SetKey(nlohmann::ordered_json &root, const Path &path, T value) {
    nlohmann::ordered_json *node = &root;
    for (size_t i = 0; i < path.size(); ++i) {
      const std::string &seg = path[i];
      if (i + 1 == path.size()) {
        (*node)[seg] = value;
        return true;
      }
      if (!node->is_object()) {
        *node = nlohmann::ordered_json::object();
      }
      if (!node->contains(seg) || !(*node)[seg].is_object()) {
        (*node)[seg] = nlohmann::ordered_json::object();
      }
      node = &(*node)[seg];
    }
    return false;
  }

private:
  AMConfigManager() = default;

  struct HostEntry {
    std::map<std::string, Value> fields;
  };

  static void OnExit();
  void CloseHandles();
  ECM EnsureInitialized(const char *caller) const;
  [[nodiscard]] std::string ValueToString(const Value &value) const;
  [[nodiscard]] std::map<std::string, HostEntry> CollectHosts() const;
  [[nodiscard]] ECM PrintHost(const std::string &nickname,
                              const HostEntry &entry) const;
  [[nodiscard]] bool HostExists(const std::string &nickname) const;
  ECM UpsertHostField(const std::string &nickname, const std::string &field,
                      Value value);
  ECM RemoveHost(const std::string &nickname);

  ECM PromptAddFields(std::string *nickname, HostEntry *entry);
  ECM PromptModifyFields(const std::string &nickname, HostEntry *entry);
  bool ParsePositiveInt(const std::string &input, int64_t *value) const;

  /**
   * @brief Ensure history file is loaded and ready for access.
   */
  ECM EnsureHistoryLoaded_();

  /**
   * @brief Persist in-memory history JSON to disk.
   */
  ECM DumpHistory_();

  /** @brief Start the background writer thread if not running. */
  void StartWriteThread_();
  /** @brief Stop the background writer thread and drain pending tasks. */
  void StopWriteThread_();
  /** @brief Background worker loop for serialized write tasks. */
  void WriteThreadLoop_();
  /**
   * @brief Write a TOML snapshot to a target path using the given handle.
   */
  void WriteSnapshotToPath_(ConfigHandle *handle, const std::string &json,
                            const std::filesystem::path &out_path) const;

  std::filesystem::path root_dir_;
  std::filesystem::path config_path_;
  std::filesystem::path settings_path_;
  std::filesystem::path known_hosts_path_;
  std::filesystem::path history_path_;
  /** JSON schema path for config.toml filtering. */
  std::filesystem::path config_schema_path_;
  /** JSON schema path for settings.toml filtering. */
  std::filesystem::path settings_schema_path_;
  /** JSON schema path for known_hosts.toml filtering. */
  std::filesystem::path known_hosts_schema_path_;
  nlohmann::ordered_json config_json_;
  nlohmann::ordered_json settings_json_;
  nlohmann::ordered_json known_hosts_json_;
  nlohmann::ordered_json history_json_;
  ConfigHandle *config_handle_ = nullptr;
  ConfigHandle *settings_handle_ = nullptr;
  ConfigHandle *known_hosts_handle_ = nullptr;
  ConfigHandle *history_handle_ = nullptr;
  KnownHostCallback known_host_cb_ = {};

  std::vector<FormatPath> config_filters_;
  std::vector<FormatPath> settings_filters_;

  std::mutex write_mtx_;
  std::condition_variable write_cv_;
  std::deque<std::function<void()>> write_queue_;
  std::thread write_thread_;
  std::atomic<bool> write_running_{false};
  std::mutex handle_mtx_;
  bool backup_prune_checked_ = false;

  bool initialized_ = false;
  bool exit_hook_installed_ = false;
};
