#pragma once
#include "AMBase/CommonTools.hpp"
#include "AMBase/DataClass.hpp"
#include "AMBase/Enum.hpp"
#include "AMBase/cfgffi.h"
#include "AMManager/Prompt.hpp"
#include <atomic>
#include <condition_variable>
#include <deque>
#include <filesystem>
#include <functional>
#include <map>
#include <mutex>
#include <optional>
#include <regex>
#include <string>
#include <thread>
#include <utility>
#include <variant>
#include <vector>

/**
 * @brief Low-level config storage layer for raw persistence and file I/O.
 */
class AMConfigStorage {
public:
  using Path = std::vector<std::string>;
  using Value =
      std::variant<int64_t, bool, std::string, std::vector<std::string>>;

  /**
   * @brief Construct a storage layer with empty state.
   */
  AMConfigStorage() = default;

  /**
   * @brief Stop the background writer thread on destruction.
   */
  ~AMConfigStorage() { StopWriteThread(); }

  /**
   * @brief Initialize storage paths and reset cached documents.
   * @param root_dir Project root directory.
   * @param config_path Config file path.
   * @param settings_path Settings file path.
   * @param known_hosts_path Known hosts file path.
   * @param history_path History file path.
   * @return ECM success or failure.
   */
  ECM Init(const std::filesystem::path &root_dir,
           const std::filesystem::path &config_path,
           const std::filesystem::path &settings_path,
           const std::filesystem::path &known_hosts_path,
           const std::filesystem::path &history_path) {
    root_dir_ = root_dir;
    config_path_ = config_path;
    settings_path_ = settings_path;
    known_hosts_path_ = known_hosts_path;
    history_path_ = history_path;
    config_json_ = nlohmann::ordered_json::object();
    settings_json_ = nlohmann::ordered_json::object();
    known_hosts_json_ = nlohmann::ordered_json::object();
    history_json_ = nlohmann::ordered_json::object();
    return {EC::Success, ""};
  }

  /**
   * @brief Bind cfgffi handles used for persisting config documents.
   * @param config_handle Config handle pointer.
   * @param settings_handle Settings handle pointer.
   * @param known_hosts_handle Known hosts handle pointer.
   * @param history_handle History handle pointer.
   */
  void BindHandles(ConfigHandle *config_handle, ConfigHandle *settings_handle,
                   ConfigHandle *known_hosts_handle,
                   ConfigHandle *history_handle) {
    config_handle_ = config_handle;
    settings_handle_ = settings_handle;
    known_hosts_handle_ = known_hosts_handle;
    history_handle_ = history_handle;
  }

  /**
   * @brief Persist config/settings/known_hosts JSON snapshots to disk.
   * @return ECM success or failure.
   */
  ECM Dump() {
    std::error_code ec;
    if (!config_path_.empty()) {
      std::filesystem::create_directories(config_path_.parent_path(), ec);
      if (ec) {
        return {EC::ConfigDumpFailed,
                AMStr::amfmt("failed to create config directory: {}",
                             ec.message())};
      }
    }

    ECM rcm =
        WriteHandleJson_(config_handle_, &config_json_, config_path_, "config");
    if (rcm.first != EC::Success) {
      return rcm;
    }
    rcm = WriteHandleJson_(settings_handle_, &settings_json_, settings_path_,
                           "settings");
    if (rcm.first != EC::Success) {
      return rcm;
    }
    rcm = WriteHandleJson_(known_hosts_handle_, &known_hosts_json_,
                           known_hosts_path_, "known_hosts");
    if (rcm.first != EC::Success) {
      return rcm;
    }
    return {EC::Success, ""};
  }

  /**
   * @brief Persist history JSON snapshot to disk.
   * @return ECM success or failure.
   */
  ECM DumpHistory() {
    return WriteHandleJson_(history_handle_, &history_json_, history_path_,
                            "history");
  }

  /**
   * @brief Query a JSON value by path from a root object.
   * @param root JSON root to search.
   * @param path Path segments leading to the target node.
   * @param value Output variant value on success.
   * @return True when the value is found and converted.
   */
  bool QueryKey(const nlohmann::ordered_json &root, const Path &path,
                Value *value) const {
    if (!value) {
      return false;
    }
    const nlohmann::ordered_json *node = &root;
    for (const auto &seg : path) {
      if (!node->is_object()) {
        return false;
      }
      auto it = node->find(seg);
      if (it == node->end()) {
        return false;
      }
      node = &(*it);
    }
    if (node->is_boolean()) {
      *value = node->get<bool>();
      return true;
    }
    if (node->is_number_integer()) {
      *value = node->get<int64_t>();
      return true;
    }
    if (node->is_number_unsigned()) {
      *value = static_cast<int64_t>(node->get<size_t>());
      return true;
    }
    if (node->is_string()) {
      *value = node->get<std::string>();
      return true;
    }
    if (node->is_array()) {
      std::vector<std::string> values;
      values.reserve(node->size());
      for (const auto &child : *node) {
        if (child.is_string()) {
          values.push_back(child.get<std::string>());
          continue;
        }
        if (child.is_boolean()) {
          values.push_back(child.get<bool>() ? "true" : "false");
          continue;
        }
        if (child.is_number_integer()) {
          values.push_back(std::to_string(child.get<int64_t>()));
          continue;
        }
        if (child.is_number_unsigned()) {
          values.push_back(std::to_string(child.get<size_t>()));
          continue;
        }
        if (child.is_number_float()) {
          values.push_back(std::to_string(child.get<double>()));
          continue;
        }
        if (child.is_null()) {
          values.emplace_back("null");
          continue;
        }
        return false;
      }
      *value = std::move(values);
      return true;
    }
    return false;
  }

  /**
   * @brief Set or create a JSON value by path in a root object.
   * @param root JSON root to mutate.
   * @param path Path segments to create or update.
   * @param value Value to assign at the target node.
   * @return True when the value is set.
   */
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

  /**
   * @brief Submit a write task to the background queue.
   * @param task Task to execute asynchronously.
   */
  void SubmitWriteTask(std::function<void()> task) {
    if (!task) {
      return;
    }
    StartWriteThread();
    {
      std::lock_guard<std::mutex> lock(write_mtx_);
      write_queue_.push_back(std::move(task));
    }
    write_cv_.notify_one();
  }

  /**
   * @brief Start the background writer thread if not running.
   */
  void StartWriteThread() {
    std::lock_guard<std::mutex> lock(write_mtx_);
    if (write_running_) {
      return;
    }
    write_running_ = true;
    write_thread_ = std::thread([this]() { WriteThreadLoop_(); });
  }

  /**
   * @brief Stop the background writer thread and drain pending tasks.
   */
  void StopWriteThread() {
    {
      std::lock_guard<std::mutex> lock(write_mtx_);
      if (!write_running_) {
        return;
      }
      write_running_ = false;
    }
    write_cv_.notify_one();
    if (write_thread_.joinable()) {
      write_thread_.join();
    }
  }

  /**
   * @brief Trigger backup logic when needed (no-op placeholder).
   * @return ECM success or failure.
   */
  ECM BackupIfNeeded() { return {EC::Success, ""}; }

  /**
   * @brief Provide mutable access to config JSON.
   * @return Reference to config JSON object.
   */
  [[nodiscard]] nlohmann::ordered_json &config_json() { return config_json_; }

  /**
   * @brief Provide mutable access to settings JSON.
   * @return Reference to settings JSON object.
   */
  [[nodiscard]] nlohmann::ordered_json &settings_json() {
    return settings_json_;
  }

  /**
   * @brief Provide mutable access to known hosts JSON.
   * @return Reference to known hosts JSON object.
   */
  [[nodiscard]] nlohmann::ordered_json &known_hosts_json() {
    return known_hosts_json_;
  }

  /**
   * @brief Provide mutable access to history JSON.
   * @return Reference to history JSON object.
   */
  [[nodiscard]] nlohmann::ordered_json &history_json() { return history_json_; }

  /**
   * @brief Return the root directory used by the storage layer.
   * @return Root directory path.
   */
  [[nodiscard]] const std::filesystem::path &root_dir() const {
    return root_dir_;
  }

  /**
   * @brief Return the config file path tracked by the storage layer.
   * @return Config file path.
   */
  [[nodiscard]] const std::filesystem::path &config_path() const {
    return config_path_;
  }

  /**
   * @brief Return the settings file path tracked by the storage layer.
   * @return Settings file path.
   */
  [[nodiscard]] const std::filesystem::path &settings_path() const {
    return settings_path_;
  }

  /**
   * @brief Return the known hosts file path tracked by the storage layer.
   * @return Known hosts file path.
   */
  [[nodiscard]] const std::filesystem::path &known_hosts_path() const {
    return known_hosts_path_;
  }

  /**
   * @brief Return the history file path tracked by the storage layer.
   * @return History file path.
   */
  [[nodiscard]] const std::filesystem::path &history_path() const {
    return history_path_;
  }

private:
  /**
   * @brief Parse JSON text into an ordered_json object.
   * @param json_str JSON string to parse.
   * @param out Parsed JSON output.
   * @return True when parsing succeeds.
   */
  bool ParseJsonString_(const std::string &json_str,
                        nlohmann::ordered_json *out) const {
    if (!out) {
      return false;
    }
    try {
      *out = nlohmann::ordered_json::parse(json_str);
      return true;
    } catch (...) {
      return false;
    }
  }

  /**
   * @brief Write JSON content into a cfgffi handle and refresh the cache.
   * @param handle cfgffi handle pointer.
   * @param json JSON object to serialize.
   * @param path Target file path for error messaging.
   * @param label Friendly label used in error messages.
   * @return ECM success or failure.
   */
  ECM WriteHandleJson_(ConfigHandle *handle, nlohmann::ordered_json *json,
                       const std::filesystem::path &path,
                       const std::string &label) {
    if (!handle || !json) {
      return {EC::ConfigNotInitialized,
              AMStr::amfmt("{} handle not initialized", label)};
    }
    std::string payload = json->dump(2);
    char *err = nullptr;
    {
      std::lock_guard<std::mutex> lock(handle_mtx_);
      int rc = cfgffi_write_inplace(handle, payload.c_str(), &err);
      if (rc != 0) {
        std::string msg = err ? err : "cfgffi_write error";
        if (err) {
          cfgffi_free_string(err);
        }
        return {EC::ConfigDumpFailed,
                AMStr::amfmt("Failed to dump to {}: {}", path.string(), msg)};
      }
      if (err) {
        cfgffi_free_string(err);
      }
      char *json_c = cfgffi_get_json(handle);
      if (json_c) {
        std::string json_str(json_c);
        cfgffi_free_string(json_c);
        (void)ParseJsonString_(json_str, json);
      }
    }
    return {EC::Success, ""};
  }

  /**
   * @brief Worker loop that processes queued write tasks.
   */
  void WriteThreadLoop_() {
    for (;;) {
      std::function<void()> task;
      {
        std::unique_lock<std::mutex> lock(write_mtx_);
        write_cv_.wait(
            lock, [&]() { return !write_running_ || !write_queue_.empty(); });
        if (!write_running_ && write_queue_.empty()) {
          break;
        }
        task = std::move(write_queue_.front());
        write_queue_.pop_front();
      }
      if (task) {
        task();
      }
    }
  }

  std::filesystem::path root_dir_;
  std::filesystem::path config_path_;
  std::filesystem::path settings_path_;
  std::filesystem::path known_hosts_path_;
  std::filesystem::path history_path_;
  nlohmann::ordered_json config_json_;
  nlohmann::ordered_json settings_json_;
  nlohmann::ordered_json known_hosts_json_;
  nlohmann::ordered_json history_json_;
  ConfigHandle *config_handle_ = nullptr;
  ConfigHandle *settings_handle_ = nullptr;
  ConfigHandle *known_hosts_handle_ = nullptr;
  ConfigHandle *history_handle_ = nullptr;
  std::mutex handle_mtx_;
  std::mutex write_mtx_;
  std::condition_variable write_cv_;
  std::deque<std::function<void()>> write_queue_;
  std::thread write_thread_;
  std::atomic<bool> write_running_{false};
};

/**
 * @brief Data access layer for non-style configuration entities.
 */
class AMConfigCoreData {
public:
  using Path = std::vector<std::string>;
  using Value =
      std::variant<int64_t, bool, std::string, std::vector<std::string>>;

  /**
   * @brief Construct a core data layer with default rules.
   */
  AMConfigCoreData() : nickname_pattern_("^[A-Za-z0-9_-]+$") {}

  /**
   * @brief Bind the storage layer used for raw config access.
   * @param storage Storage layer pointer.
   */
  void BindStorage(AMConfigStorage *storage) { storage_ = storage; }

  /**
   * @brief Report whether the layer has an attached storage instance.
   * @return True when storage is bound.
   */
  [[nodiscard]] bool HasStorage() const { return storage_ != nullptr; }

  /**
   * @brief Load history data into memory (in-memory only for now).
   * @return ECM success or failure.
   */
  ECM LoadHistory() {
    if (!storage_) {
      return {EC::ConfigNotInitialized, "config storage not initialized"};
    }
    auto &history = storage_->history_json();
    if (!history.is_object()) {
      history = nlohmann::ordered_json::object();
    }
    return {EC::Success, ""};
  }

  /**
   * @brief Fetch history commands for a nickname.
   * @param nickname Host nickname.
   * @param out Output list for commands.
   * @return ECM success or failure.
   */
  ECM GetHistoryCommands(const std::string &nickname,
                         std::vector<std::string> *out) const {
    if (!out) {
      return {EC::InvalidArg, "null history output"};
    }
    out->clear();
    if (!storage_) {
      return {EC::ConfigNotInitialized, "config storage not initialized"};
    }
    if (nickname.empty()) {
      return {EC::Success, ""};
    }
    const auto *node =
        FindJsonNode_(storage_->history_json(), {nickname, "commands"});
    if (!node || !node->is_array()) {
      return {EC::Success, ""};
    }
    for (const auto &item : *node) {
      if (item.is_string()) {
        out->push_back(item.get<std::string>());
      }
    }
    return {EC::Success, ""};
  }

  /**
   * @brief Store history commands for a nickname and optionally persist.
   * @param nickname Host nickname.
   * @param commands Command list to store.
   * @param dump_now Whether to persist immediately.
   * @return ECM success or failure.
   */
  ECM SetHistoryCommands(const std::string &nickname,
                         const std::vector<std::string> &commands,
                         bool dump_now = true) {
    if (!storage_) {
      return {EC::ConfigNotInitialized, "config storage not initialized"};
    }
    if (nickname.empty()) {
      return {EC::InvalidArg, "empty history nickname"};
    }
    auto &history = storage_->history_json();
    if (!history.is_object()) {
      history = nlohmann::ordered_json::object();
    }
    nlohmann::ordered_json &node = history[nickname];
    if (!node.is_object()) {
      node = nlohmann::ordered_json::object();
    }
    node["commands"] = commands;
    if (dump_now) {
      return storage_->DumpHistory();
    }
    return {EC::Success, ""};
  }

  /**
   * @brief Resolve history size limit from settings with minimum 10.
   * @param default_value Default fallback when no setting is found.
   * @return Resolved history max count.
   */
  [[nodiscard]] int ResolveMaxHistoryCount(int default_value = 10) const {
    const int fallback = std::max(default_value, 10);
    if (!storage_) {
      return fallback;
    }
    AMConfigStorage::Value value;
    if (!storage_->QueryKey(storage_->settings_json(),
                            {"InternalVars", "MaxHistoryCount"}, &value)) {
      return fallback;
    }
    if (std::holds_alternative<int64_t>(value)) {
      const int64_t raw = std::get<int64_t>(value);
      if (raw >= 10) {
        return static_cast<int>(raw);
      }
    }
    if (std::holds_alternative<std::string>(value)) {
      try {
        const int parsed = std::stoi(std::get<std::string>(value));
        return parsed >= 10 ? parsed : fallback;
      } catch (...) {
        return fallback;
      }
    }
    return fallback;
  }

  /**
   * @brief Check whether a host nickname exists in the configuration.
   * @param nickname Host nickname.
   * @return True when the nickname is present.
   */
  [[nodiscard]] bool HostExists(const std::string &nickname) const {
    if (!storage_ || nickname.empty()) {
      return false;
    }
    const auto &root = storage_->config_json();
    auto it = root.find("HOSTS");
    if (it == root.end() || !it->is_array()) {
      return false;
    }
    for (const auto &item : *it) {
      if (!item.is_object()) {
        continue;
      }
      auto nick_it = item.find("nickname");
      if (nick_it != item.end() && nick_it->is_string() &&
          nick_it->get<std::string>() == nickname) {
        return true;
      }
    }
    return false;
  }

  /**
   * @brief Validate whether a nickname is legal and not already used.
   * @param nickname Host nickname to validate.
   * @param error Output error message on failure.
   * @return True when the nickname is valid.
   */
  bool ValidateNickname(const std::string &nickname, std::string *error) const {
    if (nickname.empty()) {
      if (error) {
        *error = "Nickname cannot be empty.";
      }
      return false;
    }
    if (!std::regex_match(nickname, nickname_pattern_)) {
      if (error) {
        *error = "Nickname must contain only letters, numbers, _ or -.";
      }
      return false;
    }
    if (HostExists(nickname)) {
      if (error) {
        *error = "Nickname already exists.";
      }
      return false;
    }
    return true;
  }

private:
  /**
   * @brief Find a JSON node by walking a path.
   * @param root JSON root to search.
   * @param path Path segments leading to the target node.
   * @return Pointer to the node when found, otherwise nullptr.
   */
  [[nodiscard]] const nlohmann::ordered_json *
  FindJsonNode_(const nlohmann::ordered_json &root, const Path &path) const {
    const nlohmann::ordered_json *node = &root;
    for (const auto &seg : path) {
      if (!node->is_object()) {
        return nullptr;
      }
      auto it = node->find(seg);
      if (it == node->end()) {
        return nullptr;
      }
      node = &(*it);
    }
    return node;
  }

  AMConfigStorage *storage_ = nullptr;
  std::regex nickname_pattern_;
};

/**
 * @brief Style access layer for UI and formatting configuration.
 */
class AMConfigStyleData {
public:
  /**
   * @brief Construct a style layer with no bound storage.
   */
  AMConfigStyleData() = default;

  /**
   * @brief Bind the storage layer used for style configuration lookups.
   * @param storage Storage layer pointer.
   */
  void BindStorage(AMConfigStorage *storage) { storage_ = storage; }

  /**
   * @brief Apply a named style to a string with optional path context.
   * @param ori_str Original string.
   * @param style_name Style key name.
   * @param path_info Optional path info for styling decisions.
   * @return Styled string output.
   */
  [[nodiscard]] std::string Format(const std::string &ori_str,
                                   const std::string &style_name,
                                   const PathInfo *path_info = nullptr) const {
    (void)style_name;
    (void)path_info;
    if (!storage_) {
      return ori_str;
    }
    return ori_str;
  }

  /**
   * @brief Create a progress bar using the current style configuration.
   * @param total_size Total bytes for the progress bar.
   * @param prefix Prefix label displayed before the bar.
   * @return Configured progress bar instance.
   */
  [[nodiscard]] AMProgressBar
  CreateProgressBar(int64_t total_size, const std::string &prefix) const {
    return AMProgressBar(total_size, prefix);
  }

  /**
   * @brief Format a UTF-8 table using configured style defaults.
   * @param keys Column headers.
   * @param rows Row data.
   * @return Formatted table string.
   */
  [[nodiscard]] std::string
  FormatUtf8Table(const std::vector<std::string> &keys,
                  const std::vector<std::vector<std::string>> &rows) const {
    return AMStr::FormatUtf8Table(keys, rows);
  }

private:
  AMConfigStorage *storage_ = nullptr;
};

/**
 * @brief CLI exposure layer for configuration commands.
 */
class AMConfigCLIAdapter {
public:
  using SimpleCallback = std::function<ECM()>;
  using StringCallback = std::function<ECM(const std::string &)>;
  using StringsCallback = std::function<ECM(const std::vector<std::string> &)>;
  using RenameCallback =
      std::function<ECM(const std::string &, const std::string &)>;

  /**
   * @brief Construct an empty CLI adapter without callbacks.
   */
  AMConfigCLIAdapter() = default;

  /**
   * @brief Bind the list callback used by CLI.
   * @param cb Callback to invoke for list.
   */
  void SetListCallback(SimpleCallback cb) { list_cb_ = std::move(cb); }

  /**
   * @brief Bind the list-name callback used by CLI.
   * @param cb Callback to invoke for list-name.
   */
  void SetListNameCallback(SimpleCallback cb) { list_name_cb_ = std::move(cb); }

  /**
   * @brief Bind the add callback used by CLI.
   * @param cb Callback to invoke for add.
   */
  void SetAddCallback(SimpleCallback cb) { add_cb_ = std::move(cb); }

  /**
   * @brief Bind the modify callback used by CLI.
   * @param cb Callback to invoke for modify.
   */
  void SetModifyCallback(StringCallback cb) { modify_cb_ = std::move(cb); }

  /**
   * @brief Bind the delete-by-string callback used by CLI.
   * @param cb Callback to invoke for delete with raw string.
   */
  void SetDeleteCallback(StringCallback cb) { delete_cb_ = std::move(cb); }

  /**
   * @brief Bind the delete-by-list callback used by CLI.
   * @param cb Callback to invoke for delete with nickname list.
   */
  void SetDeleteListCallback(StringsCallback cb) {
    delete_list_cb_ = std::move(cb);
  }

  /**
   * @brief Bind the query-by-string callback used by CLI.
   * @param cb Callback to invoke for query with raw string.
   */
  void SetQueryCallback(StringCallback cb) { query_cb_ = std::move(cb); }

  /**
   * @brief Bind the query-by-list callback used by CLI.
   * @param cb Callback to invoke for query with nickname list.
   */
  void SetQueryListCallback(StringsCallback cb) {
    query_list_cb_ = std::move(cb);
  }

  /**
   * @brief Bind the rename callback used by CLI.
   * @param cb Callback to invoke for rename.
   */
  void SetRenameCallback(RenameCallback cb) { rename_cb_ = std::move(cb); }

  /**
   * @brief Bind the src callback used by CLI.
   * @param cb Callback to invoke for src.
   */
  void SetSrcCallback(SimpleCallback cb) { src_cb_ = std::move(cb); }

  /**
   * @brief List configuration entries for CLI output.
   * @return ECM success or failure.
   */
  [[nodiscard]] ECM List() const {
    return list_cb_ ? list_cb_() : MissingCallback_("List");
  }

  /**
   * @brief List configuration entry names for CLI output.
   * @return ECM success or failure.
   */
  [[nodiscard]] ECM ListName() const {
    return list_name_cb_ ? list_name_cb_() : MissingCallback_("ListName");
  }

  /**
   * @brief Add a new configuration entry through the CLI flow.
   * @return ECM success or failure.
   */
  [[nodiscard]] ECM Add() {
    return add_cb_ ? add_cb_() : MissingCallback_("Add");
  }

  /**
   * @brief Modify an existing configuration entry.
   * @param nickname Host nickname to modify.
   * @return ECM success or failure.
   */
  [[nodiscard]] ECM Modify(const std::string &nickname) {
    return modify_cb_ ? modify_cb_(nickname) : MissingCallback_("Modify");
  }

  /**
   * @brief Delete configuration entries specified by a raw CLI argument.
   * @param targets Raw target string.
   * @return ECM success or failure.
   */
  [[nodiscard]] ECM Delete(const std::string &targets) {
    return delete_cb_ ? delete_cb_(targets) : MissingCallback_("Delete");
  }

  /**
   * @brief Delete configuration entries specified by nickname list.
   * @param targets Nickname list.
   * @return ECM success or failure.
   */
  [[nodiscard]] ECM Delete(const std::vector<std::string> &targets) {
    return delete_list_cb_ ? delete_list_cb_(targets)
                           : MissingCallback_("DeleteList");
  }

  /**
   * @brief Query configuration entries specified by a raw CLI argument.
   * @param targets Raw target string.
   * @return ECM success or failure.
   */
  [[nodiscard]] ECM Query(const std::string &targets) const {
    return query_cb_ ? query_cb_(targets) : MissingCallback_("Query");
  }

  /**
   * @brief Query configuration entries specified by nickname list.
   * @param targets Nickname list.
   * @return ECM success or failure.
   */
  [[nodiscard]] ECM Query(const std::vector<std::string> &targets) const {
    return query_list_cb_ ? query_list_cb_(targets)
                          : MissingCallback_("QueryList");
  }

  /**
   * @brief Rename a configuration entry.
   * @param old_nickname Current nickname.
   * @param new_nickname New nickname.
   * @return ECM success or failure.
   */
  [[nodiscard]] ECM Rename(const std::string &old_nickname,
                           const std::string &new_nickname) {
    return rename_cb_ ? rename_cb_(old_nickname, new_nickname)
                      : MissingCallback_("Rename");
  }

  /**
   * @brief Print configuration source file locations for CLI.
   * @return ECM success or failure.
   */
  [[nodiscard]] ECM Src() const {
    return src_cb_ ? src_cb_() : MissingCallback_("Src");
  }

private:
  /**
   * @brief Build a standardized error response for missing callbacks.
   * @param action Action name being invoked.
   * @return ECM error response.
   */
  [[nodiscard]] ECM MissingCallback_(const std::string &action) const {
    return {EC::ConfigNotInitialized,
            AMStr::amfmt("ConfigCLIAdapter missing callback: {}", action)};
  }

  SimpleCallback list_cb_;
  SimpleCallback list_name_cb_;
  SimpleCallback add_cb_;
  SimpleCallback src_cb_;
  StringCallback modify_cb_;
  StringCallback delete_cb_;
  StringsCallback delete_list_cb_;
  StringCallback query_cb_;
  StringsCallback query_list_cb_;
  RenameCallback rename_cb_;
};

class AMConfigManager {
public:
  using Path = std::vector<std::string>;
  using Value =
      std::variant<int64_t, bool, std::string, std::vector<std::string>>;
  enum class ResolveArgType {
    TimeoutMs,
    RefreshIntervalMs,
    HeartbeatIntervalS,
    TraceNum,
    MaxHistoryCount
  };

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

  using KnownHostCallback = std::function<ECM(AMConfigManager::KnownHostEntry)>;

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
                                   const std::string &style_name,
                                   const PathInfo *path_info = nullptr) const;

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
  GetClientConfig(const std::string &nickname);
  /**
   * @brief Create a progress bar configured from style.ProgressBar settings.
   */
  [[nodiscard]] AMProgressBar
  CreateProgressBar(int64_t total_size, const std::string &prefix) const;
  /**
   * @brief Create a UTF-8 table using style.Table settings.
   */
  [[nodiscard]] std::string
  FormatUtf8Table(const std::vector<std::string> &keys,
                  const std::vector<std::vector<std::string>> &rows) const;
  [[nodiscard]] int GetSettingInt(const Path &path, int default_value) const;
  /**
   * @brief Resolve an integer setting by type with optional post-processing.
   */
  [[nodiscard]] int ResolveArg(ResolveArgType target_type,
                               int default_value) const;
  /**
   * @brief Resolve network timeout from settings with a default fallback.
   */
  [[nodiscard]] int ResolveTimeoutMs(int default_timeout_ms = 5000) const;
  /**
   * @brief Resolve transfer refresh interval from settings with defaults.
   */
  [[nodiscard]] int ResolveRefreshIntervalMs() const;
  /**
   * @brief Resolve heartbeat interval from settings with a default fallback.
   */
  [[nodiscard]] int ResolveHeartbeatInterval() const;
  /**
   * @brief Resolve trace buffer size from settings with sane defaults.
   */
  [[nodiscard]] ssize_t ResolveTraceNum() const;
  /** Return a string setting value or the provided default. */
  [[nodiscard]] std::string
  GetSettingString(const Path &path, const std::string &default_value) const;
  /**
   * @brief Query a UserVars entry by name.
   */
  bool GetUserVar(const std::string &name, std::string *value) const;
  /**
   * @brief List all UserVars entries.
   */
  [[nodiscard]] std::vector<std::pair<std::string, std::string>>
  ListUserVars() const;
  /**
   * @brief Set a UserVars entry and optionally persist to settings.
   */
  ECM SetUserVar(const std::string &name, const std::string &value,
                 bool dump_now = true);
  /**
   * @brief Remove a UserVars entry and optionally persist to settings.
   */
  ECM RemoveUserVar(const std::string &name, bool dump_now = true);
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
   * @brief Parse and set a host field from config set command arguments.
   */
  ECM SetHostValue(const std::string &nickname, const std::string &attrname,
                   const std::string &value);

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

  [[nodiscard]] bool HostExists(const std::string &nickname) const;

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
  ECM UpsertHostField(const std::string &nickname, const std::string &field,
                      Value value);
  ECM RemoveHost(const std::string &nickname);

  ECM PromptAddFields(std::string *nickname, HostEntry *entry);
  ECM PromptModifyFields(const std::string &nickname, HostEntry *entry);
  bool ParsePositiveInt(const std::string &input, int64_t *value) const;
  /**
   * @brief Build progress bar style from settings.
   */
  AMProgressBarStyle BuildProgressBarStyle_() const;

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
  AMPromptManager &prompt = AMPromptManager::Instance();

  std::mutex write_mtx_;
  std::condition_variable write_cv_;
  std::deque<std::function<void()>> write_queue_;
  std::thread write_thread_;
  std::atomic<bool> write_running_{false};
  std::mutex handle_mtx_;
  bool backup_prune_checked_ = false;
  mutable std::optional<AMProgressBarStyle> progress_bar_style_;

  bool initialized_ = false;
  bool exit_hook_installed_ = false;
  std::regex nickname_pattern = std::regex("^[A-Za-z0-9_]+$");
};
