#pragma once
#include "AMPromptManager.hpp"
#include "base/AMCommonTools.hpp"
#include "base/AMDataClass.hpp"
#include "base/AMEnum.hpp"
#include <filesystem>
#include <map>
#include <memory>
#include <string>
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

  static AMConfigManager &Instance();

  AMConfigManager(const AMConfigManager &) = delete;
  AMConfigManager &operator=(const AMConfigManager &) = delete;
  AMConfigManager(AMConfigManager &&) = delete;
  AMConfigManager &operator=(AMConfigManager &&) = delete;

  ECM Init();
  ECM Dump();

  [[nodiscard]] std::string Format(const std::string &ori_str,
                                   const std::string &style_name) const;

  [[nodiscard]] ECM List() const;
  [[nodiscard]] ECM ListName() const;
  [[nodiscard]] std::pair<ECM, std::vector<std::string>>
  PrivateKeys(bool print_sign = false) const;
  /** Return the project root directory path. */
  [[nodiscard]] std::filesystem::path ProjectRoot() const { return root_dir_; }
  [[nodiscard]] std::pair<ECM, ClientConfig>
  GetClientConfig(const std::string &nickname,
                  bool use_compression = false);
  [[nodiscard]] int GetSettingInt(const Path &path, int default_value) const;
  /** Return a string setting value or the provided default. */
  [[nodiscard]] std::string
  GetSettingString(const Path &path, const std::string &default_value) const;
  [[nodiscard]] ECM Src() const;
  [[nodiscard]] ECM Delete(const std::string &targets);
  [[nodiscard]] ECM Rename(const std::string &old_nickname,
                           const std::string &new_nickname);
  [[nodiscard]] ECM Query(const std::string &targets) const;
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

  std::filesystem::path root_dir_;
  std::filesystem::path config_path_;
  std::filesystem::path settings_path_;
  /** JSON schema path for config.toml filtering. */
  std::filesystem::path config_schema_path_;
  /** JSON schema path for settings.toml filtering. */
  std::filesystem::path settings_schema_path_;
  nlohmann::ordered_json config_json_;
  nlohmann::ordered_json settings_json_;
  ConfigHandle *config_handle_ = nullptr;
  ConfigHandle *settings_handle_ = nullptr;

  std::vector<FormatPath> config_filters_;
  std::vector<FormatPath> settings_filters_;

  bool initialized_ = false;
  bool exit_hook_installed_ = false;
};
