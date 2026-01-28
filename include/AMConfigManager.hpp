#pragma once
#include "AMCommonTools.hpp"
#include "AMPromptManager.hpp"
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
  using Status = std::pair<std::string, int>;
  using Path = AMConfigProcessor::Path;
  using Value = AMConfigProcessor::Value;
  using FlatMap = AMConfigProcessor::FlatMap;
  using FormatPath = AMConfigProcessor::FormatPath;

  struct ClientConfig {
    ConRequst request;
    ClientProtocol protocol = ClientProtocol::SFTP;
    int64_t buffer_size = -1;
  };

  static AMConfigManager &Instance();

  AMConfigManager(const AMConfigManager &) = delete;
  AMConfigManager &operator=(const AMConfigManager &) = delete;
  AMConfigManager(AMConfigManager &&) = delete;
  AMConfigManager &operator=(AMConfigManager &&) = delete;

  Status SetConfigFilters(const std::vector<FormatPath> &filters);
  Status SetSettingsFilters(const std::vector<FormatPath> &filters);

  Status Init();
  Status Dump();

  [[nodiscard]] std::string Format(const std::string &ori_str,
                                   const std::string &style_name) const;

  [[nodiscard]] Status List() const;
  [[nodiscard]] Status ListName() const;
  [[nodiscard]] std::pair<Status, std::vector<std::string>>
  PrivateKeys(bool print_sign = false) const;
  /** Return the project root directory path. */
  [[nodiscard]] std::filesystem::path ProjectRoot() const { return root_dir_; }
  [[nodiscard]] std::pair<Status, ClientConfig>
  GetClientConfig(const std::string &nickname,
                  bool use_compression = false) const;
  [[nodiscard]] int GetSettingInt(const Path &path, int default_value) const;
  /** Return a string setting value or the provided default. */
  [[nodiscard]] std::string
  GetSettingString(const Path &path, const std::string &default_value) const;
  [[nodiscard]] Status Src() const;
  [[nodiscard]] Status Delete(const std::string &nickname);
  [[nodiscard]] Status Rename(const std::string &old_nickname,
                              const std::string &new_nickname);
  [[nodiscard]] Status Query(const std::string &nickname) const;
  [[nodiscard]] Status Add();
  [[nodiscard]] Status Modify(const std::string &nickname);
  /**
   * @brief Persist an encrypted password for a given client nickname.
   */
  Status SetClientPasswordEncrypted(const std::string &nickname,
                                    const std::string &encrypted_password,
                                    bool dump_now = true);

private:
  AMConfigManager() = default;

  struct HostEntry {
    std::map<std::string, Value> fields;
  };

  static void OnExit();
  Status EnsureInitialized(const char *caller) const;
  [[nodiscard]] std::string ValueToString(const Value &value) const;
  [[nodiscard]] std::string StyledValue(const std::string &value,
                                        const std::string &style_name) const;
  [[nodiscard]] std::string MaybeStyle(const std::string &value,
                                       const std::string &style_name) const;
  [[nodiscard]] std::map<std::string, HostEntry> CollectHosts() const;
  [[nodiscard]] Status PrintHost(const std::string &nickname,
                                 const HostEntry &entry) const;
  [[nodiscard]] bool HostExists(const std::string &nickname) const;
  Status UpsertHostField(const std::string &nickname, const std::string &field,
                         Value value);
  Status RemoveHost(const std::string &nickname);

  Status PromptAddFields(std::string *nickname, HostEntry *entry);
  Status PromptModifyFields(const std::string &nickname, HostEntry *entry);

  bool PromptLine(const std::string &prompt, std::string *out,
                  const std::string &default_value, bool allow_empty,
                  bool *canceled, bool show_default = true) const;
  bool PromptYesNo(const std::string &prompt, bool *canceled) const;
  bool ParsePositiveInt(const std::string &input, int64_t *value) const;
  bool ValidateNickname(const std::string &nickname, std::string *error) const;

  std::filesystem::path root_dir_;
  std::filesystem::path config_path_;
  std::filesystem::path settings_path_;
  toml::table config_table_;
  toml::table settings_table_;

  std::vector<FormatPath> config_filters_;
  std::vector<FormatPath> settings_filters_;

  bool initialized_ = false;
  bool exit_hook_installed_ = false;
};
