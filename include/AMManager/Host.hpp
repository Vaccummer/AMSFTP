#pragma once
#include "AMBase/DataClass.hpp"
#include "AMManager/Config.hpp"
#include <cstdint>
#include <unordered_map>

struct ClientConfig {
  ConRequst request = {};
  ClientProtocol protocol = ClientProtocol::SFTP;
  int64_t buffer_size = -1;
  std::string login_dir = "";
  [[nodiscard]] std::unordered_map<std::string, std::string>
  GetStrDict() const {
    return {
        {"hostname", request.hostname},
        {"username", request.username},
        {"port", std::to_string(request.port)},
        {"password", request.password},
        {"protocol", AM_ENUM_NAME(protocol)},
        {"buffer_size", std::to_string(buffer_size)},
        {"trash_dir", request.trash_dir},
        {"login_dir", login_dir},
        {"keyfile", request.keyfile},
        {"compression", request.compression ? "true" : "false"},
    };
  }
};

struct KnownHostEntry {
  std::string nickname;
  std::string hostname;
  int port = 0;
  std::string protocol;
  std::string fingerprint;
  std::string fingerprint_sha256;
};

inline ClientProtocol StrToProtocol(const std::string &protocol_str) {
  auto it = protocol_map.find(AMStr::lowercase(protocol_str));
  if (it != protocol_map.end()) {
    return it->second;
  } else {
    return ClientProtocol::SFTP;
  }
}

class AMHostManager {
public:
  const std::array<std::string, 10> kHostFields = {
      "hostname",    "username",  "port",      "password", "protocol",
      "buffer_size", "trash_dir", "login_dir", "keyfile",  "compression",
  };
  using Path = std::vector<std::string>;
  using Value =
      std::variant<int64_t, bool, std::string, std::vector<std::string>>;

  explicit AMHostManager(AMConfigManager &config);

  [[nodiscard]] std::pair<ECM, ClientConfig>
  GetClientConfig(const std::string &nickname);

  [[nodiscard]] std::pair<ECM, std::optional<KnownHostEntry>>
  FindKnownHost(const std::string &hostname, int port,
                const std::string &protocol) const;

  [[nodiscard]] bool HostExists(const std::string &nickname) const;
  [[nodiscard]] bool ValidateNickname(const std::string &nickname) const;

  void CollectHosts_() const;

  template <typename T>
  ECM SetHostField(const std::string &nickname, const std::string &field,
                   const T &value, bool dump_now = true) {
    if (!config_.SetArg(DocumentKind::Config, {"HOSTS", nickname, field},
                        value)) {
      return {EC::CommonFailure, "failed to set host field"};
    }
    if (dump_now) {
      config_.Dump(DocumentKind::Config, "", true);
    }
    return Ok();
  };

  ECM SetHostConfigField(const std::string &nickname, const std::string &field,
                         const std::variant<int64_t, bool, std::string,
                                            std::vector<std::string>> &value);

  [[nodiscard]] std::vector<std::string> ListHostnames() const;

  [[nodiscard]] std::pair<ECM, std::vector<std::string>>
  PrivateKeys(bool print_sign = false) const;

  ECM List(bool detailed = true) const;
  ECM ListName() const;
  ECM Add();
  ECM Modify(const std::string &nickname);
  ECM Delete(const std::string &nickname);
  ECM Delete(const std::vector<std::string> &targets);
  ECM Query(const std::string &targets) const;
  ECM Query(const std::vector<std::string> &targets) const;
  ECM Rename(const std::string &old_nickname, const std::string &new_nickname);
  ECM Src() const;

  ECM SetHostValue(const std::string &nickname, const std::string &attrname,
                   const std::string &value_str);

private:
  [[nodiscard]] ECM EnsureReady_(const char *caller) const;
  [[nodiscard]] ECM SaveConfig_(bool async = false);
  [[nodiscard]] ECM SaveAll_(bool async = false);
  [[nodiscard]] bool
  GetDocumentJson_(DocumentKind kind, nlohmann::ordered_json *value) const;
  [[nodiscard]] bool GetDocumentPath_(DocumentKind kind,
                                      std::filesystem::path *value) const;
  [[nodiscard]] std::string FormatValue_(
      const std::string &text, const std::string &style_name,
      const PathInfo *path_info = nullptr) const;
  [[nodiscard]] std::string ProtocolToString_(ClientProtocol protocol) const;
  [[nodiscard]] std::string ValueToString_(const Value &value) const;
  ECM PersistHostConfig_(const std::string &nickname, const ClientConfig &entry,
                         bool dump_now);

  mutable std::unordered_map<std::string, ClientConfig> host_configs = {};
  [[nodiscard]] ECM PrintHost_(const std::string &nickname,
                               const ClientConfig &entry) const;
  ECM PromptAddFields_(const std::string &nickname, ClientConfig &entry);
  ECM PromptModifyFields_(const std::string &nickname, ClientConfig &entry);
  ECM RemoveHost_(const std::string &nickname);
  AMConfigManager &config_;
  AMPromptManager &prompt_;
};
