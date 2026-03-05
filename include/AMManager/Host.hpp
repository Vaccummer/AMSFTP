#pragma once
#include "domain/host/HostModel.hpp"
#include <string>
#include <unordered_map>
#include <vector>

class AMHostManager : public NonCopyableNonMovable {
public:
  explicit AMHostManager() = default;

  static AMHostManager &Instance() {
    static AMHostManager instance;
    return instance;
  }

  ECM Init() override {
    CollectHosts_();
    return Ok();
  }

  [[nodiscard]] std::pair<ECM, HostConfig>
  GetClientConfig(const std::string &nickname);

  /**
   * @brief Fetch local client config from storage and fall back to defaults.
   */
  [[nodiscard]] std::pair<ECM, HostConfig> GetLocalConfig();

  ECM UpsertHost(const HostConfig &entry, bool dump_now = true);

  [[nodiscard]] ECM FindKnownHost(KnownHostQuery &query) const;
  ECM UpsertKnownHost(const KnownHostQuery &query, bool dump_now = true);

  [[nodiscard]] bool HostExists(const std::string &nickname) const;

  [[nodiscard]] std::vector<std::string> ListNames() const;

  void CollectHosts_() const;

  [[nodiscard]] std::pair<ECM, std::vector<std::string>>
  PrivateKeys(bool print_sign = false) const;
  ECM List(bool detailed = true) const;
  ECM Add(const std::string &nickname = "");
  ECM Modify(const std::string &nickname);
  ECM Delete(const std::string &nickname);
  ECM Delete(const std::vector<std::string> &targets);
  ECM Query(const std::string &targets) const;
  ECM Query(const std::vector<std::string> &targets) const;
  ECM Rename(const std::string &old_nickname, const std::string &new_nickname);
  ECM Src() const;

  ECM SetHostValue(const std::string &nickname, const std::string &attrname,
                   const std::string &value_str);
  [[nodiscard]] ECM Save();

private:
  mutable std::unordered_map<std::string, HostConfig> host_configs = {};
  mutable std::unordered_map<std::string, KnownHostEntry> known_hosts = {};
  [[nodiscard]] ECM PrintHost_(const std::string &nickname,
                               const HostConfig &entry) const;
  ECM PromptAddFields_(const std::string &nickname, HostConfig &entry);
  ECM PromptModifyFields_(const std::string &nickname, HostConfig &entry);
  ECM AddHost_(const std::string &nickname, const HostConfig &entry);
  ECM RemoveHost_(const std::string &nickname);
};
