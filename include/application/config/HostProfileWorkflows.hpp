#pragma once

#include "foundation/DataClass.hpp"
#include <string>
#include <vector>

namespace AMApplication::HostProfileWorkflow {
/**
 * @brief Port for host-config and profile operations.
 */
class IHostProfileGateway {
public:
  /**
   * @brief Virtual destructor for polymorphic gateway.
   */
  virtual ~IHostProfileGateway() = default;

  /**
   * @brief Return whether one host nickname exists.
   */
  [[nodiscard]] virtual bool HostExists(const std::string &nickname) const = 0;

  /**
   * @brief List hosts.
   */
  virtual ECM ListHosts(bool detail) = 0;

  /**
   * @brief List configured key files.
   */
  virtual ECM ListPrivateKeys(bool detail) = 0;

  /**
   * @brief Show host configuration source payload.
   */
  virtual ECM ShowConfigSource() = 0;

  /**
   * @brief Query one or more host entries.
   */
  virtual ECM QueryHosts(const std::vector<std::string> &nicknames) = 0;

  /**
   * @brief Add one host entry.
   */
  virtual ECM AddHost(const std::string &nickname) = 0;

  /**
   * @brief Edit one host entry.
   */
  virtual ECM EditHost(const std::string &nickname) = 0;

  /**
   * @brief Rename one host entry.
   */
  virtual ECM RenameHost(const std::string &old_name,
                         const std::string &new_name) = 0;

  /**
   * @brief Remove host entries.
   */
  virtual ECM RemoveHosts(const std::vector<std::string> &nicknames) = 0;

  /**
   * @brief Set one host attribute value.
   */
  virtual ECM SetHostValue(const std::string &nickname,
                           const std::string &attrname,
                           const std::string &value) = 0;

  /**
   * @brief Persist host configuration.
   */
  virtual ECM SaveHosts() = 0;

  /**
   * @brief Set active profile nickname.
   */
  virtual ECM EditProfile(const std::string &nickname) = 0;

  /**
   * @brief Query one or more profiles.
   */
  virtual ECM GetProfiles(const std::vector<std::string> &nicknames) = 0;
};

/**
 * @brief Port for current client/session state.
 */
class ICurrentClientPort {
public:
  /**
   * @brief Virtual destructor for polymorphic state reader.
   */
  virtual ~ICurrentClientPort() = default;

  /**
   * @brief Return current active nickname or empty when unavailable.
   */
  [[nodiscard]] virtual std::string CurrentNickname() const = 0;
};

/**
 * @brief Validate nickname for config-add flow.
 */
ECM ValidateConfigAddNickname(const IHostProfileGateway &gateway,
                              const std::string &raw,
                              std::string *normalized);

/**
 * @brief Validate nickname for profile-set flow.
 */
ECM ValidateConfigProfileNickname(const IHostProfileGateway &gateway,
                                  const std::string &raw,
                                  std::string *normalized);

/**
 * @brief Resolve query targets for config-get.
 */
std::vector<std::string>
ResolveConfigGetTargets(const ICurrentClientPort &client_port,
                        const std::vector<std::string> &nicknames);

/**
 * @brief Execute config ls workflow.
 */
ECM ExecuteConfigLs(IHostProfileGateway &gateway, bool detail);

/**
 * @brief Execute config keys workflow.
 */
ECM ExecuteConfigKeys(IHostProfileGateway &gateway, bool detail = true);

/**
 * @brief Execute config data workflow.
 */
ECM ExecuteConfigData(IHostProfileGateway &gateway);

/**
 * @brief Execute config get workflow.
 */
ECM ExecuteConfigGet(IHostProfileGateway &gateway,
                     const ICurrentClientPort &client_port,
                     const std::vector<std::string> &nicknames);

/**
 * @brief Execute config add workflow with validated nickname.
 */
ECM ExecuteConfigAdd(IHostProfileGateway &gateway, const std::string &nickname);

/**
 * @brief Execute config edit workflow.
 */
ECM ExecuteConfigEdit(IHostProfileGateway &gateway,
                      const std::string &nickname);

/**
 * @brief Execute config rename workflow.
 */
ECM ExecuteConfigRename(IHostProfileGateway &gateway,
                        const std::string &old_name,
                        const std::string &new_name);

/**
 * @brief Execute config remove workflow.
 */
ECM ExecuteConfigRemove(IHostProfileGateway &gateway,
                        const std::vector<std::string> &nicknames);

/**
 * @brief Execute config set workflow.
 */
ECM ExecuteConfigSet(IHostProfileGateway &gateway, const std::string &nickname,
                     const std::string &attrname, const std::string &value);

/**
 * @brief Execute config save workflow.
 */
ECM ExecuteConfigSave(IHostProfileGateway &gateway);

/**
 * @brief Execute config profile set workflow with validated nickname.
 */
ECM ExecuteConfigProfileSet(IHostProfileGateway &gateway,
                            const std::string &nickname);

/**
 * @brief Execute profile edit workflow.
 */
ECM ExecuteProfileEdit(IHostProfileGateway &gateway,
                       const std::string &nickname);

/**
 * @brief Execute profile get workflow.
 */
ECM ExecuteProfileGet(IHostProfileGateway &gateway,
                      const std::vector<std::string> &nicknames);
} // namespace AMApplication::HostProfileWorkflow
