#include "application/host/HostProfileWorkflows.hpp"

#include "domain/host/HostDomainService.hpp"
#include "domain/host/HostModel.hpp"
#include "foundation/tools/enum_related.hpp"
#include "foundation/tools/string.hpp"

namespace AMApplication::HostProfileWorkflow {
/**
 * @brief Validate nickname for config-add flow.
 */
ECM ValidateConfigAddNickname(const IHostProfileGateway &gateway,
                              const std::string &raw,
                              std::string *normalized) {
  if (!normalized) {
    return Err(EC::InvalidArg, "null nickname output");
  }
  std::string value = AMStr::Strip(raw);
  ECM validate_rcm = AMDomain::host::HostService::ValidateFieldValue(
      AMDomain::host::ConRequest::Attr::nickname, value);
  if (!isok(validate_rcm)) {
    return validate_rcm;
  }
  if (AMStr::lowercase(value) == "local") {
    return Err(EC::InvalidArg, "Nickname 'local' is reserved");
  }
  if (gateway.HostExists(value)) {
    return Err(EC::InvalidArg, "Nickname already exists");
  }
  *normalized = value;
  return Ok();
}

/**
 * @brief Validate nickname for profile-set flow.
 */
ECM ValidateConfigProfileNickname(const IHostProfileGateway &gateway,
                                  const std::string &raw,
                                  std::string *normalized) {
  if (!normalized) {
    return Err(EC::InvalidArg, "null nickname output");
  }
  std::string value = AMStr::Strip(raw);
  if (value.empty()) {
    return Err(EC::InvalidArg, "empty profile nickname");
  }
  if (!AMDomain::host::HostService::ValidateNickname(value)) {
    return Err(EC::InvalidArg, "invalid profile nickname");
  }
  if (!gateway.HostExists(value)) {
    return Err(EC::HostConfigNotFound,
               AMStr::fmt("host nickname not found: {}", value));
  }
  *normalized = value;
  return Ok();
}

/**
 * @brief Resolve query targets for config-get.
 */
std::vector<std::string>
ResolveConfigGetTargets(const ICurrentClientPort &client_port,
                        const std::vector<std::string> &nicknames) {
  if (!nicknames.empty()) {
    return nicknames;
  }
  std::string current = client_port.CurrentNickname();
  if (current.empty()) {
    current = "local";
  }
  return {current};
}

/**
 * @brief Execute config ls workflow.
 */
ECM ExecuteConfigLs(IHostProfileGateway &gateway, bool detail) {
  return gateway.ListHosts(detail);
}

/**
 * @brief Execute config keys workflow.
 */
ECM ExecuteConfigKeys(IHostProfileGateway &gateway, bool detail) {
  return gateway.ListPrivateKeys(detail);
}

/**
 * @brief Execute config data workflow.
 */
ECM ExecuteConfigData(IHostProfileGateway &gateway) {
  return gateway.ShowConfigSource();
}

/**
 * @brief Execute config get workflow.
 */
ECM ExecuteConfigGet(IHostProfileGateway &gateway,
                     const ICurrentClientPort &client_port,
                     const std::vector<std::string> &nicknames) {
  return gateway.QueryHosts(ResolveConfigGetTargets(client_port, nicknames));
}

/**
 * @brief Execute config add workflow with validated nickname.
 */
ECM ExecuteConfigAdd(IHostProfileGateway &gateway,
                     const std::string &nickname) {
  std::string resolved;
  ECM rcm = ValidateConfigAddNickname(gateway, nickname, &resolved);
  if (!isok(rcm)) {
    return rcm;
  }
  return gateway.AddHost(resolved);
}

/**
 * @brief Execute config edit workflow.
 */
ECM ExecuteConfigEdit(IHostProfileGateway &gateway,
                      const std::string &nickname) {
  return gateway.EditHost(nickname);
}

/**
 * @brief Execute config rename workflow.
 */
ECM ExecuteConfigRename(IHostProfileGateway &gateway,
                        const std::string &old_name,
                        const std::string &new_name) {
  return gateway.RenameHost(old_name, new_name);
}

/**
 * @brief Execute config remove workflow.
 */
ECM ExecuteConfigRemove(IHostProfileGateway &gateway,
                        const std::vector<std::string> &nicknames) {
  return gateway.RemoveHosts(nicknames);
}

/**
 * @brief Execute config set workflow.
 */
ECM ExecuteConfigSet(IHostProfileGateway &gateway, const std::string &nickname,
                     const std::string &attrname, const std::string &value) {
  return gateway.SetHostValue(nickname, attrname, value);
}

/**
 * @brief Execute config save workflow.
 */
ECM ExecuteConfigSave(IHostProfileGateway &gateway) {
  return gateway.SaveHosts();
}

/**
 * @brief Execute config profile set workflow with validated nickname.
 */
ECM ExecuteConfigProfileSet(IHostProfileGateway &gateway,
                            const std::string &nickname) {
  std::string resolved;
  ECM rcm = ValidateConfigProfileNickname(gateway, nickname, &resolved);
  if (!isok(rcm)) {
    return rcm;
  }
  return gateway.EditProfile(resolved);
}

/**
 * @brief Execute profile edit workflow.
 */
ECM ExecuteProfileEdit(IHostProfileGateway &gateway,
                       const std::string &nickname) {
  return gateway.EditProfile(nickname);
}

/**
 * @brief Execute profile get workflow.
 */
ECM ExecuteProfileGet(IHostProfileGateway &gateway,
                      const std::vector<std::string> &nicknames) {
  return gateway.GetProfiles(nicknames);
}
} // namespace AMApplication::HostProfileWorkflow
