#pragma once

#include "application/client/ClientAppService.hpp"
#include "application/host/HostAppService.hpp"
#include "application/prompt/PromptProfileManager.hpp"
#include "application/var/VarAppService.hpp"
#include "domain/transfer/TransferPort.hpp"
#include "interface/adapters/var/VarInterfaceService.hpp"
#include "interface/completion/CompletionRuntime.hpp"
#include "interface/style/StyleManager.hpp"

namespace AMInterface::completion {

class CompletionRuntimeAdapter final : public ICompletionRuntime {
public:
  CompletionRuntimeAdapter(
      AMApplication::client::ClientAppService &client_service,
      AMApplication::host::HostAppService &host_service,
      AMApplication::var::VarAppService &var_service,
      AMInterface::var::VarInterfaceService &var_interface_service,
      AMInterface::style::AMStyleService &style_service,
      AMApplication::prompt::PromptProfileManager &prompt_profile_manager,
      AMDomain::transfer::ITransferPoolPort &transfer_pool)
      : client_service_(client_service), host_service_(host_service),
        var_service_(var_service), var_interface_service_(var_interface_service),
        style_service_(style_service),
        prompt_profile_manager_(prompt_profile_manager),
        transfer_pool_(transfer_pool) {}
  ~CompletionRuntimeAdapter() override = default;

  [[nodiscard]] AMDomain::client::ClientHandle CurrentClient() const override;
  [[nodiscard]] AMDomain::client::ClientHandle LocalClient() const override;
  [[nodiscard]] AMDomain::client::ClientHandle
  GetClient(const std::string &nickname) const override;

  [[nodiscard]] std::vector<std::string> ListClientNames() const override;
  [[nodiscard]] std::vector<std::string> ListHostNames() const override;
  [[nodiscard]] bool HostExists(const std::string &nickname) const override;

  [[nodiscard]] std::vector<std::string> ListVarDomains() const override;
  [[nodiscard]] bool HasVarDomain(const std::string &zone) const override;
  [[nodiscard]] std::string CurrentVarDomain() const override;
  [[nodiscard]] std::vector<AMDomain::var::VarInfo>
  ListVarsByDomain(const std::string &domain) const override;

  [[nodiscard]] std::vector<std::string> ListTaskIds() const override;

  [[nodiscard]] PromptPathOptions
  ResolvePromptPathOptions(const std::string &nickname) const override;
  [[nodiscard]] std::string
  SubstitutePathLike(const std::string &raw) const override;
  [[nodiscard]] std::string
  BuildPath(AMDomain::client::ClientHandle client,
            const std::string &raw_path) const override;
  [[nodiscard]] std::string
  Format(const std::string &text,
         AMInterface::style::StyleIndex style_index) const override;
  [[nodiscard]] std::string
  FormatPath(const std::string &segment,
             const PathInfo *path_info) const override;

private:
  AMApplication::client::ClientAppService &client_service_;
  AMApplication::host::HostAppService &host_service_;
  AMApplication::var::VarAppService &var_service_;
  AMInterface::var::VarInterfaceService &var_interface_service_;
  AMInterface::style::AMStyleService &style_service_;
  AMApplication::prompt::PromptProfileManager &prompt_profile_manager_;
  AMDomain::transfer::ITransferPoolPort &transfer_pool_;
};

} // namespace AMInterface::completion
