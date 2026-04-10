#pragma once

#include "application/client/ClientAppService.hpp"
#include "application/host/HostAppService.hpp"
#include "application/prompt/PromptProfileManager.hpp"
#include "application/terminal/TermAppService.hpp"
#include "application/var/VarAppService.hpp"
#include "interface/adapters/var/VarInterfaceService.hpp"
#include "interface/token_analyser/TokenAnalyzerRuntime.hpp"
#include "interface/style/StyleManager.hpp"

namespace AMInterface::parser {

class TokenAnalyzerRuntimeAdapter final : public ITokenAnalyzerRuntime {
public:
  TokenAnalyzerRuntimeAdapter(
      AMApplication::client::ClientAppService &client_service,
      AMApplication::host::HostAppService &host_service,
      AMApplication::terminal::TermAppService &terminal_service,
      AMApplication::var::VarAppService &var_service,
      AMInterface::var::VarInterfaceService &var_interface_service,
      AMInterface::style::AMStyleService &style_service,
      AMApplication::prompt::PromptProfileManager &prompt_profile_manager)
      : client_service_(client_service), host_service_(host_service),
        terminal_service_(terminal_service), var_service_(var_service),
        var_interface_service_(var_interface_service), style_service_(style_service),
        prompt_profile_manager_(prompt_profile_manager) {}
  ~TokenAnalyzerRuntimeAdapter() override = default;

  [[nodiscard]] AMDomain::client::ClientHandle CurrentClient() const override;
  [[nodiscard]] AMDomain::client::ClientHandle LocalClient() const override;
  [[nodiscard]] AMDomain::client::ClientHandle
  GetClient(const std::string &nickname) const override;
  [[nodiscard]] std::string CurrentNickname() const override;
  [[nodiscard]] bool HostExists(const std::string &nickname) const override;
  [[nodiscard]] bool TerminalExists(const std::string &nickname) const override;
  [[nodiscard]] TerminalNameState
  QueryTerminalNameState(const std::string &nickname) const override;
  [[nodiscard]] ChannelNameState
  QueryChannelNameState(const std::string &nickname,
                        const std::string &channel_name,
                        bool allow_new) const override;
  [[nodiscard]] bool HasVarDomain(const std::string &zone) const override;
  [[nodiscard]] std::string CurrentVarDomain() const override;
  [[nodiscard]] ECMData<AMDomain::var::VarInfo>
  GetVar(const std::string &zone, const std::string &varname) const override;
  [[nodiscard]] PromptPathOptions
  ResolvePromptPathOptions(const std::string &nickname) const override;
  [[nodiscard]] std::string
  SubstitutePathLike(const std::string &raw) const override;
  [[nodiscard]] std::string
  BuildPath(AMDomain::client::ClientHandle client,
            const std::string &raw_path) const override;
  [[nodiscard]] ECMData<PathInfo>
  StatPath(AMDomain::client::ClientHandle client, const std::string &abs_path,
           int timeout_ms) const override;
  [[nodiscard]] std::string
  FormatPath(const std::string &segment,
             const PathInfo *path_info) const override;
  [[nodiscard]] std::string
  ResolveInputHighlightStyle(AMTokenType type,
                             const std::string &default_value) const override;
  [[nodiscard]] std::string
  ResolvePathHighlightStyle(AMTokenType type,
                            const std::string &default_value) const override;

private:
  AMApplication::client::ClientAppService &client_service_;
  AMApplication::host::HostAppService &host_service_;
  AMApplication::terminal::TermAppService &terminal_service_;
  AMApplication::var::VarAppService &var_service_;
  AMInterface::var::VarInterfaceService &var_interface_service_;
  AMInterface::style::AMStyleService &style_service_;
  AMApplication::prompt::PromptProfileManager &prompt_profile_manager_;
};

} // namespace AMInterface::parser

