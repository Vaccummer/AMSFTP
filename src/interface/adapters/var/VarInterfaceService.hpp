#pragma once

#include "application/client/ClientAppService.hpp"
#include "application/var/VarAppService.hpp"
#include "foundation/core/DataClass.hpp"
#include "interface/prompt/Prompt.hpp"

namespace AMInterface::var {
using VarAppService = AMApplication::var::VarAppService;
using ClientAppService = AMApplication::client::ClientAppService;
using PromptIOManager = AMInterface::prompt::PromptIOManager;
using ParsedVarToken = AMDomain::var::ParsedVarToken;
using VarInfo = AMDomain::var::VarInfo;
using AllVarInfoMap = AMApplication::var::AllVarInfoMap;

class VarInterfaceService final : public NonCopyableNonMovable {
public:
  VarInterfaceService(VarAppService &var_service,
                      ClientAppService &client_service,
                      PromptIOManager &prompt_io_manager);
  ~VarInterfaceService() override = default;

  [[nodiscard]] ECMData<ParsedVarToken>
  ParseVarTokenExpression(const std::string &expr) const;
  [[nodiscard]] ECMData<VarInfo>
  ResolveLookupToken(const std::string &token_expr) const;
  [[nodiscard]] ECMData<VarInfo>
  ResolveDefineTarget(bool global, const std::string &token_expr) const;
  [[nodiscard]] ECM QueryAndPrintVar(const std::string &token_expr) const;
  [[nodiscard]] ECM DefineVar(bool global, const std::string &token_expr,
                              const std::string &value) const;
  [[nodiscard]] ECM DeleteVar(bool all,
                              const std::vector<std::string> &tokens) const;
  [[nodiscard]] ECM ListVars(const std::vector<std::string> &sections) const;
  [[nodiscard]] std::string SubstitutePathLike(const std::string &raw) const;
  [[nodiscard]] std::vector<std::string>
  SubstitutePathLike(const std::vector<std::string> &raw) const;
  void VSubstitutePathLike(std::string &raw) const;
  void VSubstitutePathLike(std::vector<std::string> &raw) const;
  bool RewriteVarShortcutTokens(std::vector<std::string> *tokens) const;

private:
  [[nodiscard]] std::string ResolveCurrentDomain_() const;
  [[nodiscard]] ECMData<std::string>
  LookupVarValue_(const ParsedVarToken &token,
                  const AllVarInfoMap &all_vars) const;
  [[nodiscard]] std::string
  SubstitutePathLikeWithSnapshot_(const std::string &raw,
                                  const AllVarInfoMap &all_vars) const;

  VarAppService &var_service_;
  ClientAppService &client_service_;
  PromptIOManager &prompt_io_manager_;
};
} // namespace AMInterface::var
