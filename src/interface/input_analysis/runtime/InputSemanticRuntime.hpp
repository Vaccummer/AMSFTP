#pragma once

#include "domain/client/ClientPort.hpp"
#include "domain/transfer/TransferDomainModel.hpp"
#include "domain/var/VarModel.hpp"

#include <cstddef>
#include <memory>
#include <string>
#include <vector>

namespace AMInterface::input {

class IInputSemanticRuntime {
public:
  using TaskID = AMDomain::transfer::TaskID;

  enum class TerminalNameState {
    OK = 0,
    Disconnected = 1,
    Unestablished = 2,
    Nonexistent = 3,
    ValidNew = 4,
    InvalidNew = 5,
  };

  struct ModePolicy {
    bool enable = true;
    bool use_async = false;
    size_t timeout_ms = 0;
    int delay_ms = 0;
  };

  struct HighlightPolicy {
    bool enable = true;
    size_t timeout_ms = 1000;
  };

  struct PromptPathOptions {
    ModePolicy complete = {};
    ModePolicy inline_hint = {};
    HighlightPolicy highlight = {};
  };

  virtual ~IInputSemanticRuntime() = default;

  [[nodiscard]] virtual AMDomain::client::ClientHandle
  CurrentClient() const = 0;
  [[nodiscard]] virtual std::string CurrentNickname() const = 0;
  [[nodiscard]] virtual AMDomain::client::ClientHandle LocalClient() const = 0;
  [[nodiscard]] virtual AMDomain::client::ClientHandle
  GetClient(const std::string &nickname) const = 0;

  [[nodiscard]] virtual std::vector<std::string> ListClientNames() const = 0;
  [[nodiscard]] virtual std::vector<std::string> ListHostNames() const = 0;
  [[nodiscard]] virtual std::vector<std::string> ListPoolNames() const = 0;
  [[nodiscard]] virtual std::vector<std::string> ListTerminalNames() const = 0;
  [[nodiscard]] virtual std::vector<std::string>
  ListTermNames(const std::string &client_name) const = 0;
  [[nodiscard]] virtual bool HostExists(const std::string &nickname) const = 0;
  [[nodiscard]] virtual bool PoolExists(const std::string &nickname) const = 0;
  [[nodiscard]] virtual bool
  TerminalExists(const std::string &nickname) const = 0;
  [[nodiscard]] virtual TerminalNameState
  QueryTerminalClientNameState(const std::string &client_name) const = 0;
  [[nodiscard]] virtual TerminalNameState
  QueryTermNameState(const std::string &client_name,
                     const std::string &term_name, bool allow_new) const = 0;

  [[nodiscard]] virtual std::vector<std::string> ListVarDomains() const = 0;
  [[nodiscard]] virtual bool HasVarDomain(const std::string &zone) const = 0;
  [[nodiscard]] virtual std::string CurrentVarDomain() const = 0;
  [[nodiscard]] virtual std::vector<AMDomain::var::VarInfo>
  ListVarsByDomain(const std::string &domain) const = 0;
  [[nodiscard]] virtual ECMData<AMDomain::var::VarInfo>
  GetVar(const std::string &zone, const std::string &varname) const = 0;

  [[nodiscard]] virtual std::vector<TaskID> ListTaskIDs() const = 0;
  [[nodiscard]] virtual std::vector<TaskID> ListPausedTaskIDs() const = 0;

  [[nodiscard]] virtual PromptPathOptions
  ResolvePromptPathOptions(const std::string &nickname) const = 0;
  [[nodiscard]] virtual std::string
  SubstitutePathLike(const std::string &raw) const = 0;
  [[nodiscard]] virtual std::string
  BuildPath(AMDomain::client::ClientHandle client,
            const std::string &raw_path) const = 0;
  [[nodiscard]] virtual ECMData<PathInfo>
  StatPath(AMDomain::client::ClientHandle client, const std::string &abs_path,
           int timeout_ms) const = 0;
};

using InputSemanticRuntimePtr = std::shared_ptr<IInputSemanticRuntime>;

} // namespace AMInterface::input
