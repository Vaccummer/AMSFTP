#pragma once

#include "domain/client/ClientPort.hpp"
#include "domain/transfer/TransferDomainModel.hpp"
#include "domain/var/VarModel.hpp"
#include "interface/style/StyleIndex.hpp"
#include <cstddef>
#include <memory>
#include <string>
#include <vector>

namespace AMInterface::completion {
using TASKID = AMDomain::transfer::TaskInfo::ID;
class ICompletionRuntime {
public:
  struct ModePolicy {
    bool enable = true;
    bool use_async = false;
    size_t timeout_ms = 0;
    int delay_ms = 0;
  };

  struct PromptPathOptions {
    ModePolicy complete = {};
    ModePolicy inline_hint = {};
  };

  virtual ~ICompletionRuntime() = default;

  [[nodiscard]] virtual AMDomain::client::ClientHandle
  CurrentClient() const = 0;
  [[nodiscard]] virtual AMDomain::client::ClientHandle LocalClient() const = 0;
  [[nodiscard]] virtual AMDomain::client::ClientHandle
  GetClient(const std::string &nickname) const = 0;

  [[nodiscard]] virtual std::vector<std::string> ListClientNames() const = 0;
  [[nodiscard]] virtual std::vector<std::string> ListHostNames() const = 0;
  [[nodiscard]] virtual bool HostExists(const std::string &nickname) const = 0;

  [[nodiscard]] virtual std::vector<std::string> ListVarDomains() const = 0;
  [[nodiscard]] virtual bool HasVarDomain(const std::string &zone) const = 0;
  [[nodiscard]] virtual std::string CurrentVarDomain() const = 0;
  [[nodiscard]] virtual std::vector<AMDomain::var::VarInfo>
  ListVarsByDomain(const std::string &domain) const = 0;

  [[nodiscard]] virtual std::vector<TASKID> ListTaskIds() const = 0;

  [[nodiscard]] virtual PromptPathOptions
  ResolvePromptPathOptions(const std::string &nickname) const = 0;
  [[nodiscard]] virtual std::string
  SubstitutePathLike(const std::string &raw) const = 0;
  [[nodiscard]] virtual std::string
  BuildPath(AMDomain::client::ClientHandle client,
            const std::string &raw_path) const = 0;
  [[nodiscard]] virtual std::string
  Format(const std::string &text,
         AMInterface::style::StyleIndex style_index) const = 0;
  [[nodiscard]] virtual std::string
  FormatPath(const std::string &segment, const PathInfo *path_info) const = 0;
};

using CompletionRuntimePtr = std::shared_ptr<ICompletionRuntime>;

} // namespace AMInterface::completion
