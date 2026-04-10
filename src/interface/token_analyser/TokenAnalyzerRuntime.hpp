#pragma once

#include "domain/client/ClientPort.hpp"
#include "domain/prompt/PromptDomainModel.hpp"
#include "domain/var/VarModel.hpp"
#include "foundation/core/DataClass.hpp"
#include <cstddef>
#include <memory>
#include <string>
#include <vector>

namespace AMInterface::parser {

class ITokenAnalyzerRuntime {
public:
  enum class TerminalNameState {
    OK = 0,
    Disconnected = 1,
    Unestablished = 2,
    Nonexistent = 3,
  };

  enum class ChannelNameState {
    OK = 0,
    Disconnected = 1,
    Nonexistent = 2,
    ValidNew = 3,
    InvalidNew = 4,
  };

  struct PromptPathOptions {
    bool highlight_enable = true;
    size_t highlight_timeout_ms = 1000;
  };

  virtual ~ITokenAnalyzerRuntime() = default;

  [[nodiscard]] virtual AMDomain::client::ClientHandle CurrentClient() const = 0;
  [[nodiscard]] virtual AMDomain::client::ClientHandle LocalClient() const = 0;
  [[nodiscard]] virtual AMDomain::client::ClientHandle
  GetClient(const std::string &nickname) const = 0;
  [[nodiscard]] virtual std::string CurrentNickname() const = 0;
  [[nodiscard]] virtual bool HostExists(const std::string &nickname) const = 0;
  [[nodiscard]] virtual bool TerminalExists(const std::string &nickname) const = 0;
  [[nodiscard]] virtual TerminalNameState
  QueryTerminalNameState(const std::string &nickname) const = 0;
  [[nodiscard]] virtual ChannelNameState
  QueryChannelNameState(const std::string &nickname,
                        const std::string &channel_name,
                        bool allow_new) const = 0;
  [[nodiscard]] virtual bool HasVarDomain(const std::string &zone) const = 0;
  [[nodiscard]] virtual std::string CurrentVarDomain() const = 0;
  [[nodiscard]] virtual ECMData<AMDomain::var::VarInfo>
  GetVar(const std::string &zone, const std::string &varname) const = 0;
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
  [[nodiscard]] virtual std::string
  FormatPath(const std::string &segment, const PathInfo *path_info) const = 0;
  [[nodiscard]] virtual std::string
  ResolveInputHighlightStyle(AMTokenType type,
                             const std::string &default_value) const = 0;
  [[nodiscard]] virtual std::string
  ResolvePathHighlightStyle(AMTokenType type,
                            const std::string &default_value) const = 0;
};

} // namespace AMInterface::parser
