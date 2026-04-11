#pragma once

#include "domain/client/ClientPort.hpp"
#include "domain/terminal/TerminalPort.hpp"
#include "foundation/core/DataClass.hpp"
#include <deque>
#include <functional>
#include <map>
#include <mutex>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

namespace AMApplication::terminal {
using ClientHandle = AMDomain::client::ClientHandle;
using ClientControlComponent = AMDomain::client::ClientControlComponent;
using TerminalHandle = AMDomain::terminal::TerminalHandle;

class TermAppService final : public NonCopyableNonMovable {
public:
  using ChannelStreamProcessor = std::function<void(std::string_view)>;

  struct ChannelStreamAttachResult {
    size_t replayed_bytes = 0;
    bool overflowed = false;
    bool closed = false;
    ECM last_error = OK;
  };

  struct ChannelStreamState {
    bool exists = false;
    bool attached = false;
    bool closed = false;
    bool overflowed = false;
    size_t cached_bytes = 0;
    ECM last_error = OK;
  };

  TermAppService() = default;
  ~TermAppService() override;

  [[nodiscard]] ECMData<TerminalHandle>
  CreateTerminal(const ClientHandle &client, bool detach = false);

  [[nodiscard]] ECMData<TerminalHandle>
  AddTerminal(const ClientHandle &client, const TerminalHandle &terminal,
              bool force = false);

  [[nodiscard]] ECMData<TerminalHandle>
  EnsureTerminal(const ClientHandle &client);

  [[nodiscard]] ECMData<TerminalHandle>
  GetTerminalByNickname(const std::string &nickname,
                        bool case_sensitive = true) const;

  [[nodiscard]] std::vector<std::string> ListTerminalNames() const;

  ECM RemoveTerminal(const std::string &nickname,
                     const ClientControlComponent &control = {});

  [[nodiscard]] ECMData<ChannelStreamAttachResult> AttachChannelStream(
      const std::string &terminal_nickname, const std::string &channel_name,
      ChannelStreamProcessor processor,
      size_t max_cache_bytes = (16U * 1024U * 1024U));

  ECM DetachChannelStream(const std::string &terminal_nickname,
                          const std::string &channel_name);

  ECM StopChannelStream(const std::string &terminal_nickname,
                        const std::string &channel_name);

  [[nodiscard]] ChannelStreamState
  GetChannelStreamState(const std::string &terminal_nickname,
                        const std::string &channel_name) const;

private:
  struct ChannelStreamRuntime;
  using ChannelStreamRuntimeHandle = std::shared_ptr<ChannelStreamRuntime>;

  [[nodiscard]] static std::string
  BuildTerminalKey_(const ClientHandle &client, const char *action);

  [[nodiscard]] static std::string
  NormalizeTerminalKey_(const std::string &nickname);

  [[nodiscard]] static std::string
  BuildChannelStreamKey_(const std::string &terminal_key,
                         const std::string &channel_name);

  [[nodiscard]] ECMData<TerminalHandle>
  QueryTerminal_(const std::string &terminal_key) const;

  void StreamReadLoop_(const ChannelStreamRuntimeHandle &runtime);
  void StopChannelStreamRuntime_(ChannelStreamRuntimeHandle runtime);
  void StopAllChannelStreams_();
  void StopAllTerminalStreamsByKey_(const std::string &terminal_key);

private:
  mutable std::mutex mutex_ = {};
  std::map<std::string, TerminalHandle> terminals_ = {};
  mutable std::mutex stream_mutex_ = {};
  std::map<std::string, ChannelStreamRuntimeHandle> channel_streams_ = {};
};

} // namespace AMApplication::terminal
