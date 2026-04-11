#include "application/terminal/TermAppService.hpp"

#include "domain/host/HostDomainService.hpp"
#include "foundation/tools/string.hpp"
#include <algorithm>
#include <chrono>
#include <thread>
#include <vector>

namespace AMApplication::terminal {
namespace {
using EC = ErrorCode;
constexpr const char *kDefaultTerminalChannelName = "default";
constexpr int kTerminalRemoveCloseTimeoutMs = 1500;
constexpr size_t kDefaultStreamCacheBytes = 16U * 1024U * 1024U;
constexpr size_t kStreamReadChunkBytes = 32U * 1024U;
constexpr int kStreamReadTimeoutMs = 150;
}

struct TermAppService::ChannelStreamRuntime {
  std::string terminal_key = {};
  std::string channel_name = {};
  TerminalHandle terminal = nullptr;
  AMDomain::client::amf control_token = AMDomain::client::CreateClientControlToken();
  std::thread read_thread = {};
  mutable std::mutex mutex = {};
  std::deque<std::string> cache_chunks = {};
  size_t cached_bytes = 0;
  size_t max_cache_bytes = kDefaultStreamCacheBytes;
  bool overflowed = false;
  bool attached = false;
  bool stop_requested = false;
  bool closed = false;
  ChannelStreamProcessor processor = {};
  ECM last_error = OK;
};

TermAppService::~TermAppService() { StopAllChannelStreams_(); }

std::string TermAppService::BuildTerminalKey_(const ClientHandle &client,
                                              const char *action) {
  if (!client) {
    return "";
  }
  const std::string raw =
      AMStr::Strip(client->ConfigPort().GetNickname().empty()
                       ? client->ConfigPort().GetRequest().nickname
                       : client->ConfigPort().GetNickname());
  if (raw.empty()) {
    return "";
  }
  (void)action;
  return AMDomain::host::HostService::NormalizeNickname(raw);
}

std::string TermAppService::NormalizeTerminalKey_(const std::string &nickname) {
  std::string key =
      AMDomain::host::HostService::NormalizeNickname(AMStr::Strip(nickname));
  if (AMDomain::host::HostService::IsLocalNickname(key)) {
    key = "local";
  }
  return key;
}

std::string
TermAppService::BuildChannelStreamKey_(const std::string &terminal_key,
                                       const std::string &channel_name) {
  return terminal_key + "@" + channel_name;
}

ECMData<TerminalHandle>
TermAppService::QueryTerminal_(const std::string &terminal_key) const {
  if (terminal_key.empty()) {
    return {nullptr, Err(EC::InvalidArg, "terminal.query", "terminal_key",
                         "Terminal key is empty")};
  }

  std::lock_guard<std::mutex> lock(mutex_);
  auto it = terminals_.find(terminal_key);
  if (it == terminals_.end() || !it->second) {
    return {nullptr, Err(EC::ClientNotFound, "terminal.query", terminal_key,
                         "Terminal not found")};
  }
  return {it->second, OK};
}

ECMData<TerminalHandle>
TermAppService::CreateTerminal(const ClientHandle &client, bool detach) {
  if (!client) {
    return {nullptr, Err(EC::InvalidHandle, "terminal.create", "<client>",
                         "Client handle is null")};
  }

  const std::string terminal_key = BuildTerminalKey_(client, "terminal.create");
  if (terminal_key.empty()) {
    return {nullptr, Err(EC::InvalidArg, "terminal.create", "terminal_key",
                         "Failed to resolve terminal key from client")};
  }

  if (!detach) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = terminals_.find(terminal_key);
    if (it != terminals_.end() && it->second) {
      return {it->second, OK};
    }
  }

  auto create_result = AMDomain::terminal::CreateTerminalPort(client);
  if (!(create_result.rcm) || !create_result.data) {
    return create_result;
  }
  TerminalHandle created = create_result.data;

  auto open_result = created->OpenChannel({kDefaultTerminalChannelName}, {});
  if (!(open_result.rcm) && open_result.rcm.code != EC::TargetAlreadyExists) {
    return {nullptr, open_result.rcm};
  }

  auto active_result = created->ActiveChannel({kDefaultTerminalChannelName}, {});
  if (!(active_result.rcm) || !active_result.data.activated) {
    return {
        nullptr,
        active_result.rcm
            ? Err(EC::CommonFailure, "terminal.create.active_default",
                  terminal_key, "Failed to activate default terminal channel")
            : active_result.rcm};
  }

  if (detach) {
    return {created, OK};
  }
  return AddTerminal(client, created, false);
}

ECMData<TerminalHandle>
TermAppService::AddTerminal(const ClientHandle &client,
                            const TerminalHandle &terminal, bool force) {
  if (!client) {
    return {nullptr, Err(EC::InvalidHandle, "terminal.add", "<client>",
                         "Client handle is null")};
  }
  if (!terminal) {
    return {nullptr, Err(EC::InvalidHandle, "terminal.add", "<terminal>",
                         "Terminal handle is null")};
  }

  const std::string terminal_key = BuildTerminalKey_(client, "terminal.add");
  if (terminal_key.empty()) {
    return {nullptr, Err(EC::InvalidArg, "terminal.add", "terminal_key",
                         "Failed to resolve terminal key from client")};
  }

  TerminalHandle out = nullptr;
  bool replaced_terminal = false;
  {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = terminals_.find(terminal_key);
    if (it == terminals_.end()) {
      terminals_.emplace(terminal_key, terminal);
      out = terminal;
    } else {
      if (force || !it->second) {
        replaced_terminal =
            (it->second != nullptr && it->second.get() != terminal.get());
        it->second = terminal;
      }
      out = it->second;
    }
  }

  if (replaced_terminal) {
    // Existing stream pumps are bound to the old terminal handle.
    StopAllTerminalStreamsByKey_(terminal_key);
  }
  return {out, OK};
}

ECMData<TerminalHandle>
TermAppService::EnsureTerminal(const ClientHandle &client) {
  if (!client) {
    return {nullptr, Err(EC::InvalidHandle, "terminal.ensure", "<client>",
                         "Client handle is null")};
  }

  const std::string terminal_key = BuildTerminalKey_(client, "terminal.ensure");
  if (terminal_key.empty()) {
    return {nullptr, Err(EC::InvalidArg, "terminal.ensure", "terminal_key",
                         "Failed to resolve terminal key from client")};
  }

  {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = terminals_.find(terminal_key);
    if (it != terminals_.end() && it->second) {
      return {it->second, OK};
    }
  }

  return CreateTerminal(client, false);
}

ECMData<TerminalHandle>
TermAppService::GetTerminalByNickname(const std::string &nickname,
                                      bool case_sensitive) const {
  const std::string key = NormalizeTerminalKey_(nickname);
  if (key.empty()) {
    return {nullptr, Err(EC::InvalidArg, "terminal.get", nickname,
                         "Terminal nickname is empty")};
  }

  if (case_sensitive) {
    return QueryTerminal_(key);
  }

  const std::string lowered = AMStr::lowercase(key);
  std::vector<std::string> matched_names = {};
  TerminalHandle matched_terminal = nullptr;

  {
    std::lock_guard<std::mutex> lock(mutex_);
    for (const auto &entry : terminals_) {
      if (!entry.second) {
        continue;
      }
      if (AMStr::lowercase(entry.first) != lowered) {
        continue;
      }
      matched_names.push_back(entry.first);
      matched_terminal = entry.second;
    }
  }

  if (matched_names.size() == 1 && matched_terminal) {
    return {matched_terminal, OK};
  }
  if (matched_names.size() > 1) {
    return {nullptr, Err(EC::ClientNotFound, "terminal.get", nickname,
                         AMStr::fmt("Ambiguous nickname, candidates: {}",
                                    AMStr::join(matched_names, ", ")))};
  }
  return {nullptr, Err(EC::ClientNotFound, "terminal.get", nickname,
                       "Terminal not found")};
}

std::vector<std::string> TermAppService::ListTerminalNames() const {
  std::vector<std::string> names = {};
  std::lock_guard<std::mutex> lock(mutex_);
  names.reserve(terminals_.size());
  for (const auto &entry : terminals_) {
    if (entry.second) {
      names.push_back(entry.first);
    }
  }
  return names;
}

void TermAppService::StreamReadLoop_(const ChannelStreamRuntimeHandle &runtime) {
  if (!runtime || !runtime->terminal) {
    return;
  }

  auto append_cache_locked = [&](const std::string &chunk) {
    if (chunk.empty()) {
      return;
    }
    const size_t max_cache_bytes = std::max<size_t>(1, runtime->max_cache_bytes);
    if (chunk.size() >= max_cache_bytes) {
      runtime->cache_chunks.clear();
      runtime->cached_bytes = max_cache_bytes;
      runtime->overflowed = true;
      runtime->cache_chunks.emplace_back(
          chunk.substr(chunk.size() - max_cache_bytes));
      return;
    }
    while (runtime->cached_bytes + chunk.size() > max_cache_bytes &&
           !runtime->cache_chunks.empty()) {
      runtime->cached_bytes -= runtime->cache_chunks.front().size();
      runtime->cache_chunks.pop_front();
      runtime->overflowed = true;
    }
    runtime->cache_chunks.push_back(chunk);
    runtime->cached_bytes += chunk.size();
  };

  while (true) {
    std::string deliver_chunk = {};
    ChannelStreamProcessor deliver_processor = {};
    {
      std::lock_guard<std::mutex> lock(runtime->mutex);
      if (runtime->stop_requested) {
        break;
      }
      if (runtime->attached && runtime->processor &&
          !runtime->cache_chunks.empty()) {
        deliver_chunk = std::move(runtime->cache_chunks.front());
        runtime->cached_bytes -= deliver_chunk.size();
        runtime->cache_chunks.pop_front();
        deliver_processor = runtime->processor;
      }
    }
    if (deliver_processor && !deliver_chunk.empty()) {
      try {
        deliver_processor(deliver_chunk);
      } catch (...) {
      }
      continue;
    }

    const ClientControlComponent read_control(runtime->control_token,
                                              kStreamReadTimeoutMs);
    auto read_result = runtime->terminal->ReadChannel(
        {std::optional<std::string>(runtime->channel_name), kStreamReadChunkBytes},
        read_control);

    if (!(read_result.rcm)) {
      if (read_result.rcm.code == EC::OperationTimeout) {
        continue;
      }
      bool should_exit = true;
      if (read_result.rcm.code == EC::Terminate) {
        std::lock_guard<std::mutex> lock(runtime->mutex);
        should_exit = runtime->stop_requested;
      }
      if (should_exit) {
        std::lock_guard<std::mutex> lock(runtime->mutex);
        runtime->last_error = read_result.rcm;
        runtime->closed = true;
        break;
      }
      continue;
    }

    if (!read_result.data.output.empty()) {
      ChannelStreamProcessor output_processor = {};
      {
        std::lock_guard<std::mutex> lock(runtime->mutex);
        if (runtime->attached && runtime->processor) {
          output_processor = runtime->processor;
        } else {
          append_cache_locked(read_result.data.output);
        }
      }
      if (output_processor) {
        try {
          output_processor(read_result.data.output);
        } catch (...) {
        }
      }
    }

    if (read_result.data.eof) {
      std::lock_guard<std::mutex> lock(runtime->mutex);
      runtime->closed = true;
      runtime->last_error = OK;
      break;
    }
  }
}

void TermAppService::StopChannelStreamRuntime_(ChannelStreamRuntimeHandle runtime) {
  if (!runtime) {
    return;
  }
  {
    std::lock_guard<std::mutex> lock(runtime->mutex);
    runtime->attached = false;
    runtime->processor = {};
    runtime->stop_requested = true;
    if (runtime->control_token) {
      runtime->control_token->RequestInterrupt();
    }
  }
  if (runtime->read_thread.joinable()) {
    if (runtime->read_thread.get_id() == std::this_thread::get_id()) {
      runtime->read_thread.detach();
    } else {
      runtime->read_thread.join();
    }
  }
}

void TermAppService::StopAllChannelStreams_() {
  std::vector<ChannelStreamRuntimeHandle> runtimes = {};
  {
    std::lock_guard<std::mutex> lock(stream_mutex_);
    runtimes.reserve(channel_streams_.size());
    for (auto &entry : channel_streams_) {
      runtimes.push_back(entry.second);
    }
    channel_streams_.clear();
  }
  for (auto &runtime : runtimes) {
    StopChannelStreamRuntime_(runtime);
  }
}

void TermAppService::StopAllTerminalStreamsByKey_(
    const std::string &terminal_key) {
  if (terminal_key.empty()) {
    return;
  }
  std::vector<ChannelStreamRuntimeHandle> runtimes = {};
  {
    std::lock_guard<std::mutex> lock(stream_mutex_);
    for (auto it = channel_streams_.begin(); it != channel_streams_.end();) {
      if (!it->second || it->second->terminal_key != terminal_key) {
        ++it;
        continue;
      }
      runtimes.push_back(it->second);
      it = channel_streams_.erase(it);
    }
  }
  for (auto &runtime : runtimes) {
    StopChannelStreamRuntime_(runtime);
  }
}

ECMData<TermAppService::ChannelStreamAttachResult>
TermAppService::AttachChannelStream(const std::string &terminal_nickname,
                                    const std::string &channel_name,
                                    ChannelStreamProcessor processor,
                                    size_t max_cache_bytes) {
  ECMData<ChannelStreamAttachResult> out = {};
  const std::string terminal_key = NormalizeTerminalKey_(terminal_nickname);
  const std::string channel = AMStr::Strip(channel_name);
  if (terminal_key.empty()) {
    out.rcm = Err(EC::InvalidArg, "terminal.stream.attach", "terminal_key",
                  "Terminal nickname is empty");
    return out;
  }
  if (channel.empty()) {
    out.rcm = Err(EC::InvalidArg, "terminal.stream.attach", "channel_name",
                  "Channel name is empty");
    return out;
  }
  if (!processor) {
    out.rcm = Err(EC::InvalidArg, "terminal.stream.attach", channel,
                  "Processor callback is empty");
    return out;
  }
  if (max_cache_bytes == 0) {
    max_cache_bytes = kDefaultStreamCacheBytes;
  }

  auto terminal_result = QueryTerminal_(terminal_key);
  if (!(terminal_result.rcm) || !terminal_result.data) {
    out.rcm = terminal_result.rcm
                  ? Err(EC::InvalidHandle, "terminal.stream.attach", terminal_key,
                        "Terminal handle is null")
                  : terminal_result.rcm;
    return out;
  }

  const std::string stream_key = BuildChannelStreamKey_(terminal_key, channel);
  ChannelStreamRuntimeHandle runtime = nullptr;
  ChannelStreamRuntimeHandle stale_runtime = nullptr;
  {
    std::lock_guard<std::mutex> lock(stream_mutex_);
    auto it = channel_streams_.find(stream_key);
    if (it == channel_streams_.end() || !it->second) {
      runtime = std::make_shared<ChannelStreamRuntime>();
      runtime->terminal_key = terminal_key;
      runtime->channel_name = channel;
      runtime->terminal = terminal_result.data;
      runtime->max_cache_bytes = max_cache_bytes;
      runtime->read_thread =
          std::thread([this, runtime]() { StreamReadLoop_(runtime); });
      channel_streams_[stream_key] = runtime;
    } else {
      runtime = it->second;
      bool stale = false;
      {
        std::lock_guard<std::mutex> runtime_lock(runtime->mutex);
        stale = runtime->closed || runtime->stop_requested;
      }
      if (stale) {
        stale_runtime = runtime;
        runtime = std::make_shared<ChannelStreamRuntime>();
        runtime->terminal_key = terminal_key;
        runtime->channel_name = channel;
        runtime->terminal = terminal_result.data;
        runtime->max_cache_bytes = max_cache_bytes;
        runtime->read_thread =
            std::thread([this, runtime]() { StreamReadLoop_(runtime); });
        it->second = runtime;
      }
    }
  }
  if (stale_runtime) {
    StopChannelStreamRuntime_(stale_runtime);
  }
  if (!runtime) {
    out.rcm = Err(EC::InvalidHandle, "terminal.stream.attach", stream_key,
                  "Failed to resolve stream runtime");
    return out;
  }

  std::deque<std::string> replay_chunks = {};
  {
    std::lock_guard<std::mutex> lock(runtime->mutex);
    runtime->max_cache_bytes = std::max<size_t>(1, max_cache_bytes);
    while (runtime->cached_bytes > runtime->max_cache_bytes &&
           !runtime->cache_chunks.empty()) {
      runtime->cached_bytes -= runtime->cache_chunks.front().size();
      runtime->cache_chunks.pop_front();
      runtime->overflowed = true;
    }
    replay_chunks.swap(runtime->cache_chunks);
    out.data.replayed_bytes = runtime->cached_bytes;
    runtime->cached_bytes = 0;
    out.data.overflowed = runtime->overflowed;
    runtime->overflowed = false;
    out.data.closed = runtime->closed;
    out.data.last_error = runtime->last_error;
    runtime->processor = processor;
    runtime->attached = false;
  }
  for (const auto &chunk : replay_chunks) {
    try {
      processor(chunk);
    } catch (...) {
    }
  }
  {
    std::lock_guard<std::mutex> lock(runtime->mutex);
    runtime->attached = true;
  }
  out.rcm = OK;
  return out;
}

ECM TermAppService::DetachChannelStream(const std::string &terminal_nickname,
                                        const std::string &channel_name) {
  const std::string terminal_key = NormalizeTerminalKey_(terminal_nickname);
  const std::string channel = AMStr::Strip(channel_name);
  if (terminal_key.empty() || channel.empty()) {
    return Err(EC::InvalidArg, "terminal.stream.detach", "stream_key",
               "Terminal nickname or channel name is empty");
  }
  const std::string stream_key = BuildChannelStreamKey_(terminal_key, channel);
  ChannelStreamRuntimeHandle runtime = nullptr;
  {
    std::lock_guard<std::mutex> lock(stream_mutex_);
    auto it = channel_streams_.find(stream_key);
    if (it != channel_streams_.end()) {
      runtime = it->second;
    }
  }
  if (!runtime) {
    return OK;
  }
  std::lock_guard<std::mutex> lock(runtime->mutex);
  runtime->attached = false;
  runtime->processor = {};
  return OK;
}

ECM TermAppService::StopChannelStream(const std::string &terminal_nickname,
                                      const std::string &channel_name) {
  const std::string terminal_key = NormalizeTerminalKey_(terminal_nickname);
  const std::string channel = AMStr::Strip(channel_name);
  if (terminal_key.empty() || channel.empty()) {
    return Err(EC::InvalidArg, "terminal.stream.stop", "stream_key",
               "Terminal nickname or channel name is empty");
  }
  const std::string stream_key = BuildChannelStreamKey_(terminal_key, channel);
  ChannelStreamRuntimeHandle runtime = nullptr;
  {
    std::lock_guard<std::mutex> lock(stream_mutex_);
    auto it = channel_streams_.find(stream_key);
    if (it == channel_streams_.end()) {
      return OK;
    }
    runtime = it->second;
    channel_streams_.erase(it);
  }
  StopChannelStreamRuntime_(runtime);
  return OK;
}

TermAppService::ChannelStreamState TermAppService::GetChannelStreamState(
    const std::string &terminal_nickname, const std::string &channel_name) const {
  ChannelStreamState out = {};
  const std::string terminal_key = NormalizeTerminalKey_(terminal_nickname);
  const std::string channel = AMStr::Strip(channel_name);
  if (terminal_key.empty() || channel.empty()) {
    return out;
  }
  const std::string stream_key = BuildChannelStreamKey_(terminal_key, channel);

  ChannelStreamRuntimeHandle runtime = nullptr;
  {
    std::lock_guard<std::mutex> lock(stream_mutex_);
    auto it = channel_streams_.find(stream_key);
    if (it != channel_streams_.end()) {
      runtime = it->second;
    }
  }
  if (!runtime) {
    return out;
  }

  std::lock_guard<std::mutex> lock(runtime->mutex);
  out.exists = true;
  out.attached = runtime->attached;
  out.closed = runtime->closed;
  out.overflowed = runtime->overflowed;
  out.cached_bytes = runtime->cached_bytes;
  out.last_error = runtime->last_error;
  return out;
}

ECM TermAppService::RemoveTerminal(const std::string &nickname,
                                   const ClientControlComponent &control) {
  const std::string key = NormalizeTerminalKey_(nickname);
  if (key.empty()) {
    return Err(EC::InvalidArg, "terminal.remove", nickname,
               "Terminal nickname is empty");
  }

  TerminalHandle target = nullptr;
  {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = terminals_.find(key);
    if (it == terminals_.end()) {
      return OK;
    }
    target = it->second;
    terminals_.erase(it);
  }

  StopAllTerminalStreamsByKey_(key);

  if (!target) {
    return OK;
  }

  const auto session_state = target->GetSessionState();
  if (session_state != AMDomain::client::ClientStatus::OK) {
    // Disconnected sessions can fail or block during graceful channel close.
    // Terminal map entry is already removed, so best-effort cleanup stops here.
    return OK;
  }

  auto list_result = target->ListChannels({}, control);
  if (!(list_result.rcm)) {
    if (list_result.rcm.code == EC::NoConnection ||
        list_result.rcm.code == EC::ConnectionLost ||
        list_result.rcm.code == EC::NoSession) {
      return OK;
    }
    return list_result.rcm;
  }
  const AMDomain::client::ClientControlComponent close_control =
      control.RemainingTimeMs().has_value()
          ? control
          : AMDomain::client::ClientControlComponent(
                control.ControlToken(), kTerminalRemoveCloseTimeoutMs);
  ECM status = OK;
  for (const auto &name : list_result.data.channel_names) {
    auto close_result = target->CloseChannel({name, true}, close_control);
    if (!(close_result.rcm)) {
      if (close_result.rcm.code == EC::NoConnection ||
          close_result.rcm.code == EC::ConnectionLost ||
          close_result.rcm.code == EC::NoSession ||
          close_result.rcm.code == EC::ClientNotFound) {
        continue;
      }
      status = close_result.rcm;
    }
  }
  return status;
}

} // namespace AMApplication::terminal
