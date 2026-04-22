#include "interface/adapters/client/ClientInterfaceService.hpp"

#include "domain/host/HostDomainService.hpp"
#include "foundation/core/Enum.hpp"
#include "foundation/tools/auth.hpp"
#include "foundation/tools/path.hpp"
#include "foundation/tools/string.hpp"
#include "interface/style/StyleIndex.hpp"
#include <algorithm>
#include <atomic>
#include <chrono>
#include <cmath>
#include <iomanip>
#include <limits>
#include <map>
#include <mutex>
#include <optional>
#include <sstream>
#include <stop_token>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <utility>

namespace AMInterface::client {
class ClientConnectSpinner final : public NonCopyableNonMovable {
public:
  explicit ClientConnectSpinner(PromptIOManager &prompt_io_manager)
      : prompt_io_manager_(prompt_io_manager) {}
  ~ClientConnectSpinner() override { Stop(); }

  void Start(const AMDomain::host::HostConfig &config, bool quiet) {
    Stop();
    if (quiet) {
      return;
    }

    {
      std::lock_guard<std::mutex> lock(mutex_);
      running_.store(true, std::memory_order_relaxed);
      state_info_ =
          AMStr::fmt("resolving hostname: {}", config.request.hostname);
      refresh_active_ = true;
      if (!cursor_hidden_) {
        prompt_io_manager_.SetCursorVisible(false);
        cursor_hidden_ = true;
      }
      prompt_io_manager_.RefreshBegin();
      worker_ = std::jthread(
          [this](std::stop_token stop_token) { RenderLoop_(stop_token); });
    }
  }

  void Stop() {
    std::jthread worker = {};
    bool should_refresh_end = false;
    bool should_show_cursor = false;
    {
      std::lock_guard<std::mutex> lock(mutex_);
      if (!refresh_active_ && !worker_.joinable() &&
          !running_.load(std::memory_order_relaxed)) {
        return;
      }

      running_.store(false, std::memory_order_relaxed);
      if (worker_.joinable()) {
        worker = std::move(worker_);
      }
      should_refresh_end = refresh_active_;
      refresh_active_ = false;
      should_show_cursor = cursor_hidden_;
      cursor_hidden_ = false;
    }

    if (worker.joinable()) {
      worker.request_stop();
      worker.join();
    }
    if (should_refresh_end) {
      prompt_io_manager_.RefreshEnd();
    }
    if (should_show_cursor) {
      prompt_io_manager_.SetCursorVisible(true);
    }
  }

  void StopForPrompt() { Stop(); }

  [[nodiscard]] bool IsRunning() const {
    return running_.load(std::memory_order_relaxed);
  }

  void UpdateStateInfo(const std::string &state_info) {
    const std::string normalized = AMStr::Strip(state_info);
    if (normalized.empty()) {
      return;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    state_info_ = normalized;
  }

private:
  void RenderLoop_(std::stop_token stop_token) {
    static const std::vector<std::string> frames = {
        "⠉⠉", "⠈⠙", "⠀⠹", "⠀⢸", "⠀⣰", "⢀⣠", "⣀⣀", "⣄⡀", "⣆⠀", "⡇⠀", "⠏⠀", "⠋⠁"};
    size_t idx = 0;
    while (running_.load(std::memory_order_relaxed) &&
           !stop_token.stop_requested()) {
      std::string state_info;
      {
        std::lock_guard<std::mutex> lock(mutex_);
        state_info = state_info_;
      }
      if (state_info.empty()) {
        state_info = "connecting";
      }
      prompt_io_manager_.RefreshRender(
          {AMStr::fmt("{} {}", frames[idx % frames.size()], state_info)});
      ++idx;
      std::this_thread::sleep_for(std::chrono::milliseconds(120));
    }
  }

  PromptIOManager &prompt_io_manager_;
  mutable std::mutex mutex_ = {};
  std::jthread worker_ = {};
  std::atomic<bool> running_ = false;
  std::string state_info_ = "";
  bool refresh_active_ = false;
  bool cursor_hidden_ = false;
};

namespace {
using ClientHandle = AMDomain::client::ClientHandle;
using HostConfig = AMDomain::host::HostConfig;
using ClientMetaData = AMDomain::host::ClientMetaData;
using ClientProtocol = AMDomain::host::ClientProtocol;
using TraceInfo = AMDomain::client::TraceInfo;
using AMDomain::host::HostService::IsLocalNickname;
using AMDomain::host::HostService::NormalizeNickname;
using AMDomain::host::HostService::ValidateNickname;

struct ClientStatusFormat {
  size_t protocol_width = 0;
  size_t nickname_width = 0;
  size_t cwd_width = 0;
};

std::string BuildClientProtocolLabel_(const ClientHandle &client) {
  if (!client) {
    return "[UNKNOWN]";
  }
  const std::string protocol =
      AMStr::uppercase(AMStr::ToString(client->ConfigPort().GetProtocol()));
  return protocol.empty() ? "[UNKNOWN]" : AMStr::fmt("[{}]", protocol);
}

std::string BuildConnectSuccessLine_(const AMStyleService &style_service,
                                     const std::string &nickname,
                                     ClientProtocol protocol) {
  const std::string protocol_label =
      AMStr::fmt("[{}]", AMStr::uppercase(AMStr::ToString(protocol)));
  const std::string styled_protocol = style_service.Format(
      protocol_label, AMInterface::style::StyleIndex::Protocol);
  const std::string styled_nickname =
      style_service.Format(nickname, AMInterface::style::StyleIndex::Nickname);
  return AMStr::fmt("✅ Connect to {} server : {}", styled_protocol,
                    styled_nickname);
}

std::string BuildEndpointRaw_(const std::string &username,
                              const std::string &hostname,
                              const std::string &port) {
  if (hostname.empty()) {
    return "<unknown>";
  }
  if (username.empty()) {
    return AMStr::fmt("{}:{}", hostname, port);
  }
  return AMStr::fmt("{}@{}:{}", username, hostname, port);
}

std::string BuildEndpointStyled_(const AMStyleService &style_service,
                                 const std::string &username,
                                 const std::string &hostname,
                                 const std::string &port) {
  const std::string host = AMStr::Strip(hostname);
  if (host.empty()) {
    return "<unknown>";
  }
  const std::string styled_host =
      style_service.Format(host, AMInterface::style::StyleIndex::Nickname);
  const std::string styled_port =
      style_service.Format(port, AMInterface::style::StyleIndex::Number);
  if (AMStr::Strip(username).empty()) {
    return AMStr::fmt("{}:{}", styled_host, styled_port);
  }
  const std::string styled_user =
      style_service.Format(username, AMInterface::style::StyleIndex::Username);
  const std::string styled_at =
      style_service.Format("@", AMInterface::style::StyleIndex::AtSign);
  return AMStr::fmt("{}{}{}:{}", styled_user, styled_at, styled_host,
                    styled_port);
}

std::string PadStyledCellRight_(const std::string &styled_text,
                                size_t raw_display_width, size_t target_width) {
  if (target_width <= raw_display_width) {
    return styled_text;
  }
  return styled_text + std::string(target_width - raw_display_width, ' ');
}

AMInterface::style::StyleIndex
ResolveClientNicknameStyleByState_(const ClientHandle &client) {
  if (!client) {
    return AMInterface::style::StyleIndex::NonexistentNickname;
  }
  const auto cached = client->ConfigPort().GetState();
  const bool connected =
      (cached.rcm.code == EC::Success) &&
      (cached.data.status == AMDomain::client::ClientStatus::OK);
  return connected ? AMInterface::style::StyleIndex::Nickname
                   : AMInterface::style::StyleIndex::DisconnectedNickname;
}

void PrintStyledNicknamesCompact_(
    PromptIOManager &prompt, AMStyleService &style_service,
    const std::vector<std::pair<std::string, AMInterface::style::StyleIndex>>
        &nicknames) {
  if (nicknames.empty()) {
    prompt.Print("");
    return;
  }
  constexpr size_t kMaxWidth = 80;
  size_t current_width = 0;
  std::ostringstream line;
  for (const auto &entry : nicknames) {
    const std::string &nickname = entry.first;
    const size_t display_len = nickname.size();
    const size_t separator_len = current_width == 0 ? 0 : 3;
    if (current_width + separator_len + display_len > kMaxWidth &&
        current_width > 0) {
      prompt.Print(line.str());
      line.str(std::string());
      line.clear();
      current_width = 0;
    }
    if (current_width > 0) {
      line << "   ";
      current_width += 3;
    }
    line << style_service.Format(nickname, entry.second);
    current_width += display_len;
  }
  if (current_width > 0) {
    prompt.Print(line.str());
  }
}

ECM MergeStatus_(const ECM &current, const ECM &next) {
  return (next) ? current : next;
}

[[nodiscard]] ECM TimeoutSecondsToMs_(double timeout_s, const char *operation,
                                      int *out_timeout_ms) {
  if (out_timeout_ms == nullptr) {
    return Err(EC::InvalidArg, operation, "timeout", "Timeout output is null");
  }
  if (!std::isfinite(timeout_s) || timeout_s <= 0.0) {
    return Err(EC::InvalidArg, operation, "timeout",
               "Timeout must be greater than 0 seconds");
  }
  const double timeout_ms = timeout_s * 1000.0;
  if (timeout_ms > static_cast<double>(std::numeric_limits<int>::max())) {
    return Err(EC::InvalidArg, operation, "timeout", "Timeout is too large");
  }
  *out_timeout_ms = std::max(1, static_cast<int>(std::llround(timeout_ms)));
  return OK;
}

std::string
FindClientNicknameCaseInsensitive_(const std::vector<std::string> &names,
                                   const std::string &target) {
  const std::string lowered = AMStr::lowercase(AMStr::Strip(target));
  for (const auto &name : names) {
    if (AMStr::lowercase(name) == lowered) {
      return name;
    }
  }
  return "";
}

std::vector<std::string>
NormalizedNicknames(const std::vector<std::string> &targets) {
  std::vector<std::string> out = {};
  std::unordered_set<std::string> seen = {};
  out.reserve(targets.size());
  for (const auto &raw : targets) {
    std::string nickname = NormalizeNickname(AMStr::Strip(raw));
    if (nickname.empty()) {
      continue;
    }
    if (IsLocalNickname(nickname)) {
      nickname = "local";
    }
    if (seen.insert(nickname).second) {
      out.push_back(std::move(nickname));
    }
  }
  return out;
}

ECM ValidateChangeClientNickname_(
    const ClientAppService &client_service,
    const AMHostConfigManager &host_config_manager, const std::string &raw,
    std::string *normalized) {
  constexpr const char *kOp = "change_client.validate_nickname";
  if (normalized == nullptr) {
    return Err(EC::InvalidArg, kOp, "<output>", "Null nickname output");
  }

  std::string candidate = NormalizeNickname(AMStr::Strip(raw));
  if (candidate.empty()) {
    return Err(EC::InvalidArg, kOp, "<nickname>", "Nickname cannot be empty");
  }

  if (IsLocalNickname(candidate)) {
    *normalized = "local";
    return OK;
  }
  if (!ValidateNickname(candidate)) {
    return Err(EC::InvalidArg, kOp, candidate, "Invalid nickname");
  }

  if (host_config_manager.HostExists(candidate)) {
    *normalized = candidate;
    return OK;
  }

  auto existing = client_service.GetClient(candidate, true);
  if (!(existing.rcm) || !existing.data) {
    return Err(EC::ClientNotFound, kOp, candidate, "Host not found");
  }

  *normalized = candidate;
  return OK;
}

ECM ResolveChangeClientNickname_(PromptIOManager &prompt,
                                 const ClientAppService &client_service,
                                 const AMHostConfigManager &host_config_manager,
                                 const std::string &raw_nickname,
                                 std::string *normalized) {
  constexpr const char *kOp = "change_client.resolve_nickname";
  if (normalized == nullptr) {
    return Err(EC::InvalidArg, kOp, "<output>", "Null nickname output");
  }

  const std::string seeded = AMStr::Strip(raw_nickname);
  if (!seeded.empty()) {
    return ValidateChangeClientNickname_(client_service, host_config_manager,
                                         seeded, normalized);
  }

  std::vector<std::string> candidates = client_service.GetClientNames();
  const std::vector<std::string> host_candidates =
      host_config_manager.ListNames();
  candidates.insert(candidates.end(), host_candidates.begin(),
                    host_candidates.end());
  std::unordered_set<std::string> seen_candidates = {};
  std::vector<std::string> deduped_candidates = {};
  deduped_candidates.reserve(candidates.size() + 1);
  for (const auto &item : candidates) {
    const std::string stripped = AMStr::Strip(item);
    if (stripped.empty()) {
      continue;
    }
    if (seen_candidates.insert(stripped).second) {
      deduped_candidates.push_back(stripped);
    }
  }
  candidates = std::move(deduped_candidates);
  if (std::find(candidates.begin(), candidates.end(), "local") ==
      candidates.end()) {
    candidates.emplace_back("local");
  }
  std::vector<std::pair<std::string, std::string>> prompt_candidates = {};
  prompt_candidates.reserve(candidates.size());
  for (const auto &item : candidates) {
    prompt_candidates.emplace_back(item, "");
  }

  while (true) {
    auto input = prompt.Prompt("Client nickname: ", "", {}, prompt_candidates);
    if (!input.has_value()) {
      return Err(EC::ConfigCanceled, kOp, "<prompt>",
                 "Client nickname input canceled");
    }
    std::string resolved = AMStr::Strip(*input);
    if (resolved.empty()) {
      continue;
    }

    const ECM rcm = ValidateChangeClientNickname_(
        client_service, host_config_manager, resolved, normalized);
    if ((rcm)) {
      return OK;
    }
    prompt.ErrorFormat(rcm);
  }
}

bool ParseUserAtHost_(const std::string &user_at_host, std::string *username,
                      std::string *hostname) {
  if (!username || !hostname) {
    return false;
  }
  const size_t at_pos = user_at_host.find('@');
  if (at_pos == std::string::npos || at_pos == 0 ||
      at_pos + 1 >= user_at_host.size()) {
    return false;
  }
  *username = user_at_host.substr(0, at_pos);
  *hostname = user_at_host.substr(at_pos + 1);
  return !AMStr::Strip(*username).empty() && !AMStr::Strip(*hostname).empty();
}

std::string ResolveClientCwdFromService_(const ClientHandle &client) {
  if (!client) {
    return ".";
  }
  auto cwd_result = ClientAppService::GetClientCwd(client);
  std::string cwd = (cwd_result.rcm) ? AMStr::Strip(cwd_result.data) : "";
  if (cwd.empty()) {
    cwd = AMStr::Strip(client->ConfigPort().GetHomeDir());
  }
  return cwd.empty() ? "." : cwd;
}

ClientStatusFormat BuildClientStatusFormat_(
    const std::vector<std::pair<std::string, ClientHandle>> &clients) {
  ClientStatusFormat format = {};
  for (const auto &entry : clients) {
    const std::string protocol = BuildClientProtocolLabel_(entry.second);
    format.protocol_width = std::max(format.protocol_width, protocol.size());
    format.nickname_width = std::max(format.nickname_width, entry.first.size());
    const std::string cwd = ResolveClientCwdFromService_(entry.second);
    format.cwd_width = std::max(format.cwd_width, cwd.size());
  }
  return format;
}

std::vector<size_t> ParseOrderNumbers_(const std::string &raw, bool *ok) {
  if (ok) {
    *ok = false;
  }
  std::string normalized = raw;
  std::replace(normalized.begin(), normalized.end(), ',', ' ');
  std::istringstream iss(normalized);
  std::vector<size_t> out = {};
  std::unordered_set<size_t> seen = {};
  std::string token = {};
  while (iss >> token) {
    int64_t value = -1;
    if (!AMStr::GetNumber(token, &value) || value < 0) {
      return {};
    }
    const size_t order = static_cast<size_t>(value);
    if (seen.insert(order).second) {
      out.push_back(order);
    }
  }
  if (ok) {
    *ok = !out.empty();
  }
  return out;
}

namespace render {
void PrintClientStatusLine(PromptIOManager &prompt, const std::string &nickname,
                           const ClientHandle &client, const ECM &rcm,
                           const ClientStatusFormat &format,
                           const AMStyleService &style_service) {
  const std::string protocol = BuildClientProtocolLabel_(client);
  const std::string cwd = ResolveClientCwdFromService_(client);
  const std::string padded_protocol =
      AMStr::PadRightUtf8(protocol, format.protocol_width);
  const std::string padded_nickname =
      AMStr::PadRightUtf8(nickname, format.nickname_width);
  const std::string padded_cwd = AMStr::PadRightUtf8(cwd, format.cwd_width);

  const std::string styled_protocol = style_service.Format(
      padded_protocol, AMInterface::style::StyleIndex::Protocol);
  const auto nickname_style = ResolveClientNicknameStyleByState_(client);
  const std::string styled_nickname =
      style_service.Format(padded_nickname, nickname_style);
  const std::string styled_cwd =
      style_service.Format(padded_cwd, AMInterface::style::StyleIndex::Cwd);

  std::ostringstream line;
  line << ((rcm) ? "✅  " : "❌  ") << styled_protocol << "  "
       << styled_nickname << "  " << styled_cwd;
  if (!(rcm)) {
    const std::string ec_name = std::string(AMStr::ToString(rcm.code));
    const std::string msg = rcm.error.empty() ? rcm.msg() : rcm.error;
    line << "  " << ec_name << "  " << msg;
  }
  prompt.Print(line.str());
}

void PrintHostConfigDetail(PromptIOManager &prompt, const std::string &nickname,
                           const HostConfig &config,
                           const AMStyleService &style_service) {
  const auto values = config.GetStrDict();
  prompt.Print("\\[" + nickname + "]");

  size_t width = 0;
  for (const auto &field : values) {
    if (field.first == "nickname") {
      continue;
    }
    width = std::max(width, field.first.size());
  }

  for (const auto &field : values) {
    if (field.first == "nickname") {
      continue;
    }
    std::string render_value = field.second;
    const bool is_protocol = field.first == "protocol";
    if (field.first == "protocol") {
      render_value = AMStr::uppercase(render_value);
    }
    if (field.first == "cmd_template") {
      render_value = "\"" + render_value + "\"";
    } else if (render_value.empty()) {
      render_value = "\"\"";
    }
    if (is_protocol) {
      render_value = style_service.Format(
          render_value, AMInterface::style::StyleIndex::Protocol);
    }
    std::ostringstream line;
    line << std::left << std::setw(static_cast<int>(width)) << field.first
         << " :   " << render_value;
    prompt.Print(line.str());
  }
}

void PrintClientDetail(
    PromptIOManager &prompt, const std::string &nickname,
    const ClientHandle &client,
    const std::optional<ECMData<AMDomain::filesystem::CheckResult>>
        &check_result,
    bool include_status) {
  if (!client) {
    prompt.Print(AMStr::fmt("\\[{}]", nickname));
    prompt.Print("status       :  ❌");
    prompt.Print("");
    return;
  }

  const auto request = client->ConfigPort().GetRequest();
  const auto metadata_opt = ClientAppService::GetClientMetadata(client);
  const ClientMetaData metadata =
      metadata_opt.has_value() ? *metadata_opt : ClientMetaData{};

  const auto request_fields = request.GetStrDict();
  const auto metadata_fields = metadata.GetStrDict();

  std::vector<std::pair<std::string, std::string>> fields = {};
  fields.reserve(request_fields.size() + metadata_fields.size());
  for (const auto &item : request_fields) {
    if (item.first == "nickname") {
      continue;
    }
    fields.push_back(item);
  }
  fields.insert(fields.end(), metadata_fields.begin(), metadata_fields.end());

  size_t width = include_status ? std::string("status").size() : 0;
  for (const auto &field : fields) {
    width = std::max(width, field.first.size());
  }

  auto print_field = [&prompt, width](const std::string &name,
                                      const std::string &value) {
    std::ostringstream line;
    line << std::left << std::setw(static_cast<int>(width)) << name << " :  "
         << value;
    prompt.Print(line.str());
  };

  prompt.Print(AMStr::fmt("\\[{}]", nickname));
  if (include_status) {
    const ECM rcm = check_result.has_value()
                        ? check_result->rcm
                        : Err(EC::ClientNotFound, "", "", "Client not found");
    print_field("status", (rcm) ? "✅" : "❌");
  }
  for (const auto &field : fields) {
    print_field(field.first, field.second);
  }
  prompt.Print("");
}

void PrintPoolClientDetail(
    PromptIOManager &prompt, const std::string &nickname, const std::string &id,
    bool is_leased, const ClientHandle &client,
    const std::optional<ECMData<AMDomain::filesystem::CheckResult>>
        &check_result,
    bool include_status) {
  if (!client) {
    prompt.Print(AMStr::fmt("\\[{}]", nickname));
    if (include_status) {
      prompt.Print("status    :  ❌");
    }
    prompt.Print(AMStr::fmt("id        :  {}", id));
    prompt.Print(AMStr::fmt("is_leased :  {}", is_leased ? "true" : "false"));
    prompt.Print("");
    return;
  }

  const auto request = client->ConfigPort().GetRequest();
  const auto metadata_opt = ClientAppService::GetClientMetadata(client);
  const ClientMetaData metadata =
      metadata_opt.has_value() ? *metadata_opt : ClientMetaData{};

  const auto request_fields = request.GetStrDict();
  const auto metadata_fields = metadata.GetStrDict();

  std::vector<std::pair<std::string, std::string>> fields = {};
  fields.reserve(request_fields.size() + metadata_fields.size() + 2);
  fields.push_back({"id", id});
  fields.push_back({"is_leased", is_leased ? "true" : "false"});
  for (const auto &item : request_fields) {
    if (item.first == "nickname") {
      continue;
    }
    fields.push_back(item);
  }
  fields.insert(fields.end(), metadata_fields.begin(), metadata_fields.end());

  size_t width = include_status ? std::string("status").size() : 0;
  for (const auto &field : fields) {
    width = std::max(width, field.first.size());
  }

  auto print_field = [&prompt, width](const std::string &name,
                                      const std::string &value) {
    std::ostringstream line;
    line << std::left << std::setw(static_cast<int>(width)) << name << " :  "
         << value;
    prompt.Print(line.str());
  };

  prompt.Print(AMStr::fmt("\\[{}]", nickname));
  if (include_status) {
    const ECM rcm =
        check_result.has_value()
            ? check_result->rcm
            : Err(EC::ClientNotFound, "", nickname, "Client not found");
    print_field("status", (rcm) ? "✅" : "❌");
  }
  for (const auto &field : fields) {
    print_field(field.first, field.second);
  }
  prompt.Print("");
}
} // namespace render

namespace hostui {
bool ParseBool_(const std::string &text, bool *out) {
  if (!out) {
    return false;
  }
  const std::string normalized = AMStr::lowercase(AMStr::Strip(text));
  if (normalized == "true" || normalized == "1" || normalized == "yes" ||
      normalized == "on") {
    *out = true;
    return true;
  }
  if (normalized == "false" || normalized == "0" || normalized == "no" ||
      normalized == "off") {
    *out = false;
    return true;
  }
  return false;
}

bool ParseInt64_(const std::string &text, int64_t *out) {
  if (!out) {
    return false;
  }
  const std::string trimmed = AMStr::Strip(text);
  if (trimmed.empty()) {
    return false;
  }
  std::istringstream iss(trimmed);
  int64_t value = 0;
  char extra = '\0';
  if (!(iss >> value)) {
    return false;
  }
  if (iss >> extra) {
    return false;
  }
  *out = value;
  return true;
}

std::vector<std::string>
DedupTargets_(const std::vector<std::string> &targets) {
  std::vector<std::string> normalized = {};
  normalized.reserve(targets.size());
  for (const auto &target : targets) {
    const std::string value = AMStr::Strip(target);
    if (value.empty()) {
      continue;
    }
    normalized.push_back(value);
  }
  return AMStr::DedupVectorKeepOrder(
      normalized, [](const std::string &value) { return value; });
}

std::string ResolveLocalUsername_() {
  std::string local_user = "";
#ifdef _WIN32
  AMStr::GetEnv("USERNAME", &local_user);
#else
  AMStr::GetEnv("USER", &local_user);
#endif
  return local_user.empty() ? std::string("local") : local_user;
}

int DefaultPortForProtocol_(ClientProtocol protocol) {
  if (protocol == ClientProtocol::FTP) {
    return AMDomain::host::DefaultFTPPort;
  }
  return AMDomain::host::DefaultSFTPPort;
}

std::string DefaultUsernameForProtocol_(ClientProtocol protocol) {
  if (protocol == ClientProtocol::FTP) {
    return "anonymous";
  }
  return ResolveLocalUsername_();
}

bool PromptHostText_(PromptIOManager &prompt, const std::string &label,
                     const std::string &placeholder, std::string *out,
                     bool allow_empty) {
  if (!out) {
    return false;
  }
  auto checker = [allow_empty](const std::string &value) {
    return allow_empty || !AMStr::Strip(value).empty();
  };
  auto input = prompt.Prompt(label, placeholder, checker, {});
  if (!input.has_value()) {
    return false;
  }
  *out = *input;
  return true;
}

bool PromptHostBool_(PromptIOManager &prompt, const std::string &label,
                     bool current, bool *out) {
  if (!out) {
    return false;
  }
  std::string input = current ? "true" : "false";
  const std::vector<std::pair<std::string, std::string>> literals = {
      {"true", "Enable"},
      {"false", "Disable"},
  };
  auto input_opt = prompt.LiteralPrompt(label, input, literals);
  if (!input_opt.has_value()) {
    return false;
  }
  input = *input_opt;
  bool parsed = current;
  if (!ParseBool_(input, &parsed)) {
    return false;
  }
  *out = parsed;
  return true;
}

bool PromptHostProtocol_(PromptIOManager &prompt, ClientProtocol current,
                         ClientProtocol *out) {
  if (!out) {
    return false;
  }
  std::string input = AMStr::lowercase(AMStr::ToString(current));
  if (input.empty() || input == "unknown") {
    input = "sftp";
  }
  const std::vector<std::pair<std::string, std::string>> literals = {
      {"sftp", "SFTP protocol"},
      {"ftp", "FTP protocol"},
      {"local", "Local protocol"},
  };
  auto input_opt = prompt.LiteralPrompt("Protocol: ", input, literals);
  if (!input_opt.has_value()) {
    return false;
  }
  input = *input_opt;
  *out = AMDomain::host::HostService::StrToProtocol(
      AMStr::lowercase(AMStr::Strip(input)));
  return true;
}

bool PromptHostInt64_(PromptIOManager &prompt, const std::string &label,
                      int64_t current, int64_t min_v, int64_t max_v,
                      int64_t *out, bool allow_empty = false) {
  if (!out) {
    return false;
  }
  while (true) {
    const std::string placeholder = std::to_string(current);
    auto checker = [min_v, max_v, allow_empty](const std::string &value) {
      const std::string stripped = AMStr::Strip(value);
      if (allow_empty && stripped.empty()) {
        return true;
      }
      int64_t parsed = 0;
      if (!ParseInt64_(stripped, &parsed)) {
        return false;
      }
      return parsed >= min_v && parsed <= max_v;
    };
    auto input_opt = prompt.Prompt(label, placeholder, checker, {});
    if (!input_opt.has_value()) {
      return false;
    }
    const std::string stripped = AMStr::Strip(*input_opt);
    if (allow_empty && stripped.empty()) {
      *out = current;
      return true;
    }
    int64_t parsed = 0;
    if (!ParseInt64_(stripped, &parsed)) {
      prompt.ErrorFormat(Err(EC::InvalidArg, "", "", "invalid integer value"));
      continue;
    }
    if (parsed < min_v || parsed > max_v) {
      prompt.ErrorFormat(
          Err(EC::InvalidArg, "", "",
              AMStr::fmt("value out of range [{}, {}]", min_v, max_v)));
      continue;
    }
    *out = parsed;
    return true;
  }
}

ECM ResolveHostConfig_(AMHostConfigManager &host_config_manager,
                       const std::string &nickname, HostConfig *out) {
  if (!out) {
    return Err(EC::InvalidArg, "", "", "null host config output");
  }
  ECMData<HostConfig> result = {};
  if (IsLocalNickname(nickname)) {
    result = host_config_manager.GetLocalConfig();
  } else {
    result = host_config_manager.GetClientConfig(nickname, true);
  }
  if (!(result.rcm)) {
    return result.rcm;
  }
  *out = result.data;
  return OK;
}

void PrintHostCompact_(
    PromptIOManager &prompt, AMStyleService &style_service,
    const std::vector<std::string> &nicknames,
    const std::unordered_set<std::string> *established_nicknames = nullptr,
    const std::unordered_set<std::string> *configured_nicknames = nullptr) {
  if (nicknames.empty()) {
    prompt.Print("");
    return;
  }
  const size_t max_width = 80;
  size_t current_width = 0;
  std::ostringstream line;
  for (const auto &nickname : nicknames) {
    const size_t display_len = nickname.size();
    const size_t separator_len = current_width == 0 ? 0 : 3;
    if (current_width + separator_len + display_len > max_width &&
        current_width > 0) {
      prompt.Print(line.str());
      line.str(std::string());
      line.clear();
      current_width = 0;
    }
    if (current_width > 0) {
      line << "   ";
      current_width += 3;
    }
    const std::string normalized_nickname = NormalizeNickname(nickname);
    const bool established =
        established_nicknames != nullptr &&
        established_nicknames->contains(normalized_nickname);
    const bool configured = configured_nicknames != nullptr &&
                            configured_nicknames->contains(normalized_nickname);
    const auto style_index =
        established
            ? AMInterface::style::StyleIndex::Nickname
            : (configured
                   ? AMInterface::style::StyleIndex::UnestablishedNickname
                   : AMInterface::style::StyleIndex::NonexistentNickname);
    line << style_service.Format(nickname, style_index);
    current_width += display_len;
  }
  if (current_width > 0) {
    prompt.Print(line.str());
  }
}

struct HostListRow {
  std::string protocol = {};
  std::string nickname = {};
  std::string username = {};
  std::string port = {};
  std::string hostname = {};
};

HostListRow BuildHostListRow_(const std::string &nickname,
                              const HostConfig &entry) {
  HostListRow row = {};
  row.protocol = AMStr::fmt(
      "[{}]", AMStr::uppercase(AMStr::ToString(entry.request.protocol)));
  row.nickname = nickname;
  row.username = entry.request.username;
  row.port = std::to_string(entry.request.port);
  row.hostname = entry.request.hostname;
  return row;
}

void PrintHostListTable_(PromptIOManager &prompt, AMStyleService &style_service,
                         const std::vector<HostListRow> &rows) {
  if (rows.empty()) {
    prompt.Print("");
    return;
  }

  size_t protocol_width = std::string("Protocol").size();
  size_t nickname_width = std::string("Nickname").size();
  size_t username_width = std::string("Username").size();
  size_t port_width = std::string("Port").size();
  size_t hostname_width = std::string("Hostname").size();

  for (const auto &row : rows) {
    protocol_width = std::max(protocol_width, row.protocol.size());
    nickname_width = std::max(nickname_width, row.nickname.size());
    username_width = std::max(username_width, row.username.size());
    port_width = std::max(port_width, row.port.size());
    hostname_width = std::max(hostname_width, row.hostname.size());
  }

  auto print_row = [&](const HostListRow &row, bool is_header) {
    const std::string protocol =
        AMStr::PadRightUtf8(row.protocol, protocol_width);
    const std::string nickname =
        AMStr::PadRightUtf8(row.nickname, nickname_width);
    const std::string username =
        AMStr::PadRightUtf8(row.username, username_width);
    const std::string port = AMStr::PadRightUtf8(row.port, port_width);
    const std::string hostname =
        AMStr::PadRightUtf8(row.hostname, hostname_width);

    if (is_header) {
      prompt.Print(AMStr::fmt("{}  {}  {}  {}  {}", protocol, nickname,
                              username, port, hostname));
      return;
    }

    prompt.Print(AMStr::fmt(
        "{}  {}  {}  {}  {}",
        style_service.Format(protocol,
                             AMInterface::style::StyleIndex::Protocol),
        style_service.Format(nickname,
                             AMInterface::style::StyleIndex::Nickname),
        style_service.Format(username,
                             AMInterface::style::StyleIndex::Username),
        style_service.Format(port, AMInterface::style::StyleIndex::Number),
        style_service.Format(hostname,
                             AMInterface::style::StyleIndex::Nickname)));
  };

  print_row({"Protocol", "Nickname", "Username", "Port", "Hostname"}, true);
  for (const auto &row : rows) {
    print_row(row, false);
  }
}

std::string HostFieldDisplay_(const HostConfig &entry,
                              const std::string &field) {
  if (field == "hostname") {
    return entry.request.hostname;
  }
  if (field == "username") {
    return entry.request.username;
  }
  if (field == "port") {
    return std::to_string(entry.request.port);
  }
  if (field == "protocol") {
    return AMStr::lowercase(AMStr::ToString(entry.request.protocol));
  }
  if (field == "password") {
    return entry.request.password.empty() ? "\"\"" : "***";
  }
  if (field == "compression") {
    return entry.request.compression ? "true" : "false";
  }
  if (field == "cmd_template") {
    return entry.metadata.cmd_template;
  }
  if (field == "keyfile") {
    return entry.request.keyfile;
  }
  if (field == "trash_dir") {
    return entry.metadata.trash_dir;
  }
  if (field == "login_dir") {
    return entry.metadata.login_dir;
  }
  return "";
}

ECM PromptAddHostConfig_(PromptIOManager &prompt,
                         AMHostConfigManager &host_config_manager,
                         const std::string &nickname, HostConfig *out) {
  if (!out) {
    return Err(EC::InvalidArg, "", "", "null host config output");
  }
  HostConfig entry = {};

  std::string nickname_input = AMStr::Strip(nickname);
  auto nickname_checker = [&host_config_manager](const std::string &value) {
    const std::string stripped = AMStr::Strip(value);
    if (stripped.empty()) {
      return false;
    }
    const auto available = host_config_manager.CheckNicknameAvailable(stripped);
    return bool(available.rcm);
  };
  while (true) {
    if (nickname_input.empty()) {
      auto input = prompt.Prompt("Nickname: ", "", nickname_checker, {});
      if (!input.has_value()) {
        return Err(EC::ConfigCanceled, "", "", "input canceled");
      }
      nickname_input = AMStr::Strip(*input);
    }
    auto available = host_config_manager.CheckNicknameAvailable(nickname_input);
    if (!(available.rcm)) {
      prompt.ErrorFormat(available.rcm);
      nickname_input.clear();
      continue;
    }
    entry.request.nickname = available.data;
    break;
  }

  while (true) {
    if (!PromptHostProtocol_(prompt, ClientProtocol::SFTP,
                             &entry.request.protocol)) {
      return Err(EC::ConfigCanceled, "", "", "input canceled");
    }
    const std::string protocol =
        AMStr::lowercase(AMStr::ToString(entry.request.protocol));
    if (protocol == "sftp" || protocol == "ftp" || protocol == "local") {
      break;
    }
    prompt.ErrorFormat(
        Err(EC::InvalidArg, "", "", "protocol must be sftp, ftp or local"));
  }

  const bool hostname_required =
      entry.request.protocol != ClientProtocol::LOCAL;
  while (true) {
    std::string hostname = entry.request.hostname;
    if (!PromptHostText_(prompt, "Hostname: ", hostname, &hostname,
                         !hostname_required)) {
      return Err(EC::ConfigCanceled, "", "", "input canceled");
    }
    hostname = AMStr::Strip(hostname);
    if (hostname.empty()) {
      if (!hostname_required) {
        entry.request.hostname.clear();
        break;
      }
      prompt.ErrorFormat(
          Err(EC::InvalidArg, "", "", "hostname cannot be empty"));
      continue;
    }
    entry.request.hostname = hostname;
    break;
  }

  const std::string default_username =
      DefaultUsernameForProtocol_(entry.request.protocol);
  entry.request.username = default_username;
  while (true) {
    std::string username = entry.request.username;
    if (!PromptHostText_(prompt, "Username: ", default_username, &username,
                         !hostname_required)) {
      return Err(EC::ConfigCanceled, "", "", "input canceled");
    }
    username = AMStr::Strip(username);
    if (username.empty()) {
      username = default_username;
    }
    if (hostname_required && username.empty()) {
      prompt.ErrorFormat(
          Err(EC::InvalidArg, "", "", "username cannot be empty"));
      continue;
    }
    entry.request.username = username;
    break;
  }

  int64_t port = DefaultPortForProtocol_(entry.request.protocol);
  if (!PromptHostInt64_(prompt, AMStr::fmt("Port(default {}): ", port), port, 1,
                        65535, &port, true)) {
    return Err(EC::ConfigCanceled, "", "", "input canceled");
  }
  entry.request.port = static_cast<int>(port);

  while (true) {
    std::string first = "";
    auto first_opt = prompt.SecurePrompt("password(optional): ");
    if (!first_opt.has_value()) {
      AMAuth::SecureZero(first);
      return Err(EC::ConfigCanceled, "", "", "input canceled");
    }
    first = *first_opt;
    if (first.empty()) {
      entry.request.password.clear();
      AMAuth::SecureZero(first);
      break;
    }
    std::string second = "";
    auto second_opt = prompt.SecurePrompt("confirm password: ");
    if (!second_opt.has_value()) {
      AMAuth::SecureZero(first);
      AMAuth::SecureZero(second);
      return Err(EC::ConfigCanceled, "", "", "input canceled");
    }
    second = *second_opt;
    if (first != second) {
      AMAuth::SecureZero(first);
      AMAuth::SecureZero(second);
      prompt.ErrorFormat(Err(EC::InvalidArg, "", "", "Passwords do not match"));
      continue;
    }
    entry.request.password = AMAuth::EncryptPassword(first);
    AMAuth::SecureZero(first);
    AMAuth::SecureZero(second);
    break;
  }

  if (!PromptHostText_(prompt, "keyfile(optional): ", entry.request.keyfile,
                       &entry.request.keyfile, true)) {
    return Err(EC::ConfigCanceled, "", "", "input canceled");
  }

  if (!PromptHostBool_(prompt, "compression: ", false,
                       &entry.request.compression)) {
    return Err(EC::ConfigCanceled, "", "", "input canceled");
  }

  if (!PromptHostText_(prompt,
                       "trash_dir(optional): ", entry.metadata.trash_dir,
                       &entry.metadata.trash_dir, true)) {
    return Err(EC::ConfigCanceled, "", "", "input canceled");
  }
  if (!PromptHostText_(prompt,
                       "login_dir(optional): ", entry.metadata.login_dir,
                       &entry.metadata.login_dir, true)) {
    return Err(EC::ConfigCanceled, "", "", "input canceled");
  }
  if (!PromptHostText_(prompt,
                       "cmd_template(lua, optional): ",
                       entry.metadata.cmd_template,
                       &entry.metadata.cmd_template, true)) {
    return Err(EC::ConfigCanceled, "", "", "input canceled");
  }

  *out = entry;
  return OK;
}

ECM PromptModifyHostConfig_(PromptIOManager &prompt,
                            const std::string &nickname, HostConfig *inout) {
  if (!inout) {
    return Err(EC::InvalidArg, "", "", "null host config");
  }
  HostConfig entry = *inout;
  const ClientProtocol original_protocol = entry.request.protocol;

  while (true) {
    if (!PromptHostProtocol_(prompt, entry.request.protocol,
                             &entry.request.protocol)) {
      return Err(EC::ConfigCanceled, "", "", "input canceled");
    }
    const std::string protocol =
        AMStr::lowercase(AMStr::ToString(entry.request.protocol));
    if (protocol == "sftp" || protocol == "ftp" || protocol == "local") {
      break;
    }
    prompt.ErrorFormat(
        Err(EC::InvalidArg, "", "", "protocol must be sftp, ftp or local"));
  }

  const ClientProtocol selected_protocol = entry.request.protocol;
  const bool protocol_changed = selected_protocol != original_protocol;
  const bool hostname_required = selected_protocol != ClientProtocol::LOCAL;
  const std::string default_username =
      DefaultUsernameForProtocol_(selected_protocol);
  const int default_port = DefaultPortForProtocol_(selected_protocol);

  while (true) {
    std::string hostname = entry.request.hostname;
    if (!PromptHostText_(prompt, "Hostname: ", hostname, &hostname,
                         !hostname_required)) {
      return Err(EC::ConfigCanceled, "", "", "input canceled");
    }
    hostname = AMStr::Strip(hostname);
    if (hostname.empty()) {
      if (!hostname_required) {
        entry.request.hostname.clear();
        break;
      }
      prompt.ErrorFormat(
          Err(EC::InvalidArg, "", "", "hostname cannot be empty"));
      continue;
    }
    entry.request.hostname = hostname;
    break;
  }

  while (true) {
    std::string username = (protocol_changed || entry.request.username.empty())
                               ? default_username
                               : entry.request.username;
    if (!PromptHostText_(prompt, "Username: ", username, &username,
                         !hostname_required)) {
      return Err(EC::ConfigCanceled, "", "", "input canceled");
    }
    username = AMStr::Strip(username);
    if (username.empty()) {
      username = default_username;
    }
    if (hostname_required && username.empty()) {
      prompt.ErrorFormat(
          Err(EC::InvalidArg, "", "", "username cannot be empty"));
      continue;
    }
    entry.request.username = username;
    break;
  }

  int64_t port = (protocol_changed || entry.request.port <= 0 ||
                  entry.request.port > 65535)
                     ? default_port
                     : entry.request.port;
  if (!PromptHostInt64_(prompt, AMStr::fmt("Port(default {}): ", default_port),
                        port, 1, 65535, &port, true)) {
    return Err(EC::ConfigCanceled, "", "", "input canceled");
  }
  entry.request.port = static_cast<int>(port);

  bool canceled = false;
  const bool change_password =
      prompt.PromptYesNo("Change password? (y/N): ", &canceled);
  if (canceled) {
    return Err(EC::ConfigCanceled, "", "", "input canceled");
  }
  if (change_password) {
    while (true) {
      std::string first = "";
      auto first_opt = prompt.SecurePrompt("password(optional): ");
      if (!first_opt.has_value()) {
        AMAuth::SecureZero(first);
        return Err(EC::ConfigCanceled, "", "", "input canceled");
      }
      first = *first_opt;
      if (first.empty()) {
        entry.request.password.clear();
        AMAuth::SecureZero(first);
        break;
      }
      std::string second = "";
      auto second_opt = prompt.SecurePrompt("confirm password: ");
      if (!second_opt.has_value()) {
        AMAuth::SecureZero(first);
        AMAuth::SecureZero(second);
        return Err(EC::ConfigCanceled, "", "", "input canceled");
      }
      second = *second_opt;
      if (first != second) {
        AMAuth::SecureZero(first);
        AMAuth::SecureZero(second);
        prompt.ErrorFormat(
            Err(EC::InvalidArg, "", "", "Passwords do not match"));
        continue;
      }
      entry.request.password = AMAuth::EncryptPassword(first);
      AMAuth::SecureZero(first);
      AMAuth::SecureZero(second);
      break;
    }
  }

  if (!PromptHostText_(prompt, "keyfile(optional): ", entry.request.keyfile,
                       &entry.request.keyfile, true)) {
    return Err(EC::ConfigCanceled, "", "", "input canceled");
  }

  if (!PromptHostBool_(prompt, "Compression (true/false): ",
                       entry.request.compression, &entry.request.compression)) {
    return Err(EC::ConfigCanceled, "", "", "input canceled");
  }
  if (!PromptHostText_(prompt,
                       "trash_dir(optional): ", entry.metadata.trash_dir,
                       &entry.metadata.trash_dir, true)) {
    return Err(EC::ConfigCanceled, "", "", "input canceled");
  }
  if (!PromptHostText_(prompt,
                       "login_dir(optional): ", entry.metadata.login_dir,
                       &entry.metadata.login_dir, true)) {
    return Err(EC::ConfigCanceled, "", "", "input canceled");
  }
  if (!PromptHostText_(prompt,
                       "cmd_template(lua, optional): ",
                       entry.metadata.cmd_template,
                       &entry.metadata.cmd_template, true)) {
    return Err(EC::ConfigCanceled, "", "", "input canceled");
  }

  entry.request.nickname = nickname;
  *inout = entry;
  return OK;
}
} // namespace hostui

} // namespace

ClientInterfaceService::ClientInterfaceService(
    ClientAppService &client_service, TermAppService &terminal_service,
    FilesystemAppService &filesystem_service,
    AMHostConfigManager &host_config_manager,
    AMKnownHostsManager &known_hosts_manager,
    PromptIOManager &prompt_io_manager, AMStyleService &style_service)
    : client_service_(client_service), terminal_service_(terminal_service),
      filesystem_service_(filesystem_service),
      host_config_manager_(host_config_manager),
      known_hosts_manager_(known_hosts_manager),
      prompt_io_manager_(prompt_io_manager), style_service_(style_service),
      spinner_(std::make_unique<ClientConnectSpinner>(prompt_io_manager)) {}

ClientInterfaceService::~ClientInterfaceService() = default;

void ClientInterfaceService::SetDefaultControlToken(const amf &token) {
  default_control_token_ = token;
}

amf ClientInterfaceService::GetDefaultControlToken() const {
  return default_control_token_;
}

void ClientInterfaceService::BindInteractionCallbacks() {
  const AMDomain::client::TraceCallback maintainer_trace_prev =
      client_service_.GetMaintainerCallbacks().trace;
  const AMDomain::client::TraceCallback public_trace_prev =
      client_service_.GetPublicCallbacks().trace;
  const AMDomain::client::ConnectStateCallback maintainer_connect_state_prev =
      client_service_.GetMaintainerCallbacks().connect_state;
  const AMDomain::client::ConnectStateCallback public_connect_state_prev =
      client_service_.GetPublicCallbacks().connect_state;
  const auto make_trace_callback =
      [this](AMDomain::client::TraceCallback next_cb) {
        return [this, next_cb = std::move(next_cb)](const TraceInfo &info) {
          if (spinner_ && info.action == "connect.state") {
            spinner_->UpdateStateInfo(info.message);
          }
          if (next_cb) {
            (void)CallCallbackSafe(next_cb, info);
          }
        };
      };
  const auto make_connect_state_callback =
      [this](AMDomain::client::ConnectStateCallback next_cb) {
        return [this, next_cb = std::move(next_cb)](
                   const std::string &state_info, const std::string &target) {
          (void)target;
          if (spinner_) {
            spinner_->UpdateStateInfo(state_info);
          }
          if (next_cb) {
            (void)CallCallbackSafe(next_cb, state_info, target);
          }
        };
      };

  AMDomain::client::DisconnectCallback disconnect_callback =
      [this](const ClientHandle &client, const ECM &rcm) {
        if (!client) {
          return;
        }
        const auto request = client->ConfigPort().GetRequest();
        const std::string ec_name = std::string(AMStr::ToString(rcm.code));
        const std::string protocol =
            std::string(AMStr::ToString(request.protocol));
        const std::string nickname = request.nickname.empty()
                                         ? client->ConfigPort().GetNickname()
                                         : request.nickname;
        if (!nickname.empty()) {
          (void)terminal_service_.RemoveTerminal(nickname, {});
        }
        const std::string error_text = AMStr::Strip(rcm.error).empty()
                                           ? AMStr::Strip(rcm.msg())
                                           : AMStr::Strip(rcm.error);
        std::string disconnect_note =
            AMStr::fmt("🛑 \\[{}] Client {} disconnected! (ec={}, error={})",
                       protocol, nickname, ec_name, error_text);
        if (!disconnect_note.empty() && disconnect_note.front() != '\n' &&
            ic_is_editline_active()) {
          disconnect_note.insert(disconnect_note.begin(), '\n');
        }
        prompt_io_manager_.Print(disconnect_note);
      };

  AMDomain::client::KnownHostCallback known_host_callback =
      [this](const AMDomain::client::KnownHostQuery &query) -> ECM {
    if (spinner_) {
      spinner_->StopForPrompt();
    }
    if (!AMDomain::host::KnownHostRules::ValidateConfig(query)) {
      return Err(EC::InvalidArg, "", "", "invalid known host query");
    }

    auto stored = query;
    const ECM find_rcm = known_hosts_manager_.FindKnownHost(stored);
    if (!(find_rcm)) {
      bool canceled = false;
      const auto print_known_host_field = [this](const std::string &label,
                                                 const std::string &value) {
        constexpr size_t kLabelWidth = 22;
        prompt_io_manager_.FmtPrint(
            "{}{}", AMStr::PadRightUtf8(label, kLabelWidth), value);
      };

      print_known_host_field(
          "Unknown host:",
          AMStr::fmt("{}@{}:{}", query.username, query.hostname, query.port));
      print_known_host_field(
          "Protocol:",
          style_service_.Format(query.protocol,
                                AMInterface::style::StyleIndex::Protocol));
      print_known_host_field("Fingerprint:",
                             AMStr::Strip(query.GetFingerprint()));
      const bool accepted = prompt_io_manager_.PromptYesNo(
          "Trust this host key? (y/N): ", &canceled);
      if (canceled || !accepted) {
        return Err(EC::ConfigCanceled, "", "",
                   "Known host fingerprint add canceled");
      }
      return known_hosts_manager_.UpsertKnownHost(query, true);
    }

    const std::string expected = AMStr::Strip(stored.GetFingerprint());
    const std::string actual = AMStr::Strip(query.GetFingerprint());
    if (expected != actual) {
      return Err(EC::HostFingerprintMismatch, "", "",
                 AMStr::fmt("{}:{} {} fingerprint mismatches", query.hostname,
                            query.port, query.protocol));
    }
    return OK;
  };

  AMDomain::client::AuthCallback auth_callback =
      [this](const AMDomain::client::AuthCBInfo &info)
      -> std::optional<std::string> {
    if (spinner_) {
      spinner_->StopForPrompt();
    }
    const std::string client_name =
        info.request.nickname.empty() ? "unknown" : info.request.nickname;
    if (info.NeedPassword) {
      auto password = prompt_io_manager_.SecurePrompt(
          AMStr::fmt("Password required [{}]: ", client_name));
      if (!password.has_value()) {
        return std::string();
      }
      return *password;
    }
    if (!info.iscorrect) {
      if (info.password_n.empty()) {
        return std::nullopt;
      }
      prompt_io_manager_.FmtPrint("Wrong password [{}]", client_name);
      return std::nullopt;
    }

    auto cfg = host_config_manager_.GetClientConfig(client_name, true);
    if ((cfg.rcm)) {
      std::string password = info.password_n;
      if (!password.empty() && !AMAuth::IsEncrypted(password)) {
        password = AMAuth::EncryptPassword(password);
      }
      cfg.data.request.password = password;
      (void)host_config_manager_.AddHost(cfg.data, true);
    }
    return std::nullopt;
  };

  client_service_.RegisterMaintainerCallbacks(
      disconnect_callback, make_trace_callback(maintainer_trace_prev),
      make_connect_state_callback(maintainer_connect_state_prev),
      known_host_callback, auth_callback);
  client_service_.RegisterPublicCallbacks(
      disconnect_callback, make_trace_callback(public_trace_prev),
      make_connect_state_callback(public_connect_state_prev),
      known_host_callback, auth_callback);
  ClientAppService::ConnectHooks hooks = {};
  hooks.before_connect = [this](const HostConfig &hook_config,
                                const ClientHandle &, bool silent) {
    if (spinner_) {
      spinner_->Start(hook_config, silent);
    }
  };
  hooks.after_connect = [this](const HostConfig &, const ClientHandle &, bool,
                               const ECM &) {
    if (spinner_) {
      spinner_->Stop();
    }
  };
  client_service_.SetConnectHooks(std::move(hooks));
}

ControlComponent ClientInterfaceService::ResolveControl_(
    const std::optional<ControlComponent> &component) const {
  if (component.has_value()) {
    return component.value();
  }
  return {default_control_token_, 0};
}

ECM ClientInterfaceService::Connect(
    const ConnectRequest &request,
    const std::optional<ControlComponent> &component) {
  if (request.nicknames.empty()) {
    return Err(EC::InvalidArg, "", "",
               "connect requires at least one nickname");
  }
  const std::vector<std::string> targets =
      AMStr::UniqueTargetsKeepOrder(request.nicknames);
  const ControlComponent control = ResolveControl_(component);
  ECM status = OK;

  for (const auto &raw : targets) {
    if (control.IsInterrupted()) {
      return Err(EC::Terminate, "", "", "Interrupted by user");
    }

    const std::string nickname = AMStr::Strip(raw);
    if (nickname.empty()) {
      status =
          MergeStatus_(status, Err(EC::InvalidArg, "", "", "Empty nickname"));
      continue;
    }
    if (!IsLocalNickname(nickname) &&
        !AMDomain::host::HostService::ValidateNickname(nickname)) {
      status =
          MergeStatus_(status, Err(EC::InvalidArg, "", "", "Invalid nickname"));
      continue;
    }
    if (IsLocalNickname(nickname)) {
      prompt_io_manager_.Print(BuildConnectSuccessLine_(style_service_, "local",
                                                        ClientProtocol::LOCAL));
      continue;
    }

    if (!request.force) {
      auto existing = client_service_.GetClient(nickname, true);
      const bool existed_before = (existing.rcm) && existing.data;

      auto ensured =
          client_service_.EnsureClient(nickname, control, true, false);
      status = MergeStatus_(status, ensured.rcm);
      if (!(ensured.rcm) || !ensured.data) {
        continue;
      }
      const ECM ensure_rcm =
          filesystem_service_.EnsureClientWorkdir(ensured.data, control);
      status = MergeStatus_(status, ensure_rcm);
      if (!(ensure_rcm)) {
        continue;
      }

      if (existed_before) {
        const std::string ensured_nickname =
            ensured.data->ConfigPort().GetNickname();
        const std::optional<ECMData<AMDomain::filesystem::CheckResult>>
            checked = client_service_.CheckClient(ensured_nickname, false, true,
                                                  control);
        if (!checked.has_value()) {
          status =
              MergeStatus_(status, Err(EC::ClientNotFound, "connect_clients",
                                       ensured_nickname, "Client not found"));
          continue;
        }
        if (!(checked.value().rcm)) {
          const std::optional<ECMData<AMDomain::filesystem::CheckResult>>
              rechecked = client_service_.CheckClient(ensured_nickname, true,
                                                      true, control);
          if (!rechecked.has_value()) {
            status =
                MergeStatus_(status, Err(EC::ClientNotFound, "connect_clients",
                                         ensured_nickname, "Client not found"));
            continue;
          }
          status = MergeStatus_(status, rechecked.value().rcm);
          if (!(rechecked.value().rcm)) {
            continue;
          }
        }
      }
      prompt_io_manager_.Print(BuildConnectSuccessLine_(
          style_service_, ensured.data->ConfigPort().GetNickname(),
          ensured.data->ConfigPort().GetProtocol()));
      continue;
    }

    auto cfg_result = host_config_manager_.GetClientConfig(nickname, true);
    if (!(cfg_result.rcm)) {
      status = MergeStatus_(status, cfg_result.rcm);
      continue;
    }

    auto created =
        client_service_.CreateClient(cfg_result.data, control, false);
    if (!(created.rcm) || !created.data) {
      status = MergeStatus_(status, created.rcm);
      continue;
    }

    ECM add_rcm = client_service_.AddClient(created.data, request.force);
    status = MergeStatus_(status, add_rcm);
    if ((add_rcm)) {
      const ECM ensure_rcm =
          filesystem_service_.EnsureClientWorkdir(created.data, control);
      status = MergeStatus_(status, ensure_rcm);
      if ((ensure_rcm)) {
        prompt_io_manager_.Print(BuildConnectSuccessLine_(
            style_service_, created.data->ConfigPort().GetNickname(),
            created.data->ConfigPort().GetProtocol()));
      }
    }
  }
  if (!(status)) {
    prompt_io_manager_.ErrorFormat(status);
  }
  return status;
}

ECM ClientInterfaceService::ChangeClient(
    const ChangeClientRequest &request,
    const std::optional<ControlComponent> &component) {
  const ControlComponent control = ResolveControl_(component);
  if (control.IsInterrupted()) {
    return Err(EC::Terminate, "change_client", request.nickname,
               "Interrupted by user");
  }

  std::string nickname = {};
  ECM resolve_rcm = ResolveChangeClientNickname_(
      prompt_io_manager_, client_service_, host_config_manager_,
      request.nickname, &nickname);
  if (!(resolve_rcm)) {
    prompt_io_manager_.ErrorFormat(resolve_rcm);
    return resolve_rcm;
  }

  auto changed = client_service_.ChangeClient(nickname, control, request.quiet);
  if (!(changed.rcm) || !changed.data) {
    prompt_io_manager_.ErrorFormat(changed.rcm);
    return changed.rcm;
  }
  ECM ensure_cwd_rcm =
      filesystem_service_.EnsureClientWorkdir(changed.data, control);
  if (!(ensure_cwd_rcm)) {
    prompt_io_manager_.ErrorFormat(ensure_cwd_rcm);
    return ensure_cwd_rcm;
  }
  const ECM change_prompt_rcm =
      prompt_io_manager_.ChangeClient(changed.data->ConfigPort().GetNickname());
  if (!(change_prompt_rcm)) {
    prompt_io_manager_.ErrorFormat(change_prompt_rcm);
  } else {
    const std::string styled_nickname =
        style_service_.Format(changed.data->ConfigPort().GetNickname(),
                              AMInterface::style::StyleIndex::Nickname);
    prompt_io_manager_.Print(AMStr::fmt("✅ Connected: {}", styled_nickname));
  }
  return change_prompt_rcm;
}

ECM ClientInterfaceService::ConnectProtocol_(
    const ProtocolConnectRequest &request, ClientProtocol protocol,
    const std::optional<ControlComponent> &component) {
  constexpr const char *kOp = "connect_protocol";
  std::string nickname = AMStr::Strip(request.nickname);
  const ControlComponent control = ResolveControl_(component);
  std::string username = "";
  std::string hostname = "";
  if (protocol == ClientProtocol::LOCAL) {
    username = hostui::DefaultUsernameForProtocol_(protocol);
    hostname = "localhost";
    if (!AMStr::Strip(request.user_at_host).empty() &&
        !ParseUserAtHost_(request.user_at_host, &username, &hostname)) {
      return Err(EC::InvalidArg, "connect_protocol.parse_user_host",
                 request.user_at_host, "Invalid user@host format");
    }
  } else if (!ParseUserAtHost_(request.user_at_host, &username, &hostname)) {
    return Err(EC::InvalidArg, "connect_protocol.parse_user_host",
               request.user_at_host, "Invalid user@host format");
  }
  while (true) {
    if (control.IsInterrupted()) {
      return Err(EC::Terminate, kOp, "<control>", "Interrupted by user");
    }
    if (nickname.empty()) {
      auto prompted_nickname =
          prompt_io_manager_.Prompt("Enter a legal nickname: ");
      if (!prompted_nickname.has_value()) {
        const ECM rcm =
            Err(EC::ConfigCanceled, "connect_protocol.prompt_nickname",
                "<prompt>", "Nickname input canceled");
        prompt_io_manager_.ErrorFormat(rcm);
        return rcm;
      }
      nickname = AMStr::Strip(*prompted_nickname);
      if (nickname.empty()) {
        prompt_io_manager_.ErrorFormat(
            Err(EC::InvalidArg, "connect_protocol.prompt_nickname",
                "<nickname>", "Nickname cannot be empty"));
        continue;
      }
    }
    const auto available =
        host_config_manager_.CheckNicknameAvailable(nickname);
    if (!(available.rcm)) {
      prompt_io_manager_.ErrorFormat(available.rcm);
      nickname.clear();
      continue;
    }
    nickname = available.data;
    break;
  }

  if (protocol != ClientProtocol::LOCAL &&
      (request.port <= 0 || request.port > 65535)) {
    return Err(EC::InvalidArg, "connect_protocol.validate_port",
               std::to_string(request.port),
               "Port must be in range [1, 65535]");
  }

  HostConfig cfg = {};
  cfg.request.nickname = nickname;
  cfg.request.protocol = protocol;
  cfg.request.username = username;
  cfg.request.hostname = hostname;
  cfg.request.port = request.port;
  cfg.request.password = request.password;
  cfg.request.keyfile = request.keyfile;

  ECM validate_rcm = AMDomain::host::HostService::ValidateConfig(cfg);
  if (!(validate_rcm)) {
    return validate_rcm;
  }

  auto created = client_service_.CreateClient(cfg, control, false);
  if (!(created.rcm) || !created.data) {
    return created.rcm;
  }

  ECM add_rcm = client_service_.AddClient(created.data, true);
  if (!(add_rcm)) {
    return add_rcm;
  }

  ECM persist_rcm = host_config_manager_.AddHost(cfg, true);
  if (!(persist_rcm)) {
    return persist_rcm;
  }

  client_service_.SetCurrentClient(created.data);
  const ECM change_prompt_rcm =
      prompt_io_manager_.ChangeClient(created.data->ConfigPort().GetNickname());
  if ((change_prompt_rcm)) {
    prompt_io_manager_.Print(BuildConnectSuccessLine_(
        style_service_, created.data->ConfigPort().GetNickname(),
        created.data->ConfigPort().GetProtocol()));
  }
  return change_prompt_rcm;
}

ECM ClientInterfaceService::ConnectSftp(
    const ProtocolConnectRequest &request,
    const std::optional<ControlComponent> &component) {
  return ConnectProtocol_(request, ClientProtocol::SFTP, component);
}

ECM ClientInterfaceService::ConnectFtp(
    const ProtocolConnectRequest &request,
    const std::optional<ControlComponent> &component) {
  return ConnectProtocol_(request, ClientProtocol::FTP, component);
}

ECM ClientInterfaceService::ConnectLocal(
    const ProtocolConnectRequest &request,
    const std::optional<ControlComponent> &component) {
  return ConnectProtocol_(request, ClientProtocol::LOCAL, component);
}

ECM ClientInterfaceService::RemoveClients(
    const RemoveClientsRequest &request,
    const std::optional<ControlComponent> &component) {
  constexpr const char *kOp = "remove_clients";
  if (request.nicknames.empty()) {
    const ECM rcm = Err(EC::InvalidArg, kOp, "<targets>", "Empty nickname");
    prompt_io_manager_.ErrorFormat(rcm);
    return rcm;
  }

  const ControlComponent control = ResolveControl_(component);
  if (control.IsInterrupted()) {
    return Err(EC::Terminate, kOp, "<control>", "Interrupted by user");
  }

  const std::vector<std::string> targets =
      AMStr::UniqueTargetsKeepOrder(request.nicknames);
  const std::vector<std::string> names = client_service_.GetClientNames();
  const std::string current = client_service_.CurrentNickname();
  const std::string current_lower = AMStr::lowercase(current);

  ECM last = OK;
  std::vector<std::string> valid_targets = {};
  struct RemovePreviewEntry {
    std::string protocol = {};
    std::string nickname = {};
    std::string endpoint = {};
    std::string styled_endpoint = {};
    size_t endpoint_width = 0;
    bool healthy = false;
    std::string error = {};
  };
  std::vector<RemovePreviewEntry> preview_entries = {};
  valid_targets.reserve(targets.size());
  preview_entries.reserve(targets.size());

  for (const auto &target : targets) {
    const std::string stripped = AMStr::Strip(target);
    const std::string lowered = AMStr::lowercase(stripped);
    if (stripped.empty()) {
      last = Err(EC::InvalidArg, kOp, "<empty>", "Invalid empty client name");
      prompt_io_manager_.ErrorFormat(last);
      continue;
    }
    if (lowered == "local") {
      last =
          Err(EC::InvalidArg, kOp, "local", "Local client cannot be removed");
      prompt_io_manager_.ErrorFormat(last);
      continue;
    }
    const std::string resolved =
        FindClientNicknameCaseInsensitive_(names, stripped);
    if (resolved.empty()) {
      last = Err(EC::ClientNotFound, kOp, stripped, "Client not established");
      prompt_io_manager_.ErrorFormat(last);
      continue;
    }

    valid_targets.push_back(resolved);
    auto client_result = client_service_.GetClient(resolved, true);
    if (!(client_result.rcm) || !client_result.data) {
      preview_entries.push_back(RemovePreviewEntry{
          "[UNKNOWN]", resolved, "<unknown>", "<unknown>",
          std::string("<unknown>").size(), false, "Connection lost"});
      continue;
    }
    const ClientHandle &client = client_result.data;
    const auto request_info = client->ConfigPort().GetRequest();
    const auto state = client->ConfigPort().GetState();
    const std::string username = AMStr::Strip(request_info.username);
    const std::string host = AMStr::Strip(request_info.hostname);
    const std::string port = std::to_string(request_info.port);
    const std::string endpoint = BuildEndpointRaw_(username, host, port);
    const std::string styled_endpoint =
        BuildEndpointStyled_(style_service_, username, host, port);
    const std::string protocol = AMStr::fmt(
        "[{}]", AMStr::uppercase(AMStr::ToString(request_info.protocol)));
    const bool healthy =
        (state.rcm.code == EC::Success) &&
        (state.data.status == AMDomain::client::ClientStatus::OK);
    std::string error_text = AMStr::Strip(state.rcm.error);
    if (!healthy && error_text.empty()) {
      error_text = "Connection lost";
    }
    preview_entries.push_back(RemovePreviewEntry{
        protocol, resolved, endpoint, styled_endpoint,
        AMStr::DisplayWidthUtf8(endpoint), healthy, error_text});
  }

  if (preview_entries.empty()) {
    return (last) ? Err(EC::ClientNotFound, kOp, "<targets>",
                        "No valid clients to remove")
                  : last;
  }

  size_t protocol_width = 0;
  size_t nickname_width = 0;
  size_t endpoint_width = 0;
  for (const auto &entry : preview_entries) {
    protocol_width = std::max(protocol_width, entry.protocol.size());
    nickname_width = std::max(nickname_width, entry.nickname.size());
    endpoint_width = std::max(endpoint_width, entry.endpoint_width);
  }

  for (const auto &entry : preview_entries) {
    const std::string styled_protocol = style_service_.Format(
        AMStr::PadRightUtf8(entry.protocol, protocol_width),
        AMInterface::style::StyleIndex::Protocol);
    const auto nickname_style =
        entry.healthy ? AMInterface::style::StyleIndex::Nickname
                      : AMInterface::style::StyleIndex::DisconnectedNickname;
    const std::string styled_nickname = style_service_.Format(
        AMStr::PadRightUtf8(entry.nickname, nickname_width), nickname_style);
    const std::string styled_endpoint = PadStyledCellRight_(
        entry.styled_endpoint, entry.endpoint_width, endpoint_width);
    if (entry.healthy) {
      prompt_io_manager_.Print(AMStr::fmt("{} {} {} ✅", styled_protocol,
                                          styled_nickname, styled_endpoint));
    } else {
      prompt_io_manager_.Print(AMStr::fmt("{} {} {} ❌ {}", styled_protocol,
                                          styled_nickname, styled_endpoint,
                                          entry.error));
    }
  }

  bool canceled = false;
  const bool confirmed = prompt_io_manager_.PromptYesNo(
      "Are you sure to remove these clients? (y/n) :", &canceled);
  if (canceled || !confirmed) {
    return Err(EC::ConfigCanceled, "remove_clients.confirm", "",
               "Remove clients canceled");
  }

  bool removed_current = false;
  for (const auto &target : valid_targets) {
    if (control.IsInterrupted()) {
      return Err(EC::Terminate, kOp, target, "Interrupted by user");
    }
    ECM rcm = client_service_.RemoveClient(target);
    if (!(rcm)) {
      prompt_io_manager_.ErrorFormat(rcm);
      last = rcm;
      continue;
    }
    if (!current_lower.empty() &&
        AMStr::lowercase(AMStr::Strip(target)) == current_lower) {
      removed_current = true;
    }
  }
  if (removed_current) {
    const ECM prompt_rcm = prompt_io_manager_.ChangeClient("local");
    if (!(prompt_rcm)) {
      prompt_io_manager_.ErrorFormat(prompt_rcm);
      return prompt_rcm;
    }
  }
  return last;
}

ECM ClientInterfaceService::ListClients(
    const ListClientsRequest &request,
    const std::optional<ControlComponent> &component) {
  constexpr const char *kOp = "list_clients";
  if (request.check) {
    CheckClientsRequest check_request = {};
    check_request.nicknames = request.nicknames;
    check_request.detail = request.detail;
    return CheckClients(check_request, component);
  }

  const ControlComponent control = ResolveControl_(component);
  ECM status = OK;
  const std::vector<std::string> established_names =
      client_service_.GetClientNames();
  std::vector<std::string> resolved_names =
      request.nicknames.empty()
          ? AMStr::UniqueTargetsKeepOrder(established_names)
          : NormalizedNicknames(request.nicknames);

  if (resolved_names.empty()) {
    return Err(EC::ClientNotFound, kOp, "<targets>", "No client to list");
  }

  if (!request.nicknames.empty()) {
    std::vector<std::string> filtered = {};
    filtered.reserve(resolved_names.size());
    for (const auto &nickname : resolved_names) {
      if (control.IsInterrupted()) {
        return Err(EC::Terminate, kOp, "<control>", "Interrupted by user");
      }
      if (IsLocalNickname(nickname)) {
        if (client_service_.GetLocalClient()) {
          filtered.emplace_back("local");
        } else {
          const ECM rcm = Err(EC::ClientNotFound, kOp, "local",
                              "Local client not initialized");
          prompt_io_manager_.ErrorFormat(rcm);
          status = MergeStatus_(status, rcm);
        }
        continue;
      }
      const std::string resolved =
          FindClientNicknameCaseInsensitive_(established_names, nickname);
      if (resolved.empty()) {
        const ECM rcm =
            Err(EC::ClientNotFound, kOp, nickname, "Client not found");
        prompt_io_manager_.ErrorFormat(rcm);
        status = MergeStatus_(status, rcm);
        continue;
      }
      filtered.push_back(resolved);
    }
    resolved_names = AMStr::UniqueTargetsKeepOrder(filtered);
  }

  if (resolved_names.empty()) {
    return (status) ? Err(EC::ClientNotFound, kOp, "<targets>",
                          "No valid clients to list")
                    : status;
  }

  if (!request.detail) {
    std::vector<std::pair<std::string, AMInterface::style::StyleIndex>>
        styled_nicknames = {};
    styled_nicknames.reserve(resolved_names.size());
    for (const auto &name : resolved_names) {
      ClientHandle client = nullptr;
      std::string display_name = name;
      if (IsLocalNickname(name)) {
        display_name = "local";
        client = client_service_.GetLocalClient();
      } else {
        auto result = client_service_.GetClient(name, true);
        if ((result.rcm)) {
          client = result.data;
        }
      }
      styled_nicknames.emplace_back(display_name,
                                    ResolveClientNicknameStyleByState_(client));
    }
    PrintStyledNicknamesCompact_(prompt_io_manager_, style_service_,
                                 styled_nicknames);
    return status;
  }

  for (const auto &nickname : resolved_names) {
    if (control.IsInterrupted()) {
      return Err(EC::Terminate, kOp, "<control>", "Interrupted by user");
    }

    ClientHandle client = nullptr;
    if (IsLocalNickname(nickname)) {
      client = client_service_.GetLocalClient();
    } else {
      auto result = client_service_.GetClient(nickname, true);
      if ((result.rcm)) {
        client = result.data;
      }
    }
    if (!client) {
      const ECM rcm =
          Err(EC::ClientNotFound, kOp, nickname, "Client not found");
      prompt_io_manager_.ErrorFormat(rcm);
      status = MergeStatus_(status, rcm);
      continue;
    }

    render::PrintClientDetail(prompt_io_manager_, nickname, client,
                              std::nullopt, false);
  }
  return status;
}

ECM ClientInterfaceService::CheckClients(
    const CheckClientsRequest &request,
    const std::optional<ControlComponent> &component) {
  constexpr const char *kOp = "check_clients";
  const ControlComponent control = ResolveControl_(component);
  ECM status = OK;

  const std::vector<std::string> established_names =
      client_service_.GetClientNames();
  std::vector<std::string> targets =
      request.nicknames.empty()
          ? AMStr::UniqueTargetsKeepOrder(established_names)
          : NormalizedNicknames(request.nicknames);
  if (targets.empty()) {
    return Err(EC::ClientNotFound, kOp, "<targets>", "No client to check");
  }

  std::vector<std::pair<std::string, ClientHandle>> clients = {};
  clients.reserve(targets.size());
  std::map<std::string,
           std::optional<ECMData<AMDomain::filesystem::CheckResult>>>
      checks = {};

  for (const auto &nickname : targets) {
    if (control.IsInterrupted()) {
      return Err(EC::Terminate, kOp, "<control>", "Interrupted by user");
    }

    ClientHandle client = nullptr;
    std::string display_name = nickname;
    if (IsLocalNickname(nickname)) {
      display_name = "local";
      client = client_service_.GetLocalClient();
    } else {
      const std::string resolved =
          FindClientNicknameCaseInsensitive_(established_names, nickname);
      if (!resolved.empty()) {
        display_name = resolved;
      }
      auto result = client_service_.GetClient(display_name, true);
      if ((result.rcm)) {
        client = result.data;
      }
    }

    if (!client) {
      const ECM rcm =
          Err(EC::ClientNotFound, kOp, display_name, "Client not found");
      prompt_io_manager_.ErrorFormat(rcm);
      status = MergeStatus_(status, rcm);
      checks[display_name] = std::nullopt;
      continue;
    }

    clients.emplace_back(display_name, client);
    const auto checked =
        client_service_.CheckClient(display_name, false, true, control);
    checks[display_name] = checked;
    const ECM rcm = checked.has_value() ? checked->rcm
                                        : Err(EC::ClientNotFound, kOp,
                                              display_name, "Client not found");
    status = MergeStatus_(status, rcm);
  }

  if (!request.detail) {
    const ClientStatusFormat format = BuildClientStatusFormat_(clients);
    for (const auto &entry : clients) {
      const ECM rcm =
          (checks.count(entry.first) != 0 && checks.at(entry.first).has_value())
              ? checks.at(entry.first)->rcm
              : Err(EC::ClientNotFound, kOp, entry.first, "Client not found");
      render::PrintClientStatusLine(prompt_io_manager_, entry.first,
                                    entry.second, rcm, format, style_service_);
    }
    return status;
  }

  for (const auto &entry : clients) {
    render::PrintClientDetail(prompt_io_manager_, entry.first, entry.second,
                              checks[entry.first], true);
  }
  return status;
}

ECM ClientInterfaceService::ClearClients(
    const ClearClientsRequest &request,
    const std::optional<ControlComponent> &component) {
  constexpr const char *kOp = "client.clear";
  int timeout_ms = 0;
  ECM timeout_rcm = TimeoutSecondsToMs_(request.timeout_s, kOp, &timeout_ms);
  if (!(timeout_rcm)) {
    prompt_io_manager_.ErrorFormat(timeout_rcm);
    return timeout_rcm;
  }

  const ControlComponent base_control = ResolveControl_(component);
  const auto clients = client_service_.GetClients();
  if (clients.empty()) {
    prompt_io_manager_.FmtPrint(
        "client clear: checked=0 removed=0 kept=0 skipped=0 timeout={}s",
        request.timeout_s);
    return OK;
  }

  const std::string current_lower =
      AMStr::lowercase(AMStr::Strip(client_service_.CurrentNickname()));
  ECM status = OK;
  size_t checked_count = 0U;
  size_t removed_count = 0U;
  size_t kept_count = 0U;
  size_t skipped_count = 0U;
  bool removed_current = false;

  for (const auto &[name, client] : clients) {
    if (base_control.IsInterrupted()) {
      return Err(EC::Terminate, kOp, name, "Interrupted by user");
    }

    ++checked_count;
    const std::string display_name =
        IsLocalNickname(name) ? std::string("local") : name;
    const ControlComponent check_control(base_control.ControlToken(),
                                         timeout_ms);
    const auto checked =
        client_service_.CheckClientHandle(client, false, true, check_control);
    const bool healthy =
        (checked.rcm) &&
        checked.data.status == AMDomain::client::ClientStatus::OK;

    if (healthy) {
      ++kept_count;
      prompt_io_manager_.FmtPrint("✅ Client kept: {} ({})", display_name,
                                  AMStr::ToString(checked.data.status));
      continue;
    }

    if (IsLocalNickname(display_name)) {
      ++skipped_count;
      prompt_io_manager_.FmtPrint("⚠️  Client skipped: local {} {}",
                                  AMStr::ToString(checked.rcm.code),
                                  checked.rcm.msg());
      continue;
    }

    const ECM remove_rcm = client_service_.RemoveClient(display_name);
    if (!(remove_rcm)) {
      status = MergeStatus_(status, remove_rcm);
      prompt_io_manager_.FmtPrint(
          "❌ Client remove failed: {} {} {}", display_name,
          AMStr::ToString(remove_rcm.code), remove_rcm.msg());
      continue;
    }

    ++removed_count;
    if (!current_lower.empty() &&
        AMStr::lowercase(AMStr::Strip(display_name)) == current_lower) {
      removed_current = true;
    }
    prompt_io_manager_.FmtPrint("🧹 Client removed: {} {} {}", display_name,
                                AMStr::ToString(checked.rcm.code),
                                checked.rcm.msg());
  }

  if (removed_current) {
    const ECM prompt_rcm = prompt_io_manager_.ChangeClient("local");
    if (!(prompt_rcm)) {
      prompt_io_manager_.ErrorFormat(prompt_rcm);
      status = MergeStatus_(status, prompt_rcm);
    }
  }

  prompt_io_manager_.FmtPrint(
      "client clear: checked={} removed={} kept={} skipped={} timeout={}s",
      checked_count, removed_count, kept_count, skipped_count,
      request.timeout_s);
  return status;
}

ECM ClientInterfaceService::PoolLs(
    const ListPoolClientsRequest &request,
    const std::optional<ControlComponent> &component) {
  constexpr const char *kOp = "pool_ls";
  const ControlComponent control = ResolveControl_(component);
  if (control.IsInterrupted()) {
    return Err(EC::Terminate, kOp, "<control>", "Interrupted by user");
  }

  ECM status = OK;
  const std::vector<std::string> public_names =
      client_service_.GetPublicClientNames();
  std::vector<std::string> resolved_names = {};

  if (!request.nicknames.empty()) {
    const std::vector<std::string> targets =
        AMStr::UniqueTargetsKeepOrder(request.nicknames);
    for (const auto &target : targets) {
      const std::string stripped = AMStr::Strip(target);
      if (stripped.empty()) {
        continue;
      }
      const std::string resolved =
          FindClientNicknameCaseInsensitive_(public_names, stripped);
      if (resolved.empty()) {
        const ECM rcm = Err(EC::ClientNotFound, kOp, stripped,
                            "Public pool client not found");
        prompt_io_manager_.ErrorFormat(rcm);
        status = MergeStatus_(status, rcm);
        continue;
      }
      if (std::find(resolved_names.begin(), resolved_names.end(), resolved) ==
          resolved_names.end()) {
        resolved_names.push_back(resolved);
      }
    }
    if (resolved_names.empty()) {
      return (status) ? Err(EC::ClientNotFound, kOp, "<targets>",
                            "No public pool client matched")
                      : status;
    }
  }

  const std::vector<ClientAppService::PublicClientInstance> instances =
      client_service_.ListPublicClients(resolved_names, false);
  if (instances.empty()) {
    if (!(status)) {
      return status;
    }
    return Err(EC::ClientNotFound, kOp, "<targets>",
               "No public pool client to list");
  }

  struct PoolRow {
    std::string id = {};
    std::string protocol = {};
    std::string nickname = {};
    bool is_leased = false;
    ClientHandle client = nullptr;
    std::optional<ECMData<AMDomain::filesystem::CheckResult>> checked =
        std::nullopt;
    ECM status_rcm = OK;
  };

  std::vector<PoolRow> rows = {};
  rows.reserve(instances.size());
  for (const auto &instance : instances) {
    if (control.IsInterrupted()) {
      return Err(EC::Terminate, kOp, "<control>", "Interrupted by user");
    }
    PoolRow row = {};
    row.id = instance.id;
    row.nickname = instance.nickname;
    row.client = instance.client;
    row.protocol = instance.client
                       ? AMStr::uppercase(AMStr::ToString(
                             instance.client->ConfigPort().GetProtocol()))
                       : std::string("UNKNOWN");

    const auto leased_result =
        ClientAppService::IsTransferLeased(instance.client);
    if ((leased_result.rcm)) {
      row.is_leased = leased_result.data;
    } else {
      status = MergeStatus_(status, leased_result.rcm);
      row.is_leased = false;
    }

    if (request.check) {
      row.checked = client_service_.CheckClientHandle(instance.client, false,
                                                      true, component);
      row.status_rcm = row.checked->rcm;
      status = MergeStatus_(status, row.status_rcm);
    }

    rows.push_back(std::move(row));
  }

  std::sort(rows.begin(), rows.end(),
            [](const PoolRow &lhs, const PoolRow &rhs) {
              if (lhs.nickname != rhs.nickname) {
                return lhs.nickname < rhs.nickname;
              }
              return lhs.id < rhs.id;
            });

  if (request.detail) {
    for (const auto &row : rows) {
      render::PrintPoolClientDetail(prompt_io_manager_, row.nickname, row.id,
                                    row.is_leased, row.client, row.checked,
                                    request.check);
    }
    return status;
  }

  size_t id_width = std::string("ID").size();
  size_t protocol_width = std::string("Protocol").size();
  size_t nickname_width = std::string("Nickname").size();
  size_t leased_width = std::string("IsLeased").size();
  for (const auto &row : rows) {
    id_width = std::max(id_width, row.id.size());
    protocol_width = std::max(protocol_width, row.protocol.size());
    nickname_width = std::max(nickname_width, row.nickname.size());
    leased_width = std::max(
        leased_width, std::string(row.is_leased ? "true" : "false").size());
  }

  std::ostringstream header;
  header << AMStr::PadRightUtf8("ID", id_width) << "  "
         << AMStr::PadRightUtf8("Protocol", protocol_width) << "  "
         << AMStr::PadRightUtf8("Nickname", nickname_width) << "  "
         << AMStr::PadRightUtf8("IsLeased", leased_width);
  if (request.check) {
    header << "  Status";
  }
  prompt_io_manager_.Print(header.str());

  for (const auto &row : rows) {
    const std::string styled_protocol =
        style_service_.Format(AMStr::PadRightUtf8(row.protocol, protocol_width),
                              AMInterface::style::StyleIndex::Protocol);
    const std::string styled_nickname =
        style_service_.Format(AMStr::PadRightUtf8(row.nickname, nickname_width),
                              ResolveClientNicknameStyleByState_(row.client));
    std::ostringstream line;
    line << AMStr::PadRightUtf8(row.id, id_width) << "  " << styled_protocol
         << "  " << styled_nickname << "  "
         << AMStr::PadRightUtf8(row.is_leased ? "true" : "false", leased_width);
    if (request.check) {
      line << "  " << ((row.status_rcm) ? "✅" : "❌");
    }
    prompt_io_manager_.Print(line.str());
  }
  return status;
}

ECM ClientInterfaceService::PoolCheck(
    const CheckPoolClientsRequest &request,
    const std::optional<ControlComponent> &component) {
  ListPoolClientsRequest ls_request = {};
  ls_request.nicknames = request.nicknames;
  ls_request.check = true;
  ls_request.detail = request.detail;
  return PoolLs(ls_request, component);
}

ECM ClientInterfaceService::PoolRm(
    const RemovePoolClientsRequest &request,
    const std::optional<ControlComponent> &component) {
  constexpr const char *kOp = "pool_rm";
  const std::string nickname = AMStr::Strip(request.nickname);
  if (nickname.empty()) {
    return Err(EC::InvalidArg, kOp, "<nickname>", "Pool nickname is empty");
  }
  const ControlComponent control = ResolveControl_(component);
  if (control.IsInterrupted()) {
    return Err(EC::Terminate, kOp, "<control>", "Interrupted by user");
  }

  const std::vector<std::string> public_names =
      client_service_.GetPublicClientNames();
  const std::string resolved =
      FindClientNicknameCaseInsensitive_(public_names, nickname);
  if (resolved.empty()) {
    return Err(EC::ClientNotFound, kOp, nickname,
               "Public pool client not found");
  }

  std::vector<ClientAppService::PublicClientInstance> instances =
      client_service_.ListPublicClients({resolved}, true);
  if (instances.empty()) {
    return Err(EC::ClientNotFound, kOp, resolved,
               "Public pool client not found");
  }

  struct RemoveRow {
    std::string id = {};
    std::string protocol = {};
    std::string nickname = {};
    bool is_leased = false;
    size_t order = std::numeric_limits<size_t>::max();
    ECM status_rcm = OK;
    ClientHandle client = nullptr;
  };

  std::vector<RemoveRow> rows = {};
  rows.reserve(instances.size());
  for (const auto &instance : instances) {
    RemoveRow row = {};
    row.id = instance.id;
    row.nickname = instance.nickname;
    row.client = instance.client;
    row.protocol = instance.client
                       ? AMStr::uppercase(AMStr::ToString(
                             instance.client->ConfigPort().GetProtocol()))
                       : std::string("UNKNOWN");

    const auto leased_result =
        ClientAppService::IsTransferLeased(instance.client);
    row.is_leased = (leased_result.rcm) ? leased_result.data : false;
    row.status_rcm =
        client_service_.CheckClientHandle(instance.client, false, true, control)
            .rcm;
    rows.push_back(std::move(row));
  }

  std::sort(rows.begin(), rows.end(),
            [](const RemoveRow &lhs, const RemoveRow &rhs) {
              if (lhs.nickname != rhs.nickname) {
                return lhs.nickname < rhs.nickname;
              }
              return lhs.id < rhs.id;
            });

  size_t order_counter = 0;
  std::unordered_map<size_t, size_t> order_to_index = {};
  for (size_t idx = 0; idx < rows.size(); ++idx) {
    if (rows[idx].is_leased) {
      continue;
    }
    rows[idx].order = order_counter;
    order_to_index[order_counter] = idx;
    ++order_counter;
  }
  if (order_to_index.empty()) {
    return Err(EC::PathUsingByOthers, kOp, resolved,
               "All public pool clients are leased");
  }

  size_t order_width = std::string("Order").size();
  size_t id_width = std::string("ID").size();
  size_t protocol_width = std::string("Protocol").size();
  size_t nickname_width = std::string("Nickname").size();
  size_t leased_width = std::string("IsLeased").size();
  for (const auto &row : rows) {
    if (row.order != std::numeric_limits<size_t>::max()) {
      order_width = std::max(order_width, AMStr::ToString(row.order).size());
    }
    id_width = std::max(id_width, row.id.size());
    protocol_width = std::max(protocol_width, row.protocol.size());
    nickname_width = std::max(nickname_width, row.nickname.size());
    leased_width = std::max(
        leased_width, std::string(row.is_leased ? "true" : "false").size());
  }

  std::ostringstream header;
  header << AMStr::PadRightUtf8("Order", order_width) << "  "
         << AMStr::PadRightUtf8("ID", id_width) << "  "
         << AMStr::PadRightUtf8("Protocol", protocol_width) << "  "
         << AMStr::PadRightUtf8("Nickname", nickname_width) << "  "
         << AMStr::PadRightUtf8("IsLeased", leased_width) << "  Status";
  prompt_io_manager_.Print(header.str());

  for (const auto &row : rows) {
    const std::string order_text =
        row.order == std::numeric_limits<size_t>::max()
            ? ""
            : AMStr::ToString(row.order);
    const std::string styled_protocol =
        style_service_.Format(AMStr::PadRightUtf8(row.protocol, protocol_width),
                              AMInterface::style::StyleIndex::Protocol);
    const std::string styled_nickname =
        style_service_.Format(AMStr::PadRightUtf8(row.nickname, nickname_width),
                              ResolveClientNicknameStyleByState_(row.client));
    std::ostringstream line;
    line << AMStr::PadRightUtf8(order_text, order_width) << "  "
         << AMStr::PadRightUtf8(row.id, id_width) << "  " << styled_protocol
         << "  " << styled_nickname << "  "
         << AMStr::PadRightUtf8(row.is_leased ? "true" : "false", leased_width)
         << "  " << ((row.status_rcm) ? "✅" : "❌");
    prompt_io_manager_.Print(line.str());
  }

  auto input = prompt_io_manager_.Prompt(
      "Type in order num of clients you want to remove: ");
  if (!input.has_value()) {
    prompt_io_manager_.PrintOperationAbort();
    return OK;
  }

  bool parsed_ok = false;
  const std::vector<size_t> selected_orders =
      ParseOrderNumbers_(*input, &parsed_ok);
  if (!parsed_ok) {
    return Err(EC::InvalidArg, kOp, resolved, "Invalid order numbers");
  }

  std::vector<std::pair<std::string, AMDomain::client::ClientID>>
      remove_targets = {};
  remove_targets.reserve(selected_orders.size());
  for (const size_t order : selected_orders) {
    auto order_it = order_to_index.find(order);
    if (order_it == order_to_index.end()) {
      return Err(EC::InvalidArg, kOp, AMStr::ToString(order),
                 "Order not removable");
    }
    const auto &row = rows[order_it->second];
    remove_targets.push_back({row.nickname, row.id});
  }

  const ECM remove_rcm = client_service_.RemovePublicClients(remove_targets);
  if (!(remove_rcm)) {
    prompt_io_manager_.ErrorFormat(remove_rcm);
  }
  return remove_rcm;
}

ECM ClientInterfaceService::ListPrivateKeys() {
  const std::vector<std::string> keys = host_config_manager_.PrivateKeys();
  prompt_io_manager_.Print("\\[Private Keys]");
  for (const auto &key : keys) {
    const std::string abs_path = AMPath::abspath(key, true, AMPath::HomePath());
    prompt_io_manager_.Print(abs_path);
  }
  return OK;
}

ECM ClientInterfaceService::AddHost(const std::string &nickname) {
  std::string seed_nickname = AMStr::Strip(nickname);
  if (!seed_nickname.empty()) {
    auto available = host_config_manager_.CheckNicknameAvailable(seed_nickname);
    if (!(available.rcm)) {
      prompt_io_manager_.ErrorFormat(available.rcm);
      return available.rcm;
    }
    seed_nickname = available.data;
  }

  HostConfig entry = {};
  const ECM prompt_rcm = hostui::PromptAddHostConfig_(
      prompt_io_manager_, host_config_manager_, seed_nickname, &entry);
  if (!(prompt_rcm)) {
    prompt_io_manager_.ErrorFormat(prompt_rcm);
    return prompt_rcm;
  }

  const ECM add_rcm = host_config_manager_.AddHost(entry, true);
  if (!(add_rcm)) {
    prompt_io_manager_.ErrorFormat(add_rcm);
  }
  return add_rcm;
}

ECM ClientInterfaceService::ModifyHost(const std::string &nickname) {
  if (!host_config_manager_.HostExists(nickname)) {
    const ECM rcm = Err(EC::HostConfigNotFound, "", "", "host not found");
    prompt_io_manager_.ErrorFormat(rcm);
    return rcm;
  }

  HostConfig updated = {};
  const ECM get_rcm =
      hostui::ResolveHostConfig_(host_config_manager_, nickname, &updated);
  if (!(get_rcm)) {
    prompt_io_manager_.ErrorFormat(get_rcm);
    return get_rcm;
  }

  const ECM prompt_rcm =
      hostui::PromptModifyHostConfig_(prompt_io_manager_, nickname, &updated);
  if (!(prompt_rcm)) {
    prompt_io_manager_.ErrorFormat(prompt_rcm);
    return prompt_rcm;
  }

  const ECM add_rcm = host_config_manager_.AddHost(updated, true);
  if (!(add_rcm)) {
    prompt_io_manager_.ErrorFormat(add_rcm);
  }
  return add_rcm;
}

ECM ClientInterfaceService::RenameHost(const std::string &old_nickname,
                                       const std::string &new_nickname) {
  ECM rcm = OK;
  if (old_nickname.empty() || new_nickname.empty()) {
    rcm = Err(EC::InvalidArg, "", "", "empty nickname");
    prompt_io_manager_.ErrorFormat(rcm);
    return rcm;
  }
  if (old_nickname == new_nickname) {
    rcm = Err(EC::InvalidArg, "", "", "new nickname same as old nickname");
    prompt_io_manager_.ErrorFormat(rcm);
    return rcm;
  }
  if (!ValidateNickname(new_nickname)) {
    rcm = Err(EC::InvalidArg, "", "",
              "invalid new nickname, pattern is [a-zA-Z0-9_-]+");
    prompt_io_manager_.ErrorFormat(rcm);
    return rcm;
  }
  if (host_config_manager_.HostExists(new_nickname)) {
    rcm = Err(EC::KeyAlreadyExists, "", "", "new nickname already exists");
    prompt_io_manager_.ErrorFormat(rcm);
    return rcm;
  }
  if (!host_config_manager_.HostExists(old_nickname)) {
    rcm = Err(EC::HostConfigNotFound, "", "", "old nickname not found");
    prompt_io_manager_.ErrorFormat(rcm);
    return rcm;
  }

  HostConfig old_cfg = {};
  rcm =
      hostui::ResolveHostConfig_(host_config_manager_, old_nickname, &old_cfg);
  if (!(rcm)) {
    prompt_io_manager_.ErrorFormat(rcm);
    return rcm;
  }
  old_cfg.request.nickname = NormalizeNickname(new_nickname);

  rcm = host_config_manager_.AddHost(old_cfg, false);
  if (!(rcm)) {
    prompt_io_manager_.ErrorFormat(rcm);
    return rcm;
  }

  rcm = host_config_manager_.DelHost(old_nickname);
  if (!(rcm)) {
    prompt_io_manager_.ErrorFormat(rcm);
  }
  return rcm;
}

ECM ClientInterfaceService::RemoveHosts(
    const std::vector<std::string> &nicknames) {
  constexpr const char *kOp = "remove_hosts";
  const std::vector<std::string> uniq_targets =
      hostui::DedupTargets_(nicknames);
  if (uniq_targets.empty()) {
    return OK;
  }

  ECM rcm = OK;
  std::vector<std::string> valid_targets = {};
  valid_targets.reserve(uniq_targets.size());

  for (const auto &name : uniq_targets) {
    const std::string raw = AMStr::Strip(name);
    if (raw.empty()) {
      rcm = Err(EC::InvalidArg, "", "", "invalid empty host nickname");
      prompt_io_manager_.ErrorFormat(rcm);
      continue;
    }
    if (IsLocalNickname(raw)) {
      rcm = Err(EC::InvalidArg, "", "", "local host cannot be removed");
      prompt_io_manager_.ErrorFormat(rcm);
      continue;
    }
    if (!ValidateNickname(raw)) {
      rcm = Err(EC::InvalidArg, "", "",
                AMStr::fmt("invalid host nickname literal: {}", raw));
      prompt_io_manager_.ErrorFormat(rcm);
      continue;
    }
    const std::string normalized = NormalizeNickname(raw);
    if (!host_config_manager_.HostExists(normalized)) {
      rcm = Err(EC::HostConfigNotFound, "", "",
                AMStr::fmt("host nickname not found: {}", normalized));
      prompt_io_manager_.ErrorFormat(rcm);
      continue;
    }
    valid_targets.push_back(normalized);
  }

  if (valid_targets.empty()) {
    return rcm;
  }

  struct HostRemovePreviewEntry {
    std::string protocol = {};
    std::string nickname = {};
    std::string endpoint = {};
    std::string styled_endpoint = {};
    size_t endpoint_width = 0;
    AMInterface::style::StyleIndex nickname_style =
        AMInterface::style::StyleIndex::Nickname;
  };
  std::vector<HostRemovePreviewEntry> preview_entries = {};
  preview_entries.reserve(valid_targets.size());

  for (const auto &name : valid_targets) {
    HostConfig host_cfg = {};
    const ECM cfg_rcm = hostui::ResolveHostConfig_(
        host_config_manager_, NormalizeNickname(name), &host_cfg);
    if (!(cfg_rcm)) {
      prompt_io_manager_.ErrorFormat(cfg_rcm);
      rcm = cfg_rcm;
      continue;
    }
    const std::string username = AMStr::Strip(host_cfg.request.username);
    const std::string hostname = AMStr::Strip(host_cfg.request.hostname);
    const std::string port = std::to_string(host_cfg.request.port);
    const std::string endpoint = BuildEndpointRaw_(username, hostname, port);
    const std::string styled_endpoint =
        BuildEndpointStyled_(style_service_, username, hostname, port);
    AMInterface::style::StyleIndex nickname_style =
        AMInterface::style::StyleIndex::UnestablishedNickname;
    auto client_result = client_service_.GetClient(name, true);
    if ((client_result.rcm) && client_result.data) {
      nickname_style = ResolveClientNicknameStyleByState_(client_result.data);
    }
    preview_entries.push_back(HostRemovePreviewEntry{
        AMStr::fmt("[{}]", AMStr::uppercase(
                               AMStr::ToString(host_cfg.request.protocol))),
        name, endpoint, styled_endpoint, AMStr::DisplayWidthUtf8(endpoint),
        nickname_style});
  }

  if (preview_entries.empty()) {
    return rcm;
  }

  size_t protocol_width = 0;
  size_t nickname_width = 0;
  size_t endpoint_width = 0;
  for (const auto &entry : preview_entries) {
    protocol_width = std::max(protocol_width, entry.protocol.size());
    nickname_width = std::max(nickname_width, entry.nickname.size());
    endpoint_width = std::max(endpoint_width, entry.endpoint_width);
  }

  for (const auto &entry : preview_entries) {
    const std::string styled_protocol = style_service_.Format(
        AMStr::PadRightUtf8(entry.protocol, protocol_width),
        AMInterface::style::StyleIndex::Protocol);
    const std::string styled_nickname = style_service_.Format(
        AMStr::PadRightUtf8(entry.nickname, nickname_width),
        entry.nickname_style);
    const std::string styled_endpoint = PadStyledCellRight_(
        entry.styled_endpoint, entry.endpoint_width, endpoint_width);
    prompt_io_manager_.Print(AMStr::fmt("{} {} {}", styled_protocol,
                                        styled_nickname, styled_endpoint));
  }

  bool canceled = false;
  const bool confirmed = prompt_io_manager_.PromptYesNo(
      "Are you sure to remove these hosts? (y/n) :", &canceled);
  if (canceled || !confirmed) {
    prompt_io_manager_.PrintOperationAbort();
    return OK;
  }

  const std::string current_nickname =
      NormalizeNickname(client_service_.CurrentNickname());
  bool removing_current = false;
  if (!current_nickname.empty() && !IsLocalNickname(current_nickname)) {
    for (const auto &name : valid_targets) {
      if (NormalizeNickname(name) == current_nickname) {
        removing_current = true;
        break;
      }
    }
  }

  if (removing_current) {
    auto local_result = client_service_.EnsureClient("local", true, true);
    if (!(local_result.rcm) || !local_result.data) {
      const ECM rcm = (local_result.rcm) ? Err(EC::InvalidHandle, "", "",
                                               "local client unavailable")
                                         : local_result.rcm;
      prompt_io_manager_.ErrorFormat(rcm);
      return rcm;
    }
    client_service_.SetCurrentClient(local_result.data);
    const ECM prompt_rcm = prompt_io_manager_.ChangeClient("local");
    if (!(prompt_rcm)) {
      prompt_io_manager_.ErrorFormat(prompt_rcm);
      return prompt_rcm;
    }
  }

  for (const auto &name : valid_targets) {
    const std::string normalized = NormalizeNickname(name);
    rcm = host_config_manager_.DelHost(normalized);
    if (!(rcm)) {
      prompt_io_manager_.ErrorFormat(rcm);
      return Err(rcm.code, kOp, normalized, rcm.error, rcm.raw_error);
    }
    const ECM remove_client_rcm = client_service_.RemoveClient(normalized);
    if (!(remove_client_rcm) && remove_client_rcm.code != EC::ClientNotFound) {
      prompt_io_manager_.ErrorFormat(remove_client_rcm);
      return Err(remove_client_rcm.code, kOp, normalized,
                 remove_client_rcm.error, remove_client_rcm.raw_error);
    }
  }
  return OK;
}

ECM ClientInterfaceService::SetHostValue(const SetHostValueRequest &request) {
  const std::string nickname = AMStr::Strip(request.nickname);
  const std::string field = AMStr::lowercase(AMStr::Strip(request.attrname));
  if (nickname.empty()) {
    const ECM err = Err(EC::InvalidArg, "", "", "empty nickname");
    prompt_io_manager_.ErrorFormat(err);
    return err;
  }
  if (!host_config_manager_.HostExists(nickname)) {
    const ECM err = Err(EC::HostConfigNotFound, "", "", "host not found");
    prompt_io_manager_.ErrorFormat(err);
    return err;
  }

  const auto parsed_field =
      AMDomain::host::HostService::ParseEditableHostSetField(field);
  if (!parsed_field.has_value()) {
    const ECM err = Err(EC::InvalidArg, "", "", "unsupported property name");
    prompt_io_manager_.ErrorFormat(err);
    return err;
  }

  HostConfig before = {};
  const ECM before_rcm =
      hostui::ResolveHostConfig_(host_config_manager_, nickname, &before);
  if (!(before_rcm)) {
    prompt_io_manager_.ErrorFormat(before_rcm);
    return before_rcm;
  }

  std::string resolved_value = request.value;
  if (field == "password" && AMStr::Strip(resolved_value).empty()) {
    auto resolved = prompt_io_manager_.SecurePrompt("Password: ");
    if (!resolved.has_value()) {
      const ECM err =
          Err(EC::ConfigCanceled, "", "", "password input canceled");
      prompt_io_manager_.ErrorFormat(err);
      return err;
    }
    resolved_value = *resolved;
  }

  const std::string old_value = hostui::HostFieldDisplay_(before, field);
  HostConfig updated = before;
  ECM set_rcm = AMDomain::host::HostService::ValidateEditableHostSetFieldValue(
      parsed_field.value(), resolved_value);
  if (!(set_rcm)) {
    prompt_io_manager_.ErrorFormat(set_rcm);
    return set_rcm;
  }

  if (parsed_field->scope ==
      AMDomain::host::HostService::HostSetFieldRef::Scope::Request) {
    switch (parsed_field->request_attr) {
    case AMDomain::host::ConRequest::Attr::hostname:
      updated.request.hostname = resolved_value;
      break;
    case AMDomain::host::ConRequest::Attr::username:
      updated.request.username = resolved_value;
      break;
    case AMDomain::host::ConRequest::Attr::port: {
      int64_t port = 0;
      (void)AMStr::GetNumber(resolved_value, &port);
      updated.request.port = port;
    } break;
    case AMDomain::host::ConRequest::Attr::protocol:
      updated.request.protocol = AMDomain::host::HostService::StrToProtocol(
          AMStr::Strip(resolved_value));
      break;
    case AMDomain::host::ConRequest::Attr::password:
      updated.request.password = resolved_value;
      break;
    case AMDomain::host::ConRequest::Attr::keyfile:
      updated.request.keyfile = resolved_value;
      break;
    case AMDomain::host::ConRequest::Attr::compression: {
      bool compression = false;
      (void)AMStr::GetBool(resolved_value, &compression);
      updated.request.compression = compression;
    } break;
    default:
      set_rcm = Err(EC::InvalidArg, "", field, "unsupported property name");
      break;
    }
  } else {
    switch (parsed_field->metadata_attr) {
    case AMDomain::host::ClientMetaData::Attr::trash_dir:
      updated.metadata.trash_dir = resolved_value;
      break;
    case AMDomain::host::ClientMetaData::Attr::login_dir:
      updated.metadata.login_dir = resolved_value;
      break;
    case AMDomain::host::ClientMetaData::Attr::cmd_template:
      updated.metadata.cmd_template = resolved_value;
      break;
    default:
      set_rcm = Err(EC::InvalidArg, "", field, "unsupported property name");
      break;
    }
  }
  if ((set_rcm)) {
    set_rcm = host_config_manager_.AddHost(updated, true);
  }
  if (!(set_rcm)) {
    prompt_io_manager_.ErrorFormat(set_rcm);
    return set_rcm;
  }

  HostConfig after = {};
  const ECM after_rcm =
      hostui::ResolveHostConfig_(host_config_manager_, nickname, &after);
  const std::string new_value =
      (after_rcm) ? hostui::HostFieldDisplay_(after, field) : resolved_value;

  prompt_io_manager_.Print(
      AMStr::fmt("{}.{}: {} -> {}", nickname, field, old_value, new_value));
  return OK;
}

ECM ClientInterfaceService::ListHosts(bool detail, bool list) {
  return ListHosts({}, detail, list);
}

ECM ClientInterfaceService::ListHosts(const std::vector<std::string> &filters,
                                      bool detail, bool list) {
  std::vector<std::string> nicknames = {};
  if (filters.empty()) {
    nicknames = host_config_manager_.ListNames();
  } else {
    std::unordered_set<std::string> seen = {};
    for (const auto &raw_name : filters) {
      const std::string stripped = AMStr::Strip(raw_name);
      if (stripped.empty()) {
        continue;
      }
      const std::string normalized = NormalizeNickname(stripped);
      if (normalized.empty()) {
        continue;
      }

      std::string resolved = normalized;
      if (IsLocalNickname(normalized)) {
        resolved = "local";
      } else {
        auto host_result =
            host_config_manager_.GetClientConfig(normalized, false);
        if (!(host_result.rcm)) {
          prompt_io_manager_.ErrorFormat(host_result.rcm);
          return host_result.rcm;
        }
        resolved = NormalizeNickname(host_result.data.request.nickname);
        if (resolved.empty()) {
          resolved = normalized;
        }
      }

      if (seen.insert(resolved).second) {
        nicknames.push_back(resolved);
      }
    }
  }

  if (!detail && list) {
    std::vector<hostui::HostListRow> rows = {};
    rows.reserve(nicknames.size());
    for (const auto &nickname : nicknames) {
      HostConfig entry = {};
      const ECM get_rcm =
          hostui::ResolveHostConfig_(host_config_manager_, nickname, &entry);
      if (!(get_rcm)) {
        prompt_io_manager_.ErrorFormat(get_rcm);
        return get_rcm;
      }
      rows.push_back(hostui::BuildHostListRow_(nickname, entry));
    }
    hostui::PrintHostListTable_(prompt_io_manager_, style_service_, rows);
    return OK;
  }

  if (!detail) {
    const std::vector<std::string> established =
        client_service_.GetClientNames();
    std::unordered_set<std::string> established_set = {};
    established_set.reserve(established.size() + 1);
    for (const auto &name : established) {
      const std::string normalized = NormalizeNickname(name);
      if (!normalized.empty()) {
        established_set.insert(normalized);
      }
    }
    if (client_service_.GetLocalClient()) {
      established_set.insert("local");
    }
    std::unordered_set<std::string> configured_set = {};
    configured_set.reserve(nicknames.size());
    for (const auto &name : nicknames) {
      const std::string normalized = NormalizeNickname(name);
      if (!normalized.empty()) {
        configured_set.insert(normalized);
      }
    }
    hostui::PrintHostCompact_(prompt_io_manager_, style_service_, nicknames,
                              &established_set, &configured_set);
    return OK;
  }

  if (nicknames.empty()) {
    prompt_io_manager_.Print("");
    return OK;
  }

  for (const auto &nickname : nicknames) {
    HostConfig entry = {};
    const ECM get_rcm =
        hostui::ResolveHostConfig_(host_config_manager_, nickname, &entry);
    if (!(get_rcm)) {
      prompt_io_manager_.ErrorFormat(get_rcm);
      return get_rcm;
    }
    render::PrintHostConfigDetail(prompt_io_manager_, nickname, entry,
                                  style_service_);
    prompt_io_manager_.Print("");
  }
  return OK;
}
} // namespace AMInterface::client
