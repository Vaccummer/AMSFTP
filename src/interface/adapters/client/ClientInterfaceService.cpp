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
#include <iomanip>
#include <map>
#include <mutex>
#include <optional>
#include <sstream>
#include <thread>
#include <unordered_set>
#include <utility>

namespace AMInterface::client {
class ClientConnectSpinner final : public NonCopyableNonMovable {
public:
  explicit ClientConnectSpinner(AMPromptIOManager &prompt_io_manager)
      : prompt_io_manager_(prompt_io_manager) {}
  ~ClientConnectSpinner() override { Stop(); }

  void Start(const AMDomain::host::HostConfig &config, bool quiet) {
    Stop();
    if (quiet) {
      return;
    }

    const std::string spinner_line = AMStr::fmt(
        "Connecting to {} Server   [{}]",
        AMStr::ToString(config.request.protocol), config.request.nickname);
    {
      std::lock_guard<std::mutex> lock(mutex_);
      stop_requested_.store(false, std::memory_order_relaxed);
      running_.store(true, std::memory_order_relaxed);
      refresh_active_ = true;
      prompt_io_manager_.RefreshBegin(1);
      worker_ =
          std::thread([this, spinner_line]() { RenderLoop_(spinner_line); });
    }
  }

  void Stop() {
    std::thread worker = {};
    bool should_refresh_end = false;
    {
      std::lock_guard<std::mutex> lock(mutex_);
      if (!refresh_active_ && !worker_.joinable() &&
          !running_.load(std::memory_order_relaxed)) {
        return;
      }

      stop_requested_.store(true, std::memory_order_relaxed);
      running_.store(false, std::memory_order_relaxed);
      if (worker_.joinable()) {
        worker = std::move(worker_);
      }
      should_refresh_end = refresh_active_;
      refresh_active_ = false;
    }

    if (worker.joinable()) {
      worker.join();
    }
    if (should_refresh_end) {
      prompt_io_manager_.RefreshEnd();
    }
  }

  void StopForPrompt() { Stop(); }

  [[nodiscard]] bool IsRunning() const {
    return running_.load(std::memory_order_relaxed);
  }

private:
  void RenderLoop_(const std::string &spinner_line) {
    static const std::vector<std::string> frames = {"|", "/", "-", "\\"};
    size_t idx = 0;
    while (running_.load(std::memory_order_relaxed) &&
           !stop_requested_.load(std::memory_order_relaxed)) {
      prompt_io_manager_.RefreshRender(
          {AMStr::fmt("{}  {}", frames[idx % frames.size()], spinner_line)});
      ++idx;
      std::this_thread::sleep_for(std::chrono::milliseconds(120));
    }
  }

  AMPromptIOManager &prompt_io_manager_;
  mutable std::mutex mutex_ = {};
  std::thread worker_ = {};
  std::atomic<bool> running_ = false;
  std::atomic<bool> stop_requested_ = true;
  bool refresh_active_ = false;
};

namespace {
using ClientHandle = AMDomain::client::ClientHandle;
using HostConfig = AMDomain::host::HostConfig;
using ClientMetaData = AMDomain::host::ClientMetaData;
using ClientProtocol = AMDomain::host::ClientProtocol;
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

ECM MergeStatus_(const ECM &current, const ECM &next) {
  return (next) ? current : next;
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

ECM ResolveChangeClientNickname_(AMPromptIOManager &prompt,
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

namespace render {
void PrintClientStatusLine(AMPromptIOManager &prompt,
                           const std::string &nickname,
                           const ClientHandle &client, const ECM &rcm,
                           const ClientStatusFormat &format,
                           const AMStyleService &style_service) {
  const std::string protocol = BuildClientProtocolLabel_(client);
  const std::string cwd = ResolveClientCwdFromService_(client);
  const std::string padded_protocol = AMStr::replace(
      AMStr::PadRightUtf8(protocol, format.protocol_width), "[", "\\[");
  const std::string padded_nickname =
      AMStr::PadRightUtf8(nickname, format.nickname_width);
  const std::string padded_cwd = AMStr::PadRightUtf8(cwd, format.cwd_width);

  const std::string styled_nickname =
      style_service.Format(padded_nickname,
                           AMInterface::style::StyleIndex::Nickname);
  const std::string styled_cwd =
      style_service.Format(padded_cwd, AMInterface::style::StyleIndex::Cwd);

  std::ostringstream line;
  line << ((rcm) ? "✅  " : "❌  ") << padded_protocol << "  "
       << styled_nickname << "  " << styled_cwd;
  if (!(rcm)) {
    const std::string ec_name = std::string(AMStr::ToString(rcm.code));
    const std::string msg = rcm.error.empty() ? rcm.msg() : rcm.error;
    line << "  " << ec_name << "  " << msg;
  }
  prompt.Print(line.str());
}

void PrintHostConfigDetail(AMPromptIOManager &prompt,
                           const std::string &nickname,
                           const HostConfig &config) {
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
    if (field.first == "protocol") {
      render_value = AMStr::uppercase(render_value);
    }
    if (field.first == "cmd_template") {
      render_value = "\"" + render_value + "\"";
    } else if (render_value.empty()) {
      render_value = "\"\"";
    }
    std::ostringstream line;
    line << std::left << std::setw(static_cast<int>(width)) << field.first
         << " :   " << render_value;
    prompt.Print(line.str());
  }
}

void PrintClientDetail(
    AMPromptIOManager &prompt, const std::string &nickname,
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
                        : Err(EC::ClientNotFound, __func__, "<context>", "Client not found");
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
  std::vector<std::string> out = {};
  std::unordered_set<std::string> seen = {};
  out.reserve(targets.size());
  for (const auto &target : targets) {
    const std::string value = AMStr::Strip(target);
    if (value.empty()) {
      continue;
    }
    if (seen.insert(value).second) {
      out.push_back(value);
    }
  }
  return out;
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

bool PromptHostText_(AMPromptIOManager &prompt, const std::string &label,
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

bool PromptHostBool_(AMPromptIOManager &prompt, const std::string &label,
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

bool PromptHostProtocol_(AMPromptIOManager &prompt, ClientProtocol current,
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

bool PromptHostInt64_(AMPromptIOManager &prompt, const std::string &label,
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
      prompt.ErrorFormat(Err(EC::InvalidArg, __func__, "<context>", "invalid integer value"));
      continue;
    }
    if (parsed < min_v || parsed > max_v) {
      prompt.ErrorFormat(
          Err(EC::InvalidArg, __func__, "<context>",
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
    return Err(EC::InvalidArg, __func__, "<context>", "null host config output");
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
    AMPromptIOManager &prompt, AMStyleService &style_service,
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
    const bool established = established_nicknames != nullptr &&
                             established_nicknames->find(normalized_nickname) !=
                                 established_nicknames->end();
    const bool configured = configured_nicknames != nullptr &&
                            configured_nicknames->find(normalized_nickname) !=
                                configured_nicknames->end();
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
  if (field == "buffer_size") {
    return std::to_string(entry.request.buffer_size);
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

ECM PromptAddHostConfig_(AMPromptIOManager &prompt,
                         AMHostConfigManager &host_config_manager,
                         const std::string &nickname, HostConfig *out) {
  if (!out) {
    return Err(EC::InvalidArg, __func__, "<context>", "null host config output");
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
        return Err(EC::ConfigCanceled, __func__, "<context>", "input canceled");
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
      return Err(EC::ConfigCanceled, __func__, "<context>", "input canceled");
    }
    const std::string protocol =
        AMStr::lowercase(AMStr::ToString(entry.request.protocol));
    if (protocol == "sftp" || protocol == "ftp" || protocol == "local") {
      break;
    }
    prompt.ErrorFormat(
        Err(EC::InvalidArg, __func__, "<context>", "protocol must be sftp, ftp or local"));
  }

  const bool hostname_required =
      entry.request.protocol != ClientProtocol::LOCAL;
  while (true) {
    std::string hostname = entry.request.hostname;
    if (!PromptHostText_(prompt, "Hostname: ", hostname, &hostname,
                         !hostname_required)) {
      return Err(EC::ConfigCanceled, __func__, "<context>", "input canceled");
    }
    hostname = AMStr::Strip(hostname);
    if (hostname.empty()) {
      if (!hostname_required) {
        entry.request.hostname.clear();
        break;
      }
      prompt.ErrorFormat(
          Err(EC::InvalidArg, __func__, "<context>", "hostname cannot be empty"));
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
      return Err(EC::ConfigCanceled, __func__, "<context>", "input canceled");
    }
    username = AMStr::Strip(username);
    if (username.empty()) {
      username = default_username;
    }
    if (hostname_required && username.empty()) {
      prompt.ErrorFormat(
          Err(EC::InvalidArg, __func__, "<context>", "username cannot be empty"));
      continue;
    }
    entry.request.username = username;
    break;
  }

  int64_t port = DefaultPortForProtocol_(entry.request.protocol);
  if (!PromptHostInt64_(prompt, AMStr::fmt("Port(default {}): ", port), port, 1,
                        65535, &port, true)) {
    return Err(EC::ConfigCanceled, __func__, "<context>", "input canceled");
  }
  entry.request.port = static_cast<int>(port);

  while (true) {
    std::string first = "";
    auto first_opt = prompt.SecurePrompt("password(optional): ");
    if (!first_opt.has_value()) {
      AMAuth::SecureZero(first);
      return Err(EC::ConfigCanceled, __func__, "<context>", "input canceled");
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
      return Err(EC::ConfigCanceled, __func__, "<context>", "input canceled");
    }
    second = *second_opt;
    if (first != second) {
      AMAuth::SecureZero(first);
      AMAuth::SecureZero(second);
      prompt.ErrorFormat(Err(EC::InvalidArg, __func__, "<context>", "Passwords do not match"));
      continue;
    }
    entry.request.password = AMAuth::EncryptPassword(first);
    AMAuth::SecureZero(first);
    AMAuth::SecureZero(second);
    break;
  }

  if (!PromptHostText_(prompt, "keyfile(optional): ", entry.request.keyfile,
                       &entry.request.keyfile, true)) {
    return Err(EC::ConfigCanceled, __func__, "<context>", "input canceled");
  }

  entry.request.buffer_size = 24 * AMMB;

  if (!PromptHostBool_(prompt, "compression: ", false,
                       &entry.request.compression)) {
    return Err(EC::ConfigCanceled, __func__, "<context>", "input canceled");
  }

  if (!PromptHostText_(prompt,
                       "trash_dir(optional): ", entry.metadata.trash_dir,
                       &entry.metadata.trash_dir, true)) {
    return Err(EC::ConfigCanceled, __func__, "<context>", "input canceled");
  }
  if (!PromptHostText_(prompt,
                       "login_dir(optional): ", entry.metadata.login_dir,
                       &entry.metadata.login_dir, true)) {
    return Err(EC::ConfigCanceled, __func__, "<context>", "input canceled");
  }
  if (!PromptHostText_(prompt,
                       "cmd_template(optional): ", entry.metadata.cmd_template,
                       &entry.metadata.cmd_template, true)) {
    return Err(EC::ConfigCanceled, __func__, "<context>", "input canceled");
  }

  *out = entry;
  return OK;
}

ECM PromptModifyHostConfig_(AMPromptIOManager &prompt,
                            const std::string &nickname, HostConfig *inout) {
  if (!inout) {
    return Err(EC::InvalidArg, __func__, "<context>", "null host config");
  }
  HostConfig entry = *inout;
  const ClientProtocol original_protocol = entry.request.protocol;

  while (true) {
    if (!PromptHostProtocol_(prompt, entry.request.protocol,
                             &entry.request.protocol)) {
      return Err(EC::ConfigCanceled, __func__, "<context>", "input canceled");
    }
    const std::string protocol =
        AMStr::lowercase(AMStr::ToString(entry.request.protocol));
    if (protocol == "sftp" || protocol == "ftp" || protocol == "local") {
      break;
    }
    prompt.ErrorFormat(
        Err(EC::InvalidArg, __func__, "<context>", "protocol must be sftp, ftp or local"));
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
      return Err(EC::ConfigCanceled, __func__, "<context>", "input canceled");
    }
    hostname = AMStr::Strip(hostname);
    if (hostname.empty()) {
      if (!hostname_required) {
        entry.request.hostname.clear();
        break;
      }
      prompt.ErrorFormat(
          Err(EC::InvalidArg, __func__, "<context>", "hostname cannot be empty"));
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
      return Err(EC::ConfigCanceled, __func__, "<context>", "input canceled");
    }
    username = AMStr::Strip(username);
    if (username.empty()) {
      username = default_username;
    }
    if (hostname_required && username.empty()) {
      prompt.ErrorFormat(
          Err(EC::InvalidArg, __func__, "<context>", "username cannot be empty"));
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
    return Err(EC::ConfigCanceled, __func__, "<context>", "input canceled");
  }
  entry.request.port = static_cast<int>(port);

  bool canceled = false;
  const bool change_password =
      prompt.PromptYesNo("Change password? (y/N): ", &canceled);
  if (canceled) {
    return Err(EC::ConfigCanceled, __func__, "<context>", "input canceled");
  }
  if (change_password) {
    while (true) {
      std::string first = "";
      auto first_opt = prompt.SecurePrompt("password(optional): ");
      if (!first_opt.has_value()) {
        AMAuth::SecureZero(first);
        return Err(EC::ConfigCanceled, __func__, "<context>", "input canceled");
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
        return Err(EC::ConfigCanceled, __func__, "<context>", "input canceled");
      }
      second = *second_opt;
      if (first != second) {
        AMAuth::SecureZero(first);
        AMAuth::SecureZero(second);
        prompt.ErrorFormat(
            Err(EC::InvalidArg, __func__, "<context>", "Passwords do not match"));
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
    return Err(EC::ConfigCanceled, __func__, "<context>", "input canceled");
  }

  if (!PromptHostBool_(prompt, "Compression (true/false): ",
                       entry.request.compression, &entry.request.compression)) {
    return Err(EC::ConfigCanceled, __func__, "<context>", "input canceled");
  }
  if (!PromptHostText_(prompt,
                       "trash_dir(optional): ", entry.metadata.trash_dir,
                       &entry.metadata.trash_dir, true)) {
    return Err(EC::ConfigCanceled, __func__, "<context>", "input canceled");
  }
  if (!PromptHostText_(prompt,
                       "login_dir(optional): ", entry.metadata.login_dir,
                       &entry.metadata.login_dir, true)) {
    return Err(EC::ConfigCanceled, __func__, "<context>", "input canceled");
  }
  if (!PromptHostText_(prompt,
                       "cmd_template(optional): ", entry.metadata.cmd_template,
                       &entry.metadata.cmd_template, true)) {
    return Err(EC::ConfigCanceled, __func__, "<context>", "input canceled");
  }

  entry.request.nickname = nickname;
  *inout = entry;
  return OK;
}
} // namespace hostui

} // namespace

ClientInterfaceService::ClientInterfaceService(
    ClientAppService &client_service, FilesystemAppService &filesystem_service,
    AMHostConfigManager &host_config_manager,
    AMKnownHostsManager &known_hosts_manager,
    AMPromptIOManager &prompt_io_manager, AMStyleService &style_service)
    : client_service_(client_service), filesystem_service_(filesystem_service),
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
  AMDomain::client::DisconnectCallback disconnect_callback =
      [this](const ClientHandle &client, const ECM &rcm) {
        if (!client) {
          return;
        }
        const auto request = client->ConfigPort().GetRequest();
        const std::string ec_name = std::string(AMStr::ToString(rcm.code));
        const std::string protocol =
            std::string(AMStr::ToString(request.protocol));
        const std::string reason = AMStr::Strip(rcm.msg()).empty()
                                       ? std::string("connection lost")
                                       : AMStr::Strip(rcm.msg());
        const std::string nickname = request.nickname.empty()
                                         ? client->ConfigPort().GetNickname()
                                         : request.nickname;
        prompt_io_manager_.Print(AMStr::fmt(
            "❌\\[{}] {}: connection lost ({}, nickname={}, host={}:{})",
            ec_name, protocol, reason, nickname, request.hostname,
            request.port));
      };

  AMDomain::client::KnownHostCallback known_host_callback =
      [this](const AMDomain::client::KnownHostQuery &query) -> ECM {
    if (spinner_) {
      spinner_->StopForPrompt();
    }
    if (!AMDomain::host::KnownHostRules::ValidateConfig(query)) {
      return Err(EC::InvalidArg, __func__, "<context>", "invalid known host query");
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
      print_known_host_field("Protocol:", query.protocol);
      print_known_host_field("Fingerprint:",
                             AMStr::Strip(query.GetFingerprint()));
      const bool accepted = prompt_io_manager_.PromptYesNo(
          "Trust this host key? (y/N): ", &canceled);
      if (canceled || !accepted) {
        return Err(EC::ConfigCanceled, __func__, "<context>",
                   "Known host fingerprint add canceled");
      }
      return known_hosts_manager_.UpsertKnownHost(query, true);
    }

    const std::string expected = AMStr::Strip(stored.GetFingerprint());
    const std::string actual = AMStr::Strip(query.GetFingerprint());
    if (expected != actual) {
      return Err(EC::HostFingerprintMismatch, __func__, "<context>",
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
      disconnect_callback, std::nullopt, known_host_callback, auth_callback);
  client_service_.RegisterPublicCallbacks(disconnect_callback, std::nullopt,
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

ClientControlComponent ClientInterfaceService::ResolveControl_(
    const std::optional<ClientControlComponent> &component) const {
  if (component.has_value()) {
    return component.value();
  }
  return {default_control_token_, -1};
}

ECM ClientInterfaceService::Connect(
    const ConnectRequest &request,
    const std::optional<ClientControlComponent> &component) {
  if (request.nicknames.empty()) {
    return Err(EC::InvalidArg, __func__, "<context>",
               "connect requires at least one nickname");
  }
  const std::vector<std::string> targets =
      AMStr::UniqueTargetsKeepOrder(request.nicknames);
  const ClientControlComponent control = ResolveControl_(component);
  ECM status = OK;

  for (const auto &raw : targets) {
    if (control.IsInterrupted()) {
      return Err(EC::Terminate, __func__, "<context>", "Interrupted by user");
    }

    const std::string nickname = AMStr::Strip(raw);
    if (nickname.empty()) {
      status =
          MergeStatus_(status, Err(EC::InvalidArg, __func__, "<context>", "Empty nickname"));
      continue;
    }
    if (!IsLocalNickname(nickname) &&
        !AMDomain::host::HostService::ValidateNickname(nickname)) {
      status =
          MergeStatus_(status, Err(EC::InvalidArg, __func__, "<context>", "Invalid nickname"));
      continue;
    }
    if (IsLocalNickname(nickname)) {
      prompt_io_manager_.Print("Connected: local");
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
          status = MergeStatus_(
              status, Err(EC::ClientNotFound, "connect_clients",
                          ensured_nickname, "Client not found"));
          continue;
        }
        if (!(checked.value().rcm)) {
          const std::optional<ECMData<AMDomain::filesystem::CheckResult>>
              rechecked = client_service_.CheckClient(ensured_nickname, true,
                                                      true, control);
          if (!rechecked.has_value()) {
            status = MergeStatus_(
                status, Err(EC::ClientNotFound, "connect_clients",
                            ensured_nickname, "Client not found"));
            continue;
          }
          status = MergeStatus_(status, rechecked.value().rcm);
          if (!(rechecked.value().rcm)) {
            continue;
          }
        }
      }
      prompt_io_manager_.Print(AMStr::fmt(
          "Connected: {}", ensured.data->ConfigPort().GetNickname()));
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
        prompt_io_manager_.Print(AMStr::fmt(
            "Connected: {}", created.data->ConfigPort().GetNickname()));
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
    const std::optional<ClientControlComponent> &component) {
  const ClientControlComponent control = ResolveControl_(component);
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
    const std::optional<ClientControlComponent> &component) {
  constexpr const char *kOp = "connect_protocol";
  std::string nickname = AMStr::Strip(request.nickname);
  const ClientControlComponent control = ResolveControl_(component);
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
        const ECM rcm = Err(EC::ConfigCanceled,
                            "connect_protocol.prompt_nickname", "<prompt>",
                            "Nickname input canceled");
        prompt_io_manager_.ErrorFormat(rcm);
        return rcm;
      }
      nickname = AMStr::Strip(*prompted_nickname);
      if (nickname.empty()) {
        prompt_io_manager_.ErrorFormat(Err(EC::InvalidArg,
                                           "connect_protocol.prompt_nickname",
                                           "<nickname>",
                                           "Nickname cannot be empty"));
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
    prompt_io_manager_.Print(
        AMStr::fmt("Connected: {}", created.data->ConfigPort().GetNickname()));
  }
  return change_prompt_rcm;
}

ECM ClientInterfaceService::ConnectSftp(
    const ProtocolConnectRequest &request,
    const std::optional<ClientControlComponent> &component) {
  return ConnectProtocol_(request, ClientProtocol::SFTP, component);
}

ECM ClientInterfaceService::ConnectFtp(
    const ProtocolConnectRequest &request,
    const std::optional<ClientControlComponent> &component) {
  return ConnectProtocol_(request, ClientProtocol::FTP, component);
}

ECM ClientInterfaceService::ConnectLocal(
    const ProtocolConnectRequest &request,
    const std::optional<ClientControlComponent> &component) {
  return ConnectProtocol_(request, ClientProtocol::LOCAL, component);
}

ECM ClientInterfaceService::RemoveClients(
    const RemoveClientsRequest &request,
    const std::optional<ClientControlComponent> &component) {
  constexpr const char *kOp = "remove_clients";
  if (request.nicknames.empty()) {
    const ECM rcm = Err(EC::InvalidArg, kOp, "<targets>", "Empty nickname");
    prompt_io_manager_.ErrorFormat(rcm);
    return rcm;
  }

  const ClientControlComponent control = ResolveControl_(component);
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
  std::vector<std::string> show_targets = {};
  valid_targets.reserve(targets.size());
  show_targets.reserve(targets.size());

  for (const auto &target : targets) {
    const std::string stripped = AMStr::Strip(target);
    const std::string lowered = AMStr::lowercase(stripped);
    if (stripped.empty()) {
      last = Err(EC::InvalidArg, kOp, "<empty>", "Invalid empty client name");
      prompt_io_manager_.ErrorFormat(last);
      continue;
    }
    if (lowered == "local") {
      last = Err(EC::InvalidArg, kOp, "local",
                 "Local client cannot be removed");
      prompt_io_manager_.ErrorFormat(last);
      continue;
    }
    const std::string resolved =
        FindClientNicknameCaseInsensitive_(names, stripped);
    if (resolved.empty()) {
      last = Err(EC::ClientNotFound, kOp, stripped,
                 "Client not established");
      prompt_io_manager_.ErrorFormat(last);
      continue;
    }

    valid_targets.push_back(resolved);
    show_targets.push_back(resolved);
  }

  if (show_targets.empty()) {
    return (last) ? Err(EC::ClientNotFound, kOp, "<targets>",
                        "No valid clients to remove")
                  : last;
  }

  std::string target_line = "";
  for (size_t i = 0; i < show_targets.size(); ++i) {
    if (i > 0) {
      target_line += ", ";
    }
    target_line += show_targets[i];
  }

  bool canceled = false;
  const bool confirmed = prompt_io_manager_.PromptYesNo(
      AMStr::fmt("Remove clients: {} ? (y/N): ", target_line), &canceled);
  if (canceled || !confirmed) {
    const std::string msg = "Remove clients canceled";
    prompt_io_manager_.FmtPrint("🚫  {}\n", msg);
    prompt_io_manager_.ErrorFormat(
        Err(EC::ConfigCanceled, "remove_clients.confirm", target_line, msg));
    return Err(EC::Terminate, "remove_clients.confirm", target_line, msg);
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
    const std::optional<ClientControlComponent> &component) {
  constexpr const char *kOp = "list_clients";
  if (request.check) {
    CheckClientsRequest check_request = {};
    check_request.nicknames = request.nicknames;
    check_request.detail = request.detail;
    return CheckClients(check_request, component);
  }

  const ClientControlComponent control = ResolveControl_(component);
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
        const ECM rcm = Err(EC::ClientNotFound, kOp, nickname,
                            "Client not found");
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
    std::unordered_set<std::string> established_set = {};
    established_set.reserve(resolved_names.size());
    for (const auto &name : resolved_names) {
      const std::string normalized = NormalizeNickname(name);
      if (!normalized.empty()) {
        established_set.insert(normalized);
      }
    }
    hostui::PrintHostCompact_(prompt_io_manager_, style_service_,
                              resolved_names, &established_set, nullptr);
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
    const std::optional<ClientControlComponent> &component) {
  constexpr const char *kOp = "check_clients";
  const ClientControlComponent control = ResolveControl_(component);
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
    const ECM rcm = checked.has_value()
                        ? checked->rcm
                        : Err(EC::ClientNotFound, kOp, display_name,
                              "Client not found");
    status = MergeStatus_(status, rcm);
  }

  if (!request.detail) {
    const ClientStatusFormat format = BuildClientStatusFormat_(clients);
    for (const auto &entry : clients) {
      const ECM rcm =
          (checks.count(entry.first) != 0 && checks.at(entry.first).has_value())
              ? checks.at(entry.first)->rcm
              : Err(EC::ClientNotFound, kOp, entry.first,
                    "Client not found");
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
    if (prompt_rcm.code == EC::ConfigCanceled) {
      prompt_io_manager_.Print(style_service_.Format(
          "Host add aborted.", AMInterface::style::StyleIndex::Abort));
    }
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
    const ECM rcm = Err(EC::HostConfigNotFound, __func__, "<context>", "host not found");
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
    if (prompt_rcm.code == EC::ConfigCanceled) {
      prompt_io_manager_.Print(style_service_.Format(
          "Host edit aborted.", AMInterface::style::StyleIndex::Abort));
    }
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
    rcm = Err(EC::InvalidArg, __func__, "<context>", "empty nickname");
    prompt_io_manager_.ErrorFormat(rcm);
    return rcm;
  }
  if (old_nickname == new_nickname) {
    rcm = Err(EC::InvalidArg, __func__, "<context>", "new nickname same as old nickname");
    prompt_io_manager_.ErrorFormat(rcm);
    return rcm;
  }
  if (!ValidateNickname(new_nickname)) {
    rcm = Err(EC::InvalidArg, __func__, "<context>",
              "invalid new nickname, pattern is [a-zA-Z0-9_-]+");
    prompt_io_manager_.ErrorFormat(rcm);
    return rcm;
  }
  if (host_config_manager_.HostExists(new_nickname)) {
    rcm = Err(EC::KeyAlreadyExists, __func__, "<context>", "new nickname already exists");
    prompt_io_manager_.ErrorFormat(rcm);
    return rcm;
  }
  if (!host_config_manager_.HostExists(old_nickname)) {
    rcm = Err(EC::HostConfigNotFound, __func__, "<context>", "old nickname not found");
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
  const std::vector<std::string> uniq_targets =
      hostui::DedupTargets_(nicknames);
  if (uniq_targets.empty()) {
    return OK;
  }

  ECM rcm = OK;
  std::vector<std::string> valid_targets = {};
  valid_targets.reserve(uniq_targets.size());

  for (const auto &name : uniq_targets) {
    const std::string normalized = NormalizeNickname(name);
    if (normalized.empty()) {
      rcm = Err(EC::InvalidArg, __func__, "<context>", "invalid empty host nickname");
      prompt_io_manager_.ErrorFormat(rcm);
      continue;
    }
    if (IsLocalNickname(normalized)) {
      rcm = Err(EC::InvalidArg, __func__, "<context>", "local host cannot be removed");
      prompt_io_manager_.ErrorFormat(rcm);
      continue;
    }
    if (!host_config_manager_.HostExists(normalized)) {
      rcm = Err(EC::InvalidArg, __func__, "<context>",
                AMStr::fmt("invalid host nickname: {}", normalized));
      prompt_io_manager_.ErrorFormat(rcm);
      continue;
    }
    valid_targets.push_back(normalized);
  }

  if (valid_targets.empty()) {
    return rcm;
  }

  std::string listing = "";
  for (size_t i = 0; i < valid_targets.size(); ++i) {
    if (i > 0) {
      listing += ", ";
    }
    listing += valid_targets[i];
  }

  bool canceled = false;
  const bool confirmed = prompt_io_manager_.PromptYesNo(
      AMStr::fmt("Delete {} host(s): {} ? (y/N): ", valid_targets.size(),
                 listing),
      &canceled);
  if (canceled || !confirmed) {
    prompt_io_manager_.Print("Delete aborted.");
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
      const ECM rcm = (local_result.rcm) ? Err(EC::InvalidHandle, __func__, "<context>",
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
      return rcm;
    }
    const ECM remove_client_rcm = client_service_.RemoveClient(normalized);
    if (!(remove_client_rcm) && remove_client_rcm.code != EC::ClientNotFound) {
      prompt_io_manager_.ErrorFormat(remove_client_rcm);
      return remove_client_rcm;
    }
  }
  return OK;
}

ECM ClientInterfaceService::SetHostValue(const SetHostValueRequest &request) {
  const std::string nickname = AMStr::Strip(request.nickname);
  const std::string field = AMStr::lowercase(AMStr::Strip(request.attrname));
  if (nickname.empty()) {
    const ECM err = Err(EC::InvalidArg, __func__, "<context>", "empty nickname");
    prompt_io_manager_.ErrorFormat(err);
    return err;
  }
  if (!host_config_manager_.HostExists(nickname)) {
    const ECM err = Err(EC::HostConfigNotFound, __func__, "<context>", "host not found");
    prompt_io_manager_.ErrorFormat(err);
    return err;
  }

  static const std::vector<std::string> kAllowedFields = {
      "hostname",    "username",     "port",     "buffer_size",
      "compression", "cmd_template", "protocol", "password",
      "keyfile",     "trash_dir",    "login_dir"};
  bool field_validated = false;
  for (const auto &allowed : kAllowedFields) {
    if (field == allowed) {
      field_validated = true;
      break;
    }
  }
  if (!field_validated) {
    const ECM err = Err(EC::InvalidArg, __func__, "<context>", "unsupported property name");
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
          Err(EC::ConfigCanceled, __func__, "<context>", "password input canceled");
      prompt_io_manager_.ErrorFormat(err);
      return err;
    }
    resolved_value = *resolved;
  }

  const std::string old_value = hostui::HostFieldDisplay_(before, field);
  HostConfig updated = before;
  ECM set_rcm = OK;
  if (field == "hostname") {
    updated.request.hostname = resolved_value;
  } else if (field == "username") {
    updated.request.username = resolved_value;
  } else if (field == "port") {
    int64_t port = 0;
    if (!AMStr::GetNumber(resolved_value, &port)) {
      set_rcm = Err(EC::InvalidArg, __func__, "<context>", "invalid port");
    } else {
      updated.request.port = port;
    }
  } else if (field == "protocol") {
    updated.request.protocol = AMDomain::host::HostService::StrToProtocol(
        AMStr::Strip(resolved_value));
  } else if (field == "password") {
    updated.request.password = resolved_value;
  } else if (field == "keyfile") {
    updated.request.keyfile = resolved_value;
  } else if (field == "buffer_size") {
    int64_t buffer_size = 0;
    if (!AMStr::GetNumber(resolved_value, &buffer_size)) {
      set_rcm = Err(EC::InvalidArg, __func__, "<context>", "invalid buffer_size");
    } else {
      updated.request.buffer_size = buffer_size;
    }
  } else if (field == "compression") {
    bool compression = false;
    if (!AMStr::GetBool(resolved_value, &compression)) {
      set_rcm = Err(EC::InvalidArg, __func__, "<context>", "invalid compression value");
    } else {
      updated.request.compression = compression;
    }
  } else if (field == "trash_dir") {
    updated.metadata.trash_dir = resolved_value;
  } else if (field == "login_dir") {
    updated.metadata.login_dir = resolved_value;
  } else if (field == "cmd_template") {
    updated.metadata.cmd_template = resolved_value;
  } else {
    set_rcm = Err(EC::InvalidArg, __func__, "<context>", "unsupported property name");
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

ECM ClientInterfaceService::ListHosts(bool detail) {
  return ListHosts({}, detail);
}

ECM ClientInterfaceService::ListHosts(const std::vector<std::string> &filters,
                                      bool detail) {
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
      return get_rcm;
    }
    render::PrintHostConfigDetail(prompt_io_manager_, nickname, entry);
    prompt_io_manager_.Print("");
  }
  return OK;
}
} // namespace AMInterface::client

