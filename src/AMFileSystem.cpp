#include "AMFileSystem.hpp"
#include "base/AMCommonTools.hpp"
#include "base/AMDataClass.hpp"
#include "base/AMEnum.hpp"
#include "base/AMPath.hpp"
#include <algorithm>
#include <cctype>
#include <functional>
#include <iomanip>
#include <magic_enum/magic_enum.hpp>
#include <sstream>
#include <unordered_map>
#include <unordered_set>

using EC = ErrorCode;

AMFileSystem &AMFileSystem::Instance(AMClientManager &client_manager,
                                     AMConfigManager &config_manager) {
  static AMFileSystem instance(client_manager, config_manager);
  return instance;
}

AMFileSystem::AMFileSystem(AMClientManager &client_manager,
                           AMConfigManager &config_manager)
    : client_manager_(client_manager), config_manager_(config_manager),
      prompt_manager_(AMPromptManager::Instance()) {
  EnsureClientWorkdir(client_manager_.LOCAL);
}

AMFileSystem::ECM AMFileSystem::check(const std::string &nickname,
                                      amf interrupt_flag) {
  amf flag = interrupt_flag ? interrupt_flag : global_interrupt_flag;
  std::vector<std::string> targets = SplitTargets(nickname);
  if (targets.empty()) {
    const std::string current =
        client_manager_.CLIENT ? client_manager_.CLIENT->GetNickname() : "";
    targets.push_back(current.empty() ? "local" : current);
  }

  ECM last = {EC::Success, ""};
  for (const auto &name : targets) {
    ClientRef client = ResolveClientByName(name);
    if (!client.is_valid()) {
      last = {EC::ClientNotFound, AMStr::amfmt("Client not found: {}", name)};
      continue;
    }
    ECM rcm = PrintClientStatus(client, true, flag);
    if (rcm.first != EC::Success) {
      last = rcm;
    }
  }
  return last;
}

AMFileSystem::ECM AMFileSystem::connect(const std::string &nickname,
                                        amf interrupt_flag) {
  amf flag = interrupt_flag ? interrupt_flag : global_interrupt_flag;
  auto result =
      client_manager_.AddClient(nickname, nullptr, false, false, {}, flag);
  if (result.first.first != EC::Success) {
    return result.first;
  }
  EnsureClientWorkdir(result.second);
  return {EC::Success, ""};
}

AMFileSystem::ECM AMFileSystem::sftp(const std::string &nickname,
                                     const std::string &hostname,
                                     const std::string &username, int64_t port,
                                     const std::string &password,
                                     const std::string &keyfile,
                                     amf interrupt_flag) {
  amf flag = interrupt_flag ? interrupt_flag : global_interrupt_flag;
  auto result = client_manager_.Connect(nickname, hostname, username,
                                        ClientProtocol::SFTP, port, password,
                                        keyfile, nullptr, false, {}, flag);
  if (result.first.first != EC::Success || !result.second) {
    return result.first;
  }
  EnsureClientWorkdir(result.second);
  client_manager_.CLIENT = result.second;
  return {EC::Success, ""};
}

AMFileSystem::ECM AMFileSystem::ftp(const std::string &nickname,
                                    const std::string &hostname,
                                    const std::string &username, int64_t port,
                                    const std::string &password,
                                    const std::string &keyfile,
                                    amf interrupt_flag) {
  amf flag = interrupt_flag ? interrupt_flag : global_interrupt_flag;
  auto result = client_manager_.Connect(nickname, hostname, username,
                                        ClientProtocol::FTP, port, password,
                                        keyfile, nullptr, false, {}, flag);
  if (result.first.first != EC::Success || !result.second) {
    return result.first;
  }
  EnsureClientWorkdir(result.second);
  client_manager_.CLIENT = result.second;
  return {EC::Success, ""};
}

AMFileSystem::ECM AMFileSystem::change_client(const std::string &nickname,
                                              amf interrupt_flag) {
  amf flag = interrupt_flag ? interrupt_flag : global_interrupt_flag;
  if (nickname.empty()) {
    return {EC::InvalidArg, "Empty nickname"};
  }
  ClientRef client = ResolveClientByName(nickname);
  if (!client.is_valid()) {
    bool canceled = false;
    if (!prompt_manager_.PromptYesNo("Client not found. Create it? (y/N): ",
                                     &canceled)) {
      return {EC::Terminate, "Operation aborted"};
    }
    auto added =
        client_manager_.AddClient(nickname, nullptr, false, false, {}, flag);
    if (added.first.first != EC::Success) {
      return added.first;
    }
    client.nickname = nickname;
    client.client = added.second;
  }
  client_manager_.CLIENT = client.client;
  std::string cwd = GetOrInitWorkdir(client.client);
  SetClientWorkdir(client.client, cwd);
  return {EC::Success, ""};
}

AMFileSystem::ECM AMFileSystem::remove_client(const std::string &nickname) {
  std::vector<std::string> targets = SplitTargets(nickname);
  if (targets.empty()) {
    return {EC::InvalidArg, "Empty nickname"};
  }
  const std::string current =
      client_manager_.CLIENT ? client_manager_.CLIENT->GetNickname() : "";
  const std::string current_lower = AMStr::lowercase(current);
  for (const auto &target : targets) {
    const std::string lower = AMStr::lowercase(target);
    if (!current_lower.empty() && lower == current_lower) {
      return {EC::InvalidArg, "Cannot remove current client"};
    }
    if (lower == "local") {
      return {EC::InvalidArg, "Local client cannot be removed"};
    }
  }
  bool canceled = false;
  if (!prompt_manager_.PromptYesNo("Remove client(s)? (y/N): ", &canceled)) {
    return {EC::Terminate, "Remove canceled"};
  }

  ECM last = {EC::Success, ""};
  for (const auto &target : targets) {
    ECM rcm = client_manager_.RemoveClient(target);
    if (rcm.first != EC::Success) {
      last = rcm;
    }
  }
  return last;
}

AMFileSystem::ECM AMFileSystem::cd(const std::string &path,
                                   amf interrupt_flag) {
  amf flag = interrupt_flag ? interrupt_flag : global_interrupt_flag;
  if (path.empty()) {
    return {EC::Success, ""};
  }

  bool from_history = false;
  if (path == "-") {
    if (last_cd_.empty()) {
      return {EC::InvalidArg, "No previous directory"};
    }
    std::string target = last_cd_;
    last_cd_.clear();
    from_history = true;
    std::string resolved_path;
    ClientRef client = ResolveClientForPath(target, &resolved_path, true, flag);
    if (!client.is_valid()) {
      return {EC::ClientNotFound, "Client not found"};
    }
    if (resolved_path.empty()) {
      return change_client(client.nickname, flag);
    }
    std::string abs_path = BuildPath(client, resolved_path);
    auto [rcm, info] = client.client->stat(abs_path, false, flag);
    if (rcm.first != EC::Success) {
      return rcm;
    }
    if (info.type != PathType::DIR) {
      return {EC::NotADirectory, "Path is not a directory"};
    }
    SetClientWorkdir(client.client, abs_path);
    client_manager_.CLIENT = client.client;
    return {EC::Success, ""};
  }

  std::string resolved_path;
  ClientRef client = ResolveClientForPath(path, &resolved_path, true, flag);
  if (!client.is_valid()) {
    return {EC::ClientNotFound, "Client not found"};
  }

  if (resolved_path.empty()) {
    return change_client(client.nickname, flag);
  }

  std::string abs_path = BuildPath(client, resolved_path);
  auto [rcm, info] = client.client->stat(abs_path, false, flag);
  if (rcm.first != EC::Success) {
    return rcm;
  }
  if (info.type != PathType::DIR) {
    return {EC::NotADirectory, "Path is not a directory"};
  }

  std::string prev_cwd = GetOrInitWorkdir(client.client);
  if (!from_history && abs_path != prev_cwd) {
    UpdateHistory(client.nickname, prev_cwd);
  }

  SetClientWorkdir(client.client, abs_path);
  client_manager_.CLIENT = client.client;
  return {EC::Success, ""};
}

AMFileSystem::ECM AMFileSystem::print_clients(amf interrupt_flag) {
  amf flag = interrupt_flag ? interrupt_flag : global_interrupt_flag;
  std::vector<std::string> seen;

  auto add_unique = [&, flag](const std::string &name) {
    std::string lowered = AMStr::lowercase(name);
    if (std::find(seen.begin(), seen.end(), lowered) != seen.end()) {
      return;
    }
    seen.push_back(lowered);
    ClientRef client = ResolveClientByName(name);
    if (client.is_valid()) {
      PrintClientStatus(client, true, flag);
    }
  };

  add_unique("local");

  for (const auto &name : client_manager_.Clients().get_nicknames()) {
    add_unique(name);
  }

  return {EC::Success, ""};
}

AMFileSystem::ECM AMFileSystem::stat(const std::string &path,
                                     amf interrupt_flag, int timeout_ms) {
  amf flag = interrupt_flag ? interrupt_flag : global_interrupt_flag;
  std::vector<std::string> targets = SplitTargets(path);
  if (targets.empty()) {
    return {EC::InvalidArg, "Empty path"};
  }
  ECM last = {EC::Success, ""};
  for (const auto &target : targets) {
    std::string resolved_path;
    ClientRef client =
        ResolveClientForPath(target, &resolved_path, false, flag);
    if (!client.is_valid()) {
      last = {EC::ClientNotFound, "Client not found"};
      continue;
    }
    if (resolved_path.empty()) {
      last = {EC::InvalidArg, "Empty path"};
      continue;
    }
    std::string abs_path = BuildPath(client, resolved_path);
    int64_t start_time = am_ms();
    auto [rcm, info] =
        client.client->stat(abs_path, false, flag, timeout_ms, start_time);
    if (rcm.first != EC::Success) {
      last = rcm;
      continue;
    }
    prompt_manager_.Print(FormatStatOutput(info));
  }
  return last;
}

AMFileSystem::ECM AMFileSystem::ls(const std::string &path, bool list_like,
                                   bool show_all, amf interrupt_flag,
                                   int timeout_ms) {
  amf flag = interrupt_flag ? interrupt_flag : global_interrupt_flag;
  std::string resolved_path;
  ClientRef client = ResolveClientForPath(path, &resolved_path, false, flag);
  if (!client.is_valid()) {
    return {EC::ClientNotFound, "Client not found"};
  }
  std::string target_path = resolved_path.empty() ? "." : resolved_path;
  std::string abs_path = BuildPath(client, target_path);
  int64_t start_time = am_ms();
  auto [rcm, list] =
      client.client->listdir(abs_path, flag, timeout_ms, start_time);
  if (rcm.first != EC::Success) {
    return rcm;
  }

  std::vector<PathInfo> entries;
  entries.reserve(list.size());
  for (const auto &info : list) {
    if (!show_all && !info.name.empty() && info.name.front() == '.') {
      continue;
    }
    entries.push_back(info);
  }

  auto type_rank = [](PathType type) {
    switch (type) {
    case PathType::FILE:
      return 0;
    case PathType::SYMLINK:
      return 1;
    case PathType::DIR:
      return 2;
    default:
      return 3;
    }
  };

  auto name_key = [](const std::string &name) {
    std::string lowered = name;
    std::transform(
        lowered.begin(), lowered.end(), lowered.begin(),
        [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return lowered;
  };

  std::sort(entries.begin(), entries.end(),
            [&](const PathInfo &a, const PathInfo &b) {
              int ra = type_rank(a.type);
              int rb = type_rank(b.type);
              if (ra != rb) {
                return ra < rb;
              }
              return name_key(a.name) < name_key(b.name);
            });

  if (!list_like) {
    const size_t max_width = 80;
    size_t max_len = 0;
    for (const auto &info : entries) {
      max_len = std::max(max_len, info.name.size());
    }
    size_t col_width = max_len == 0 ? 1 : max_len + 2;
    size_t columns =
        col_width == 0 ? 1 : std::max<size_t>(1, max_width / col_width);
    size_t rows = (entries.size() + columns - 1) / columns;

    for (size_t r = 0; r < rows; ++r) {
      std::ostringstream line;
      for (size_t c = 0; c < columns; ++c) {
        size_t idx = r + c * rows;
        if (idx >= entries.size()) {
          continue;
        }
        const auto &info = entries[idx];
        std::string styled = StylePath(info, info.name);
        size_t raw_len = info.name.size();
        line << styled;
        if (c + 1 < columns && idx + rows < entries.size()) {
          size_t pad = col_width > raw_len ? col_width - raw_len : 1;
          line << std::string(pad, ' ');
        }
      }
      prompt_manager_.Print(line.str());
    }
    return {EC::Success, ""};
  }

  size_t mode_width = 0;
  size_t owner_width = 0;
  size_t size_width = 0;
  size_t time_width = 0;

  std::vector<std::string> time_values;
  time_values.reserve(entries.size());

  for (const auto &info : entries) {
    std::string mode = info.mode_str;
    char type_char = '-';
    if (info.type == PathType::DIR) {
      type_char = 'd';
    } else if (info.type == PathType::SYMLINK) {
      type_char = 'l';
    }
    mode = std::string(1, type_char) + mode;
    mode_width = std::max(mode_width, mode.size());

    owner_width = std::max(owner_width, info.owner.size());

    std::string size_str = FormatSize(info.size);
    size_width = std::max(size_width, size_str.size());

    std::string time_str = FormatTimestamp(info.modify_time);
    time_values.push_back(time_str);
    time_width = std::max(time_width, time_str.size());
  }

  for (size_t i = 0; i < entries.size(); ++i) {
    const auto &info = entries[i];
    char type_char = '-';
    if (info.type == PathType::DIR) {
      type_char = 'd';
    } else if (info.type == PathType::SYMLINK) {
      type_char = 'l';
    }
    std::string mode = std::string(1, type_char) + info.mode_str;
    std::string size_str = FormatSize(info.size);
    std::string time_str = i < time_values.size()
                               ? time_values[i]
                               : FormatTimestamp(info.modify_time);
    std::string name = StylePath(info, info.name);

    std::ostringstream line;
    line << std::left << std::setw(static_cast<int>(mode_width)) << mode << "  "
         << std::left << std::setw(static_cast<int>(owner_width)) << info.owner
         << "  " << std::right << std::setw(static_cast<int>(size_width))
         << size_str << "  " << std::left
         << std::setw(static_cast<int>(time_width)) << time_str << "  " << name;
    prompt_manager_.Print(line.str());
  }

  return {EC::Success, ""};
}

AMFileSystem::ECM AMFileSystem::getsize(const std::string &path,
                                        amf interrupt_flag, int timeout_ms) {
  amf flag = interrupt_flag ? interrupt_flag : global_interrupt_flag;
  std::vector<std::string> targets = SplitTargets(path);
  if (targets.empty()) {
    return {EC::InvalidArg, "Empty path"};
  }
  ECM last = {EC::Success, ""};
  for (const auto &target : targets) {
    std::string resolved_path;
    ClientRef client =
        ResolveClientForPath(target, &resolved_path, false, flag);
    if (!client.is_valid()) {
      last = {EC::ClientNotFound, "Client not found"};
      continue;
    }
    if (resolved_path.empty()) {
      last = {EC::InvalidArg, "Empty path"};
      continue;
    }
    std::string abs_path = BuildPath(client, resolved_path);
    int64_t start_time = am_ms();
    int64_t size =
        client.client->getsize(abs_path, true, flag, timeout_ms, start_time);
    if (size < 0) {
      last = {EC::UnknownError, "Get size failed"};
      continue;
    }
    prompt_manager_.Print(AMStr::amfmt(
        "{}  {}", abs_path, FormatSize(static_cast<uint64_t>(size))));
  }
  return last;
}

AMFileSystem::ECM AMFileSystem::find(const std::string &path, SearchType type,
                                     amf interrupt_flag, int timeout_ms) {
  amf flag = interrupt_flag ? interrupt_flag : global_interrupt_flag;
  std::string resolved_path;
  ClientRef client = ResolveClientForPath(path, &resolved_path, false, flag);
  if (!client.is_valid()) {
    return {EC::ClientNotFound, "Client not found"};
  }
  if (resolved_path.empty()) {
    return {EC::InvalidArg, "Empty path"};
  }
  std::string abs_path = BuildPath(client, resolved_path);
  int64_t start_time = am_ms();
  auto results =
      client.client->find(abs_path, type, flag, timeout_ms, start_time);
  for (const auto &info : results) {
    prompt_manager_.Print(StylePath(info, info.path));
  }
  return {EC::Success, ""};
}

/** Walk a path and print entries based on filters. */
AMFileSystem::ECM AMFileSystem::walk(const std::string &path, bool only_file,
                                     bool only_dir, bool ignore_special_file,
                                     amf interrupt_flag, int timeout_ms) {
  if (only_file && only_dir) {
    return {EC::InvalidArg, "Conflicting filters: both file and dir"};
  }
  amf flag = interrupt_flag ? interrupt_flag : global_interrupt_flag;
  std::string resolved_path;
  ClientRef client = ResolveClientForPath(path, &resolved_path, false, flag);
  if (!client.is_valid()) {
    return {EC::ClientNotFound, "Client not found"};
  }
  if (resolved_path.empty()) {
    return {EC::InvalidArg, "Empty path"};
  }
  std::string abs_path = BuildPath(client, resolved_path);
  int64_t start_time = am_ms();
  auto [rcm, list] = client.client->iwalk(abs_path, ignore_special_file, flag,
                                          timeout_ms, start_time);
  if (rcm.first != EC::Success) {
    return rcm;
  }
  for (const auto &info : list) {
    if (only_file && info.type == PathType::DIR) {
      continue;
    }
    if (only_dir && info.type != PathType::DIR) {
      continue;
    }
    prompt_manager_.Print(StylePath(info, info.path));
  }
  return {EC::Success, ""};
}

/** Print a directory tree using the client walk output. */
AMFileSystem::ECM AMFileSystem::tree(const std::string &path, int max_depth,
                                     bool ignore_special_file,
                                     amf interrupt_flag, int timeout_ms) {
  amf flag = interrupt_flag ? interrupt_flag : global_interrupt_flag;
  std::string resolved_path;
  ClientRef client = ResolveClientForPath(path, &resolved_path, false, flag);
  if (!client.is_valid()) {
    return {EC::ClientNotFound, "Client not found"};
  }
  if (resolved_path.empty()) {
    return {EC::InvalidArg, "Empty path"};
  }
  std::string abs_path = BuildPath(client, resolved_path);
  int64_t start_time = am_ms();
  auto [rcm, structure] = client.client->walk(
      abs_path, max_depth, ignore_special_file, flag, timeout_ms, start_time);
  if (rcm.first != EC::Success) {
    return rcm;
  }

  AMTree::TreeNodeMap nodes;
  const auto join_parts = [](const std::vector<std::string> &parts) {
    return AMPathStr::join(parts);
  };
  const auto join_pair = [](const std::string &a, const std::string &b) {
    return AMPathStr::join(a, b);
  };
  AMTree::BuildTreeNodes(abs_path, structure, &nodes, join_parts, join_pair);
  AMTree::SortTreeNodes(&nodes);
  AMTree::PrintTree(
      abs_path, nodes,
      [this](const PathInfo &info, const std::string &name) {
        return StylePath(info, name);
      },
      [this](const std::string &line) { prompt_manager_.Print(line); },
      join_pair);
  return {EC::Success, ""};
}

AMFileSystem::ECM AMFileSystem::mkdir(const std::string &path,
                                      amf interrupt_flag, int timeout_ms) {
  amf flag = interrupt_flag ? interrupt_flag : global_interrupt_flag;
  std::vector<std::string> targets = SplitTargets(path);
  if (targets.empty()) {
    return {EC::InvalidArg, "Empty path"};
  }
  ECM last = {EC::Success, ""};
  for (const auto &target : targets) {
    std::string resolved_path;
    ClientRef client =
        ResolveClientForPath(target, &resolved_path, false, flag);
    if (!client.is_valid()) {
      last = {EC::ClientNotFound, "Client not found"};
      continue;
    }
    if (resolved_path.empty()) {
      last = {EC::InvalidArg, "Empty path"};
      continue;
    }
    std::string abs_path = BuildPath(client, resolved_path);
    int64_t start_time = am_ms();
    ECM rcm = client.client->mkdirs(abs_path, flag, timeout_ms, start_time);
    if (rcm.first != EC::Success) {
      last = rcm;
    }
  }
  return last;
}

AMFileSystem::ECM AMFileSystem::rm(const std::string &path, amf interrupt_flag,
                                   int timeout_ms) {
  amf flag = interrupt_flag ? interrupt_flag : global_interrupt_flag;
  std::vector<std::string> targets = SplitTargets(path);
  if (targets.empty()) {
    return {EC::InvalidArg, "Empty path"};
  }
  bool canceled = false;
  if (!prompt_manager_.PromptYesNo("Remove path(s)? (y/N): ", &canceled)) {
    return {EC::Terminate, "Remove canceled"};
  }
  ECM last = {EC::Success, ""};
  for (const auto &target : targets) {
    std::string resolved_path;
    ClientRef client =
        ResolveClientForPath(target, &resolved_path, false, flag);
    if (!client.is_valid()) {
      last = {EC::ClientNotFound, "Client not found"};
      continue;
    }
    if (resolved_path.empty()) {
      last = {EC::InvalidArg, "Empty path"};
      continue;
    }
    std::string abs_path = BuildPath(client, resolved_path);
    try {
      int64_t start_time = am_ms();
      ECM rcm = client.client->saferm(abs_path, flag, timeout_ms, start_time);
      if (rcm.first != EC::Success) {
        last = rcm;
      }
    } catch (const std::exception &ex) {
      last = {EC::UnImplentedMethod, ex.what()};
    }
  }
  return last;
}

AMFileSystem::ClientRef
AMFileSystem::ResolveClientByName(const std::string &nickname) const {
  ClientRef result;
  std::string lowered = AMStr::lowercase(nickname);
  if (lowered.empty() || lowered == "local") {
    result.nickname = "local";
    result.client = client_manager_.LOCAL;
    return result;
  }

  auto names = client_manager_.Clients().get_nicknames();
  for (const auto &name : names) {
    if (AMStr::lowercase(name) == lowered) {
      result.nickname = name;
      result.client = client_manager_.Clients().GetHost(name);
      return result;
    }
  }
  return result;
}

AMFileSystem::ClientRef AMFileSystem::ResolveClientForPath(
    const std::string &input, std::string *out_path, bool allow_config_probe,
    amf interrupt_flag) {
  amf flag = interrupt_flag ? interrupt_flag : global_interrupt_flag;
  if (out_path) {
    out_path->clear();
  }

  std::string current_nickname =
      client_manager_.CLIENT ? client_manager_.CLIENT->GetNickname() : "local";
  ClientRef current = ResolveClientByName(current_nickname);

  auto at_pos = input.find('@');
  if (at_pos == std::string::npos) {
    if (out_path) {
      *out_path = input;
    }
    return current;
  }

  std::string prefix = input.substr(0, at_pos);
  std::string rest = input.substr(at_pos + 1);
  std::string lowered = AMStr::lowercase(prefix);

  if (prefix.empty() || lowered == "local") {
    if (out_path) {
      *out_path = rest;
    }
    return ResolveClientByName("local");
  }

  ClientRef matched = ResolveClientByName(prefix);
  if (matched.is_valid()) {
    if (out_path) {
      *out_path = rest;
    }
    return matched;
  }

  if (allow_config_probe) {
    auto cfg = config_manager_.GetClientConfig(prefix, false);
    if (cfg.first.first == EC::Success) {
      if (out_path) {
        *out_path = rest;
      }
      return ResolveOrCreateClient(prefix, flag);
    }
  }

  if (out_path) {
    *out_path = input;
  }
  return current;
}

AMFileSystem::ClientRef
AMFileSystem::ResolveOrCreateClient(const std::string &nickname,
                                    amf interrupt_flag) {
  amf flag = interrupt_flag ? interrupt_flag : global_interrupt_flag;
  ClientRef existing = ResolveClientByName(nickname);
  if (existing.is_valid()) {
    return existing;
  }
  bool canceled = false;
  if (!prompt_manager_.PromptYesNo("Client not found. Create it? (y/N): ",
                                   &canceled)) {
    return {};
  }
  auto created =
      client_manager_.AddClient(nickname, nullptr, false, false, {}, flag);
  if (created.first.first != EC::Success || !created.second) {
    return {};
  }
  return {nickname, created.second};
}

std::vector<std::string>
AMFileSystem::SplitTargets(const std::string &input) const {
  std::vector<std::string> targets;
  std::istringstream iss(input);
  std::string token;
  while (iss >> token) {
    targets.push_back(token);
  }
  return targets;
}

std::string AMFileSystem::BuildPath(const ClientRef &client,
                                    const std::string &path) const {
  if (!client.client) {
    return path;
  }
  if (path.empty()) {
    return GetOrInitWorkdir(client.client);
  }
  std::string cwd = GetOrInitWorkdir(client.client);
  std::string home = client.client->GetHomeDir();
  return AMFS::abspath(path, true, home, cwd, "/");
}

std::string AMFileSystem::GetClientWorkdir(
    const std::shared_ptr<BaseClient> &client) const {
  if (!client) {
    return "";
  }
  std::lock_guard<std::recursive_mutex> lock(client->public_kv_mtx);
  auto it = client->public_kv.find("workdir");
  if (it != client->public_kv.end()) {
    return it->second;
  }
  return "";
}

void AMFileSystem::SetClientWorkdir(const std::shared_ptr<BaseClient> &client,
                                    const std::string &path) {
  if (!client) {
    return;
  }
  std::lock_guard<std::recursive_mutex> lock(client->public_kv_mtx);
  client->public_kv["workdir"] = AMPathStr::UnifyPathSep(path, "/");
}

void AMFileSystem::EnsureClientWorkdir(
    const std::shared_ptr<BaseClient> &client) {
  if (!client) {
    return;
  }
  std::lock_guard<std::recursive_mutex> lock(client->public_kv_mtx);
  if (client->public_kv.find("workdir") == client->public_kv.end()) {
    client->public_kv["workdir"] =
        AMPathStr::UnifyPathSep(client->GetHomeDir(), "/");
  }
}

std::string AMFileSystem::GetOrInitWorkdir(
    const std::shared_ptr<BaseClient> &client) const {
  if (!client) {
    return "";
  }
  {
    std::lock_guard<std::recursive_mutex> lock(client->public_kv_mtx);
    auto it = client->public_kv.find("workdir");
    if (it != client->public_kv.end()) {
      return it->second;
    }
  }
  std::string home = AMPathStr::UnifyPathSep(client->GetHomeDir(), "/");
  {
    std::lock_guard<std::recursive_mutex> lock(client->public_kv_mtx);
    client->public_kv["workdir"] = home;
  }
  return home;
}

void AMFileSystem::UpdateHistory(const std::string &nickname,
                                 const std::string &path) {
  if (nickname.empty() || path.empty()) {
    return;
  }
  last_cd_ = nickname + "@" + path;
}

AMFileSystem::ECM AMFileSystem::PrintClientStatus(const ClientRef &client,
                                                  bool update,
                                                  amf interrupt_flag) {
  amf flag = interrupt_flag ? interrupt_flag : global_interrupt_flag;
  ECM rcm =
      update ? client.client->Check(flag, -1, -1) : client.client->GetState();
  std::string cwd = GetOrInitWorkdir(client.client);
  std::string prefix =
      (rcm.first == EC::Success ? "✅ " : "❌ ") + client.nickname + "@" + cwd;
  if (rcm.first == EC::Success) {
    prompt_manager_.Print(prefix);
    return rcm;
  }
  std::string ec_name = std::string(magic_enum::enum_name(rcm.first));
  std::string line = AMStr::amfmt("{}  {} : {}", prefix, ec_name, rcm.second);
  prompt_manager_.Print(line);
  return rcm;
}

std::string AMFileSystem::FormatSize(uint64_t size) const {
  const char *units[] = {"B", "KB", "MB", "GB", "TB"};
  double value = static_cast<double>(size);
  size_t idx = 0;
  while (value >= 1024.0 && idx < 4) {
    value /= 1024.0;
    ++idx;
  }
  std::ostringstream oss;
  if (value == static_cast<uint64_t>(value)) {
    oss << static_cast<uint64_t>(value);
  } else {
    oss << std::fixed << std::setprecision(1) << value;
  }
  oss << units[idx];
  return oss.str();
}

std::string AMFileSystem::FormatTimestamp(double value) const {
  if (value <= 0) {
    return "";
  }
  return FormatTime(static_cast<uint64_t>(value), "%Y/%m/%d %H:%M:%S");
}

std::string AMFileSystem::FormatPathType(PathType type) const {
  return std::string(magic_enum::enum_name(type));
}

std::string AMFileSystem::FormatStatOutput(const PathInfo &info) const {
  const size_t width = 12;
  std::ostringstream out;
  out << info.path << "\n\n";

  out << std::left << std::setw(static_cast<int>(width)) << "type" << " : "
      << FormatPathType(info.type) << "\n";
  out << std::left << std::setw(static_cast<int>(width)) << "owner" << " : "
      << info.owner << "\n";
  out << std::left << std::setw(static_cast<int>(width)) << "mode" << " : "
      << info.mode_str << "\n";
  out << std::left << std::setw(static_cast<int>(width)) << "size" << " : "
      << FormatSize(info.size) << "\n\n";

  out << std::left << std::setw(static_cast<int>(width)) << "create_time"
      << " : " << FormatTimestamp(info.create_time) << "\n";
  out << std::left << std::setw(static_cast<int>(width)) << "modify_time"
      << " : " << FormatTimestamp(info.modify_time) << "\n";
  out << std::left << std::setw(static_cast<int>(width)) << "access_time"
      << " : " << FormatTimestamp(info.access_time) << "\n";
  return out.str();
}

std::string AMFileSystem::StylePath(const PathInfo &info,
                                    const std::string &path) const {
  std::string style = "regular";
  if (info.type == PathType::DIR) {
    style = "dir";
  } else if (info.type == PathType::SYMLINK) {
    style = "symlink";
  }
  std::string styled = config_manager_.Format(path, style);
  return styled.empty() ? path : styled;
}

// bool AMFileSystem::PromptYesNo(const std::string &prompt,
//                                bool default_no) const {
//   std::string answer;
//   if (!prompt_manager_.Prompt(prompt, "", &answer)) {
//     return false;
//   }
//   AMStr::VStrip(answer);
//   if (answer.empty()) {
//     return !default_no;
//   }
//   std::string lower = answer;
//   std::transform(
//       lower.begin(), lower.end(), lower.begin(),
//       [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
//   return lower == "y" || lower == "yes";
// }

// bool AMFileSystem::IsAbsolutePath(const std::string &path) const {
//   if (path.empty()) {
//     return false;
//   }
//   if (path[0] == '/' || path[0] == '\\') {
//     return true;
//   }
//   if (path.size() >= 2 && std::isalpha(static_cast<unsigned char>(path[0]))
//   &&
//       path[1] == ':') {
//     return true;
//   }
//   return false;
// }
