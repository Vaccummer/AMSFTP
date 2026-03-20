#include "domain/filesystem/dep/FileSystemManager.dep.hpp"
#include "interface/adapters/ApplicationAdapters.hpp"
#include "foundation/core/DataClass.hpp"
#include "foundation/core/Enum.hpp"
#include "foundation/core/Path.hpp"
#include "foundation/tools/time.hpp"
#include "domain/config/ConfigModel.hpp"
#include "domain/host/HostManager.hpp"
#include "interface/prompt/Prompt.hpp"
#include <algorithm>
#include <cctype>
#include <cstddef>
#include <functional>
#include <iomanip>
#include <magic_enum/magic_enum.hpp>
#include <sstream>
#include <unordered_map>
#include <unordered_set>


using EC = ErrorCode;
using ClientHandle = std::shared_ptr<AMDomain::client::IClientPort>;

namespace {
/**
 * @brief Return application-managed workdir for one client.
 */
std::string ResolveClientWorkdir_(const ClientHandle &client) {
  if (!client) {
    return "";
  }
  return AMInterface::ApplicationAdapters::Runtime::GetOrInitWorkdir(client);
}

/**
 * @brief Return cached login directory for one client.
 */
std::string ResolveClientLoginDir_(const ClientHandle &client) {
  if (!client) {
    return "";
  }
  auto state = AMInterface::ApplicationAdapters::Runtime::ClientPathPortOrThrow()
                   .GetWorkdirState(client->ConfigPort().GetNickname());
  return state.login_dir;
}

/**
 * @brief Build connect context for explicit protocol connect flows.
 */
AMDomain::client::ClientConnectContext
BuildConnectContext_(const std::string &nickname, const std::string &hostname,
                     const std::string &username,
                     AMDomain::client::ClientProtocol protocol, int64_t port,
                     const std::string &password,
                     const std::string &keyfile) {
  AMDomain::client::ClientConnectContext context{};
  context.request.nickname = nickname;
  context.request.hostname = hostname;
  context.request.username = username;
  context.request.protocol = protocol;
  context.request.port = port;
  context.request.password = password;
  context.request.keyfile = keyfile;
  context.options.register_to_manager = true;
  return context;
}
} // namespace

namespace AMPathTree {
enum class TreeStyleRole {
  Root,
  NodeDirName,
  Filename,
};

struct TreeNode {
  std::vector<std::string> children;
  std::vector<PathInfo> files;
};

using TreeNodeMap = std::unordered_map<std::string, TreeNode>;
using JoinPartsFn =
    std::function<std::string(const std::vector<std::string> &)>;
using JoinPairFn =
    std::function<std::string(const std::string &, const std::string &)>;

/**
 * @brief Build tree nodes from walk structure data.
 */
inline void BuildTreeNodes(
    const std::string &root,
    const std::vector<
        std::pair<std::vector<std::string>, std::vector<PathInfo>>> &structure,
    TreeNodeMap *nodes, const JoinPartsFn &join_parts,
    const JoinPairFn &join_pair) {
  (void)join_pair;
  if (!nodes) {
    return;
  }
  nodes->clear();
  std::unordered_set<std::string> child_set;

  auto ensure_node = [&](const std::string &dir_path) {
    if (nodes->find(dir_path) == nodes->end()) {
      (*nodes)[dir_path] = TreeNode{};
    }
  };

  auto add_child = [&](const std::string &parent, const std::string &name) {
    std::string key = parent + "\n" + name;
    if (child_set.find(key) != child_set.end()) {
      return;
    }
    child_set.insert(key);
    (*nodes)[parent].children.push_back(name);
  };

  ensure_node(root);
  for (const auto &entry : structure) {
    const auto &parts = entry.first;
    const auto &files = entry.second;
    if (parts.empty()) {
      continue;
    }
    std::string dir_path = join_parts ? join_parts(parts) : root;
    ensure_node(dir_path);
    if (!files.empty()) {
      auto &list = (*nodes)[dir_path].files;
      list.insert(list.end(), files.begin(), files.end());
    }
    if (parts.size() > 1) {
      std::vector<std::string> parent_parts(parts.begin(), parts.end() - 1);
      std::string parent_path = join_parts ? join_parts(parent_parts) : root;
      ensure_node(parent_path);
      add_child(parent_path, parts.back());
    }
  }
}

/**
 * @brief Sort tree node children and files by case-insensitive name.
 */
inline void SortTreeNodes(TreeNodeMap *nodes) {
  if (!nodes) {
    return;
  }
  for (auto &[dir, node] : *nodes) {
    (void)dir;
    std::sort(node.children.begin(), node.children.end(),
              [&](const std::string &a, const std::string &b) {
                return AMStr::lowercase(a) < AMStr::lowercase(b);
              });
    std::sort(node.files.begin(), node.files.end(),
              [&](const PathInfo &a, const PathInfo &b) {
                return AMStr::lowercase(a.name) < AMStr::lowercase(b.name);
              });
  }
}

/**
 * @brief Print a tree using a style callback and line printer.
 * @return True if the tree is fully printed; false if stopped early.
 */
inline bool
PrintTree(const std::string &root, const TreeNodeMap &nodes,
          const std::function<std::string(TreeStyleRole, const PathInfo &,
                                          const std::string &)> &style_path,
          const std::function<void(const std::string &)> &print_line,
          const JoinPairFn &join_pair,
          const std::function<bool()> &should_stop = {}) {
  if (!print_line) {
    return true;
  }
  PathInfo dir_info;
  dir_info.type = PathType::DIR;
  dir_info.path = root;
  const std::string root_line =
      style_path ? style_path(TreeStyleRole::Root, dir_info, root) : root;
  if (should_stop && should_stop()) {
    return false;
  }
  print_line(root_line);
  if (should_stop && should_stop()) {
    return false;
  }

  std::function<bool(const std::string &, const std::string &)> walk_tree =
      [&](const std::string &dir_path, const std::string &prefix) {
        auto it = nodes.find(dir_path);
        if (it == nodes.end()) {
          return true;
        }
        const auto &children = it->second.children;
        const auto &files = it->second.files;
        const size_t dir_count = children.size();
        const size_t file_count = files.size();

        for (size_t i = 0; i < dir_count; ++i) {
          if (should_stop && should_stop()) {
            return false;
          }
          const bool last = (i + 1 == dir_count && file_count == 0);
          const std::string connector = last ? "└── " : "├── ";
          const std::string next_prefix = prefix + (last ? "    " : "│   ");
          const std::string child_name = children[i];
          const std::string styled =
              style_path
                  ? style_path(TreeStyleRole::NodeDirName, dir_info, child_name)
                  : child_name;
          print_line(prefix + connector + styled);
          if (join_pair) {
            const std::string child_path = join_pair(dir_path, child_name);
            if (!walk_tree(child_path, next_prefix)) {
              return false;
            }
          }
        }

        for (size_t i = 0; i < file_count; ++i) {
          if (should_stop && should_stop()) {
            return false;
          }
          const bool last = (i + 1 == file_count);
          (void)last;
          const std::string connector = (i + 1 == file_count) ? "└── " : "├── ";
          const auto &info = files[i];
          const std::string styled =
              style_path ? style_path(TreeStyleRole::Filename, info, info.name)
                         : info.name;
          print_line(prefix + connector + styled);
        }
        return true;
      };

  return walk_tree(root, "");
}
} // namespace AMPathTree

/**
 * @brief Normalize one configured tree style into a single opening bbcode tag.
 */
static std::string NormalizeTreeStyleTag_(const std::string &raw) {
  std::string trimmed = AMStr::Strip(raw);
  if (trimmed.empty()) {
    return "";
  }
  if (trimmed.find("[/") != std::string::npos) {
    return "";
  }
  if (trimmed.front() != '[') {
    trimmed.insert(trimmed.begin(), '[');
  }
  if (trimmed.back() != ']') {
    trimmed.push_back(']');
  }
  return trimmed;
}

/**
 * @brief Apply one normalized bbcode tag to text.
 */
static std::string ApplyTreeStyleTag_(const std::string &tag,
                                      const std::string &text) {
  if (tag.empty()) {
    return text;
  }
  return tag + text + "[/]";
}

/**
 * @brief Right-pad text with spaces to target width.
 */
static std::string PadRight_(const std::string &text, size_t width) {
  if (text.size() >= width) {
    return text;
  }
  return text + std::string(width - text.size(), ' ');
}

/**
 * @brief Build wrapped command text for configured command prefix.
 */
static std::string BuildShellCommandWithPrefix_(const std::string &command,
                                                const std::string &cmd_prefix,
                                                bool wrap_cmd,
                                                ClientProtocol protocol) {
  if (cmd_prefix.empty()) {
    return command;
  }
  if (!wrap_cmd) {
    return cmd_prefix + command;
  }
  return AMStr::fmt("{}\"{}\"", cmd_prefix,
                    AMStr::replace_all(command, "\"", "'"));
}

/**
 * @brief Print host-like detail using runtime client data.
 */
static void PrintClientDetail_(AMPromptManager &prompt_manager,
                               const std::string &nickname,
                               const std::shared_ptr<
                                   AMDomain::client::IClientPort>
                                   &client,
                               bool print_title = true) {
  if (!client) {
    return;
  }
  ClientMetaData metadata = {};
  bool metadata_exists = false;
  const ClientMetaData *metadata_ptr =
      client->QueryNamedValue<ClientMetaData>(
          AMDomain::client::kClientMetadataStoreName,
          metadata_exists);
  if (metadata_exists && metadata_ptr) {
    metadata = *metadata_ptr;
  }
  std::string cwd = ResolveClientWorkdir_(client);
  if (cwd.empty()) {
    cwd = AMPathStr::UnifyPathSep(client->ConfigPort().GetHomeDir(), "/");
  }
  std::string login_dir = ResolveClientLoginDir_(client);
  if (login_dir.empty()) {
    login_dir = cwd;
  }
  metadata.login_dir = login_dir;
  metadata.cwd = cwd;

  const ConRequest &request = client->ConfigPort().GetRequest();
  auto values = request.GetStrDict();
  auto metadata_values = metadata.GetStrDict();
  values.insert(values.end(), metadata_values.begin(), metadata_values.end());

  if (print_title) {
    prompt_manager.Print("[!pre][" + nickname + "][/pre]");
  }
  size_t width = 0;
  for (const auto &field : values) {
    if (field.first == "nickname") {
      continue;
    }
    width = std::max<size_t>(width, field.first.size());
  }
  for (const auto &field : values) {
    if (field.first == "nickname") {
      continue;
    }
    std::string render_value = field.second;
    if (field.first == "cmd_prefix") {
      render_value = "\"" + render_value + "\"";
    } else if (render_value.empty()) {
      render_value = "\"\"";
    }
    std::ostringstream line;
    line << std::left << std::setw(static_cast<int>(width)) << field.first
         << " :   " << render_value;
    prompt_manager.Print(line.str());
  }
}

/**
 * @brief Print one check-detail block with status and optional error info.
 */
static void PrintCheckDetail_(AMPromptManager &prompt_manager,
                              const std::string &nickname,
                              const std::shared_ptr<
                                  AMDomain::client::IClientPort>
                                  &client,
                              const ECM &rcm) {
  const std::string status = (rcm.first == EC::Success) ? "✅" : "❌";
  prompt_manager.Print(AMStr::fmt("[{}] {}", nickname, status));

  if (rcm.first != EC::Success) {
    const std::string ec_name = std::string(magic_enum::enum_name(rcm.first));
    const std::string msg = rcm.second.empty()
                                ? std::string(AMStr::ToString(rcm.first))
                                : rcm.second;
    prompt_manager.Print(AMStr::fmt("error_code :   {}", ec_name));
    prompt_manager.Print(AMStr::fmt("error_msg  :   {}", msg));
  }

  PrintClientDetail_(prompt_manager, nickname, client, false);
}

ECM AMDomain::filesystem::AMFileSystem::check(const std::string &nickname, bool detail,
                        amf interrupt_flag) {
  std::vector<std::string> targets = SplitTargets(nickname);
  return check(targets, detail, interrupt_flag);
}

/** Check whether clients exist from nickname list. */
ECM AMDomain::filesystem::AMFileSystem::check(const std::vector<std::string> &nicknames, bool detail,
                        amf interrupt_flag) {
  amf flag = interrupt_flag ? interrupt_flag : TaskControlToken::Instance();
  std::vector<std::string> targets = AMStr::UniqueTargetsKeepOrder(nicknames);
  if (targets.empty()) {
    const std::string current =
        AMInterface::ApplicationAdapters::Runtime::CurrentNickname();
    targets.push_back(current.empty() ? "local" : current);
  }

  auto resolve_by_name = [&](const std::string &nickname,
                             ECM *out_error) -> ClientRef {
    ClientRef result;
    if (out_error) {
      *out_error = {EC::Success, ""};
    }
    std::string lowered = AMStr::lowercase(nickname);
    if (lowered.empty() || AMStr::lowercase(nickname) == "local") {
      result.nickname = "local";
      result.client = AMInterface::ApplicationAdapters::Runtime::LocalClient();
      return result;
    }

    std::string resolved_name = nickname;
    auto client =
        AMInterface::ApplicationAdapters::Runtime::GetHostClient(resolved_name);
    if (!client) {
      auto names = AMInterface::ApplicationAdapters::Runtime::ListClientNames();
      for (const auto &name : names) {
        if (AMStr::lowercase(name) == lowered) {
          resolved_name = name;
          client = AMInterface::ApplicationAdapters::Runtime::GetHostClient(name);
          break;
        }
      }
    }

    if (!client) {
      if (out_error) {
        const std::string styled =
            AMInterface::ApplicationAdapters::Runtime::Format(nickname, "nickname");
        if (AMInterface::ApplicationAdapters::Runtime::HostConfigManagerOrThrow().HostExists(nickname)) {
          *out_error = {EC::ClientNotFound,
                        AMStr::fmt("Client not established: {}", styled)};
        } else {
          *out_error = {EC::HostConfigNotFound,
                        AMStr::fmt("Config not found: {}", styled)};
        }
      }
      return result;
    }

    result.nickname = resolved_name;
    result.client = client;
    return result;
  };

  ECM last = {EC::Success, ""};
  std::vector<ECM> errors;
  std::vector<ClientRef> resolved_clients;
  resolved_clients.reserve(targets.size());

  for (const auto &name : targets) {
    if (flag && !flag->IsRunning()) {
      return {EC::Terminate, "Interrupted by user"};
    }
    ECM resolve_rcm = {EC::Success, ""};
    ClientRef client = resolve_by_name(name, &resolve_rcm);
    if (!client.is_valid()) {
      last = resolve_rcm;
      errors.push_back(resolve_rcm);
      continue;
    }
    resolved_clients.push_back(std::move(client));
  }

  for (const auto &err : errors) {
    AMPromptManager::Instance().ErrorFormat(err);
  }

  const ClientStatusFormat table_format =
      BuildClientStatusFormat_(resolved_clients);
  for (const auto &client : resolved_clients) {
    if (flag && !flag->IsRunning()) {
      return {EC::Terminate, "Interrupted by user"};
    }
    ECM rcm = {EC::Success, ""};
    if (detail) {
      rcm = client.client->IOPort().Check();
      PrintCheckDetail_(AMPromptManager::Instance(), client.nickname,
                        client.client, rcm);
    } else {
      rcm = PrintClientStatus(client, true, flag, &table_format);
    }
    if (rcm.first != EC::Success) {
      last = rcm;
    }
  }
  return last;
}

ECM AMDomain::filesystem::AMFileSystem::remove_client(const std::string &nickname) {
  std::vector<std::string> targets = SplitTargets(nickname);
  if (targets.empty()) {
    const std::string msg = "Empty nickname";
    AMPromptManager::Instance().ErrorFormat(ECM{EC::InvalidArg, msg});
    return {EC::InvalidArg, msg};
  }

  std::vector<std::string> unique_targets =
      AMStr::UniqueTargetsKeepOrder(targets);
  const std::string current =
      AMInterface::ApplicationAdapters::Runtime::CurrentClient()
          ? AMInterface::ApplicationAdapters::Runtime::CurrentClient()
                ->ConfigPort().GetNickname()
          : "";
  const std::string current_lower = AMStr::lowercase(current);
  const auto names = AMInterface::ApplicationAdapters::Runtime::ListClientNames();

  ECM last = {EC::Success, ""};
  std::vector<std::string> valid_targets;
  std::vector<std::string> styled_targets;
  valid_targets.reserve(unique_targets.size());
  styled_targets.reserve(unique_targets.size());

  auto find_client_name = [&](const std::string &input) -> std::string {
    std::string lowered = AMStr::lowercase(input);
    for (const auto &name : names) {
      if (AMStr::lowercase(name) == lowered) {
        return name;
      }
    }
    return "";
  };

  for (const auto &target : unique_targets) {
    const std::string lowered = AMStr::lowercase(target);
    const std::string styled =
        AMInterface::ApplicationAdapters::Runtime::Format(target, "nickname");
    if (target.empty()) {
      const std::string msg = "Invalid Empty Client Name";
      last = {EC::InvalidArg, msg};
      AMPromptManager::Instance().ErrorFormat(ECM{EC::InvalidArg, msg});
      continue;
    }
    if (lowered == "local") {
      const std::string msg = "Local client cannot be removed";
      last = {EC::InvalidArg, msg};
      AMPromptManager::Instance().ErrorFormat(ECM{EC::InvalidArg, msg});
      continue;
    }
    if (!current_lower.empty() && lowered == current_lower) {
      const std::string msg = "Cannot remove current client";
      last = {EC::InvalidArg, msg};
      AMPromptManager::Instance().ErrorFormat(ECM{EC::InvalidArg, msg});
      continue;
    }
    std::string resolved = find_client_name(target);
    if (resolved.empty()) {
      const std::string msg = AMStr::fmt("Client not established: {}", styled);
      last = {EC::ClientNotFound, msg};
      AMPromptManager::Instance().ErrorFormat(ECM{EC::ClientNotFound, msg});
      continue;
    }
    valid_targets.push_back(resolved);
    styled_targets.push_back(
        AMInterface::ApplicationAdapters::Runtime::Format(resolved, "nickname"));
  }

  if (styled_targets.empty()) {
    return last.first == EC::Success
               ? ECM{EC::ClientNotFound, "no valid clients to remove"}
               : last;
  }

  bool canceled = false;
  std::string target_line;
  for (size_t i = 0; i < styled_targets.size(); ++i) {
    if (i > 0) {
      target_line += ", ";
    }
    target_line += styled_targets[i];
  }
  const std::string question =
      AMStr::fmt("Remove clients: {} ? (y/N): ", target_line);
  if (!AMPromptManager::Instance().PromptYesNo(question, &canceled) ||
      canceled) {
    const std::string msg = "Remove clients canceled";
    AMPromptManager::Instance().FmtPrint(
        "🚫  {}\n", AMInterface::ApplicationAdapters::Runtime::Format(msg, "abort"));
    AMPromptManager::Instance().ErrorFormat(ECM{EC::ConfigCanceled, msg});
    return {EC::Terminate, msg};
  }

  for (const auto &target : valid_targets) {
    ECM rcm = AMInterface::ApplicationAdapters::Runtime::RemoveClient(target);
    if (rcm.first != EC::Success) {
      AMPromptManager::Instance().ErrorFormat(rcm);
      last = rcm;
    }
  }
  return last;
}

ECM AMDomain::filesystem::AMFileSystem::print_clients(bool detail, amf interrupt_flag) {
  amf flag = interrupt_flag ? interrupt_flag : TaskControlToken::Instance();
  std::vector<std::string> seen;
  std::vector<ClientRef> resolved_clients;

  auto add_unique = [&](const std::string &name) {
    std::string lowered = AMStr::lowercase(name);
    if (std::find(seen.begin(), seen.end(), lowered) != seen.end()) {
      return;
    }
    seen.push_back(lowered);
    ClientRef client;
    if (lowered.empty() || lowered == "local") {
      client.nickname = "local";
      client.client = AMInterface::ApplicationAdapters::Runtime::LocalClient();
    } else {
      auto names = AMInterface::ApplicationAdapters::Runtime::ListClientNames();
      for (const auto &item : names) {
        if (AMStr::lowercase(item) == lowered) {
          client.nickname = item;
          client.client =
              AMInterface::ApplicationAdapters::Runtime::GetHostClient(item);
          break;
        }
      }
    }
    if (client.is_valid()) {
      resolved_clients.push_back(std::move(client));
    }
  };

  add_unique("local");

  for (const auto &name :
       AMInterface::ApplicationAdapters::Runtime::ListClientNames()) {
    add_unique(name);
  }

  const ClientStatusFormat table_format =
      BuildClientStatusFormat_(resolved_clients);
  for (const auto &client : resolved_clients) {
    if (flag && !flag->IsRunning()) {
      return {EC::Terminate, "Interrupted by user"};
    }
    PrintClientStatus(client, true, flag, &table_format);
    if (detail) {
      PrintClientDetail_(AMPromptManager::Instance(), client.nickname,
                         client.client);
    }
  }

  return {EC::Success, ""};
}

ECM AMDomain::filesystem::AMFileSystem::change_client(const std::string &nickname,
                                amf interrupt_flag) {
  amf flag = interrupt_flag ? interrupt_flag : TaskControlToken::Instance();
  if (nickname.empty()) {
    const std::string msg = "Empty nickname";
    AMPromptManager::Instance().ErrorFormat(ECM{EC::InvalidArg, msg});
    return {EC::InvalidArg, msg};
  }
  std::string lowered = AMStr::lowercase(nickname);
  ClientRef client;
  if (lowered.empty() || lowered == "local") {
    client.nickname = "local";
    client.client = AMInterface::ApplicationAdapters::Runtime::LocalClient();
  } else {
    auto names = AMInterface::ApplicationAdapters::Runtime::ListClientNames();
    for (const auto &name : names) {
      if (AMStr::lowercase(name) == lowered) {
        client.nickname = name;
        client.client =
            AMInterface::ApplicationAdapters::Runtime::GetHostClient(name);
        break;
      }
    }
  }
  if (!client.is_valid()) {
    bool canceled = false;
    if (!AMPromptManager::Instance().PromptYesNo(
            "Client not found. Create it? (y/N): ", &canceled)) {
      const std::string msg = "Operation aborted";
      AMPromptManager::Instance().ErrorFormat(ECM{EC::ConfigCanceled, msg});
      return {EC::Terminate, msg};
    }
    auto added = AMInterface::ApplicationAdapters::Runtime::ConnectNickname(
        nickname, false, true, flag);
    if (added.first.first != EC::Success) {
      AMPromptManager::Instance().ErrorFormat(added.first);
      return added.first;
    }
    client.nickname = nickname;
    client.client = added.second;
  }
  AMInterface::ApplicationAdapters::Runtime::SetCurrentClient(client.client);
  std::string cwd =
      AMInterface::ApplicationAdapters::Runtime::GetOrInitWorkdir(client.client);
  (void)AMInterface::ApplicationAdapters::Runtime::SetClientWorkdir(
      client.client, cwd);
  return {EC::Success, ""};
}

ECM AMDomain::filesystem::AMFileSystem::connect(const std::string &nickname, bool force,
                          amf interrupt_flag, bool switch_client) {
  amf flag = interrupt_flag ? interrupt_flag : TaskControlToken::Instance();
  auto result =
      AMInterface::ApplicationAdapters::Runtime::ConnectNickname(nickname, force,
                                                                 true, flag);
  if (result.first.first != EC::Success) {
    return result.first;
  }
  if (switch_client && result.second) {
    return change_client(result.second->ConfigPort().GetNickname(), flag);
  }
  return {EC::Success, ""};
}

ECM AMDomain::filesystem::AMFileSystem::sftp(const std::string &nickname, const std::string &hostname,
                       const std::string &username, int64_t port,
                       const std::string &password, const std::string &keyfile,
                       amf interrupt_flag) {
  amf flag = interrupt_flag ? interrupt_flag : TaskControlToken::Instance();
  auto result = AMInterface::ApplicationAdapters::Runtime::ConnectRequest(
      BuildConnectContext_(nickname, hostname, username, ClientProtocol::SFTP,
                           port, password, keyfile),
      flag);
  if (result.first.first != EC::Success || !result.second) {
    return result.first;
  }
  return change_client(result.second->ConfigPort().GetNickname(), flag);
}

ECM AMDomain::filesystem::AMFileSystem::sftp(const std::string &nickname,
                       const std::string &user_at_host, int64_t port,
                       const std::string &password, const std::string &keyfile,
                       amf interrupt_flag) {
  auto pos = user_at_host.find('@');
  if (pos == std::string::npos || pos == 0 || pos + 1 >= user_at_host.size()) {
    return {EC::InvalidArg, "Invalid user@host format"};
  }
  std::string username = user_at_host.substr(0, pos);
  std::string hostname = user_at_host.substr(pos + 1);
  return sftp(nickname, hostname, username, port, password, keyfile,
              interrupt_flag);
}

ECM AMDomain::filesystem::AMFileSystem::ftp(const std::string &nickname, const std::string &hostname,
                      const std::string &username, int64_t port,
                      const std::string &password, const std::string &keyfile,
                      amf interrupt_flag) {
  amf flag = interrupt_flag ? interrupt_flag : TaskControlToken::Instance();
  auto result = AMInterface::ApplicationAdapters::Runtime::ConnectRequest(
      BuildConnectContext_(nickname, hostname, username, ClientProtocol::FTP,
                           port, password, keyfile),
      flag);
  if (result.first.first != EC::Success || !result.second) {
    return result.first;
  }
  return change_client(result.second->ConfigPort().GetNickname(), flag);
}

ECM AMDomain::filesystem::AMFileSystem::ftp(const std::string &nickname,
                      const std::string &user_at_host, int64_t port,
                      const std::string &password, const std::string &keyfile,
                      amf interrupt_flag) {
  auto pos = user_at_host.find('@');
  if (pos == std::string::npos || pos == 0 || pos + 1 >= user_at_host.size()) {
    return {EC::InvalidArg, "Invalid user@host format"};
  }
  std::string username = user_at_host.substr(0, pos);
  std::string hostname = user_at_host.substr(pos + 1);
  return ftp(nickname, hostname, username, port, password, keyfile,
             interrupt_flag);
}

ECM AMDomain::filesystem::AMFileSystem::cd(const std::string &path, amf interrupt_flag,
                     bool from_history) {
  amf flag = interrupt_flag ? interrupt_flag : TaskControlToken::Instance();
  if (path.empty()) {
    return {EC::Success, ""};
  }

  bool from_history_flag = from_history;
  if (path == "-") {
    if (cd_history_.empty()) {
      AMPromptManager::Instance().ErrorFormat(
          ECM{EC::InvalidArg, "No previous directory"});
      return {EC::InvalidArg, "No previous directory"};
    }
    std::string target = cd_history_.back();
    cd_history_.pop_back();
    return cd(target, flag, true);
  }

  auto [nickname, resolved_path, client_ptr, rcm] =
      AMInterface::ApplicationAdapters::Runtime::ParsePath(path, flag);
  if (rcm.first != EC::Success || !client_ptr) {
    AMPromptManager::Instance().ErrorFormat(rcm);
    return rcm;
  }
  ClientRef client{nickname, client_ptr};

  if (resolved_path.empty()) {
    return change_client(client.nickname, flag);
  }

  std::string abs_path = BuildPath(client, resolved_path);

  auto [rcm2, info] = client.client->IOPort().stat(abs_path, false);
  if (rcm2.first != EC::Success) {
    AMPromptManager::Instance().ErrorFormat(rcm2);
    return rcm2;
  }
  if (!info.path.empty()) {
    const std::string resolved = AMPathStr::UnifyPathSep(info.path, "/");
    if (!resolved.empty() && AMPathStr::IsAbs(resolved, "/")) {
      abs_path = resolved;
    }
  }
  if (info.type != PathType::DIR) {
    AMPromptManager::Instance().ErrorFormat(
        ECM{EC::NotADirectory, "Path is not a directory"});
    return {EC::NotADirectory, "Path is not a directory"};
  }

  std::string prev_cwd =
      AMInterface::ApplicationAdapters::Runtime::GetOrInitWorkdir(client.client);
  if (!from_history_flag && abs_path != prev_cwd) {
    UpdateHistory(client.nickname, prev_cwd);
  }

  AMInterface::ApplicationAdapters::Runtime::SetClientWorkdir(client.client, abs_path);
  AMInterface::ApplicationAdapters::Runtime::SetCurrentClient(client.client);
  return {EC::Success, ""};
}

ECM AMDomain::filesystem::AMFileSystem::stat(const std::string &path, amf interrupt_flag,
                       int timeout_ms) {
  std::vector<std::string> targets = SplitTargets(path);
  return stat(targets, interrupt_flag, timeout_ms);
}

/** Print stat info for multiple paths. */
ECM AMDomain::filesystem::AMFileSystem::stat(const std::vector<std::string> &paths,
                       amf interrupt_flag, int timeout_ms) {
  amf flag = interrupt_flag ? interrupt_flag : TaskControlToken::Instance();
  std::vector<std::string> targets = AMStr::UniqueTargetsKeepOrder(paths);
  if (targets.empty()) {
    targets.emplace_back(".");
  }
  ECM last = {EC::Success, ""};
  std::vector<PathInfo> infos;
  infos.reserve(targets.size());
  for (const auto &target : targets) {
    if (flag && !flag->IsRunning()) {
      last = {EC::Terminate, "Interrupted by user"};
      AMPromptManager::Instance().ErrorFormat(last);
      break;
    }
    auto [nickname, resolved_path, client_ptr, rcm] =
        AMInterface::ApplicationAdapters::Runtime::ParsePath(target, flag);
    if (rcm.first != EC::Success || !client_ptr) {
      last = rcm;
      AMPromptManager::Instance().ErrorFormat(last);
      continue;
    }

    ClientRef client{nickname, client_ptr};
    std::string abs_path = BuildPath(client, resolved_path);
    int64_t start_time = AMTime::miliseconds();
    auto [rcm2, info] =
        client.client->IOPort().stat(abs_path, false, timeout_ms, start_time);
    if (rcm2.first != EC::Success) {
      last = rcm2;
      AMPromptManager::Instance().ErrorFormat(last);
      continue;
    }
    infos.push_back(info);
  }
  for (const auto &info : infos) {
    AMPromptManager::Instance().Print(FormatStatOutput(info));
  }
  return last;
}

ECM AMDomain::filesystem::AMFileSystem::ls(const std::string &path, bool list_like, bool show_all,
                     amf interrupt_flag, int timeout_ms) {
  amf flag = interrupt_flag ? interrupt_flag : TaskControlToken::Instance();
  if (flag && !flag->IsRunning()) {
    ECM out = {EC::Terminate, "Interrupted by user"};
    AMPromptManager::Instance().ErrorFormat(out);
    return out;
  }
  auto [nickname, resolved_path, client_ptr, rcm] =
      AMInterface::ApplicationAdapters::Runtime::ParsePath(path, flag);
  if (rcm.first != EC::Success || !client_ptr) {
    AMPromptManager::Instance().ErrorFormat(rcm);
    return rcm;
  }
  ClientRef client{nickname, client_ptr};
  std::string target_path = resolved_path.empty() ? "." : resolved_path;
  std::string abs_path = BuildPath(client, target_path);
  int64_t start_time = AMTime::miliseconds();
  auto [rcm2, list] =
      client.client->IOPort().listdir(abs_path, timeout_ms, start_time);
  if (rcm2.first != EC::Success) {
    AMPromptManager::Instance().ErrorFormat(rcm2);
    return rcm2;
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
      max_len = std::max<size_t>(max_len, info.name.size());
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
      AMPromptManager::Instance().Print(line.str());
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
    mode_width = std::max<size_t>(mode_width, mode.size());

    owner_width = std::max<size_t>(owner_width, info.owner.size());

    std::string size_str = AMStr::FormatSize(info.size);
    size_width = std::max<size_t>(size_width, size_str.size());

    std::string time_str = FormatTimestamp(info.modify_time);
    time_values.push_back(time_str);
    time_width = std::max<size_t>(time_width, time_str.size());
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
    std::string size_str = AMStr::FormatSize(info.size);
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
    AMPromptManager::Instance().Print(line.str());
  }

  return {EC::Success, ""};
}

ECM AMDomain::filesystem::AMFileSystem::getsize(const std::string &path, amf interrupt_flag,
                          int timeout_ms) {
  std::vector<std::string> targets = SplitTargets(path);
  return getsize(targets, interrupt_flag, timeout_ms);
}

/** Print total size for multiple paths. */
ECM AMDomain::filesystem::AMFileSystem::getsize(const std::vector<std::string> &paths,
                          amf interrupt_flag, int timeout_ms) {
  amf flag = interrupt_flag ? interrupt_flag : TaskControlToken::Instance();
  std::vector<std::string> targets = AMStr::UniqueTargetsKeepOrder(paths);
  if (targets.empty()) {
    ECM out = {EC::InvalidArg, "Empty path"};
    AMPromptManager::Instance().ErrorFormat(out);
    return out;
  }
  ECM last = {EC::Success, ""};
  std::vector<std::pair<std::string, int64_t>> results;
  results.reserve(targets.size());
  for (const auto &target : targets) {
    if (flag && !flag->IsRunning()) {
      last = {EC::Terminate, "Interrupted by user"};
      AMPromptManager::Instance().ErrorFormat(last);
      break;
    }
    auto [nickname, resolved_path, client_ptr, rcm] =
        AMInterface::ApplicationAdapters::Runtime::ParsePath(target, flag);
    if (rcm.first != EC::Success || !client_ptr) {
      last = rcm.first == EC::Success
                 ? ECM{EC::ClientNotFound, "Client not found"}
                 : rcm;
      AMPromptManager::Instance().ErrorFormat(last);
      continue;
    }
    if (resolved_path.empty()) {
      last = {EC::InvalidArg, "Empty path"};
      AMPromptManager::Instance().ErrorFormat(last);
      continue;
    }
    ClientRef client{nickname, client_ptr};
    std::string abs_path = BuildPath(client, resolved_path);
    int64_t start_time = AMTime::miliseconds();
    int64_t size =
        client.client->IOPort().getsize(abs_path, true, timeout_ms, start_time);
    if (size < 0) {
      last = {EC::UnknownError, "Get size failed"};
      AMPromptManager::Instance().ErrorFormat(last);
      continue;
    }
    results.emplace_back(abs_path, size);
  }
  for (const auto &item : results) {
    AMPromptManager::Instance().FmtPrint(
        "{}  {}", item.first,
        AMStr::FormatSize(static_cast<size_t>(item.second)));
  }
  return last;
}

ECM AMDomain::filesystem::AMFileSystem::find(const std::string &path, SearchType type,
                       amf interrupt_flag, int timeout_ms) {
  amf flag = interrupt_flag ? interrupt_flag : TaskControlToken::Instance();
  auto [nickname, resolved_path, client_ptr, rcm] =
      AMInterface::ApplicationAdapters::Runtime::ParsePath(path, flag);
  if (rcm.first != EC::Success) {
    AMPromptManager::Instance().ErrorFormat(rcm);
    return rcm;
  }
  if (resolved_path.empty()) {
    ECM out = {EC::InvalidArg, "Empty path"};
    AMPromptManager::Instance().ErrorFormat(out);
    return out;
  }
  ClientRef client{nickname, client_ptr};
  std::string abs_path = BuildPath(client, resolved_path);
  int64_t start_time = AMTime::miliseconds();
  auto results =
      client.client->IOPort().find(abs_path, type, timeout_ms, start_time);
  for (const auto &info : results) {
    AMPromptManager::Instance().Print(StylePath(info, info.path));
  }
  return {EC::Success, ""};
}

/** Walk a path and print entries based on filters. */
ECM AMDomain::filesystem::AMFileSystem::walk(const std::string &path, bool only_file, bool only_dir,
                       bool show_all, bool ignore_special_file, bool quiet,
                       amf interrupt_flag, int timeout_ms) {
  if (only_file && only_dir) {
    return {EC::InvalidArg, "Conflicting filters: both file and dir"};
  }
  amf flag = interrupt_flag ? interrupt_flag : TaskControlToken::Instance();
  auto [nickname, resolved_path, client_ptr, rcm] =
      AMInterface::ApplicationAdapters::Runtime::ParsePath(path, flag);
  if (rcm.first != EC::Success || !client_ptr) {
    if (!quiet) {
      AMPromptManager::Instance().ErrorFormat(rcm);
    }
    return rcm;
  }
  if (resolved_path.empty()) {
    ECM out = {EC::InvalidArg, "Empty path"};
    if (!quiet) {
      AMPromptManager::Instance().ErrorFormat(out);
    }
    return out;
  }
  ClientRef client{nickname, client_ptr};
  std::string abs_path = BuildPath(client, resolved_path);
  int64_t start_time = AMTime::miliseconds();
  AMFS::WalkErrorCallback error_cb = MakeWalkErrorCallback("walk", quiet);
  auto [rcm2, pack] =
      client.client->IOPort().iwalk(abs_path, show_all, ignore_special_file,
                                    error_cb, timeout_ms, start_time);
  if (rcm2.first != EC::Success) {
    AMPromptManager::Instance().ErrorFormat(rcm2);
    return rcm2;
  }
  if (!quiet && !error_cb) {
    for (const auto &err : pack.second) {
      AMPromptManager::Instance().ErrorFormat(err.first, err.second.second);
    }
  }
  const auto &list = pack.first;
  for (const auto &info : list) {
    if (only_file && info.type == PathType::DIR) {
      continue;
    }
    if (only_dir && info.type != PathType::DIR) {
      continue;
    }
    AMPromptManager::Instance().Print(StylePath(info, info.path));
  }
  return {EC::Success, ""};
}

/** Print a directory tree using the client walk output with optional filters.
 */
ECM AMDomain::filesystem::AMFileSystem::tree(const std::string &path, int max_depth, bool only_dir,
                       bool show_all, bool ignore_special_file, bool quiet,
                       amf interrupt_flag, int timeout_ms) {
  amf flag = interrupt_flag ? interrupt_flag : TaskControlToken::Instance();
  auto [nickname, resolved_path, client_ptr, rcm] =
      AMInterface::ApplicationAdapters::Runtime::ParsePath(path, flag);
  if (rcm.first != EC::Success || !client_ptr) {
    ECM out = rcm.first == EC::Success
                  ? ECM{EC::ClientNotFound, "Client not found"}
                  : rcm;

    AMPromptManager::Instance().ErrorFormat(out);

    return out;
  }
  if (resolved_path.empty()) {
    ECM out = {EC::InvalidArg, "Empty path"};
    AMPromptManager::Instance().ErrorFormat(out);
    return out;
  }
  ClientRef client{nickname, client_ptr};
  std::string abs_path = BuildPath(client, resolved_path);
  int64_t start_time = AMTime::miliseconds();
  AMFS::WalkErrorCallback error_cb = MakeWalkErrorCallback("tree", quiet);
  auto [rcm2, pack] =
      client.client->IOPort().walk(abs_path, max_depth, show_all,
                                   ignore_special_file, error_cb, timeout_ms,
                                   start_time);
  if (rcm2.first != EC::Success) {
    AMPromptManager::Instance().ErrorFormat(rcm2);
    return rcm2;
  }
  if (!quiet && !error_cb) {
    for (const auto &err : pack.second) {
      const std::string msg =
          AMStr::fmt("{} : {}", err.first, err.second.second);
      AMPromptManager::Instance().ErrorFormat(ECM{err.second.first, msg});
    }
  }
  auto &structure = pack.first;

  if (only_dir) {
    for (auto &entry : structure) {
      entry.second.clear();
    }
  }

  AMPathTree::TreeNodeMap nodes;
  const auto join_parts = [](const std::vector<std::string> &parts) {
    return AMPathStr::join(parts);
  };
  const auto join_pair = [](const std::string &a, const std::string &b) {
    return AMPathStr::join(a, b);
  };
  AMPathTree::BuildTreeNodes(abs_path, structure, &nodes, join_parts,
                             join_pair);
  if (flag && !flag->IsRunning()) {
    ECM out = {EC::Terminate, "Interrupted by user"};
    if (!quiet) {
      AMPromptManager::Instance().ErrorFormat(out);
    }
    return out;
  }
  AMPathTree::SortTreeNodes(&nodes);
  if (flag && !flag->IsRunning()) {
    ECM out = {EC::Terminate, "Interrupted by user"};
    if (!quiet) {
      AMPromptManager::Instance().ErrorFormat(out);
    }
    return out;
  }
  const bool printed = AMPathTree::PrintTree(
      abs_path, nodes,
      [this](AMPathTree::TreeStyleRole role, const PathInfo &info,
             const std::string &name) {
        std::vector<std::string> style_key = {"Style", "Path"};
        switch (role) {
        case AMPathTree::TreeStyleRole::Root:
          style_key.push_back("root");
          break;
        case AMPathTree::TreeStyleRole::NodeDirName:
          style_key.push_back("node_dir_name");
          break;
        case AMPathTree::TreeStyleRole::Filename:
          style_key.push_back("filename");
          break;
        default:
          break;
        }
        const std::string tag = NormalizeTreeStyleTag_(
            AMInterface::ApplicationAdapters::Runtime::ResolveSettingString(
                style_key, ""));
        if (!tag.empty()) {
          const std::string display_name =
              AMStr::BBCEscape(AMPathStr::UnifyPathSep(name, "/"));
          return ApplyTreeStyleTag_(tag, display_name);
        }
        return StylePath(info, name);
      },
      [this](const std::string &line) {
        AMPromptManager::Instance().Print(line);
      },
      join_pair, [flag]() { return flag && !flag->IsRunning(); });
  if (!printed && flag && !flag->IsRunning()) {
    ECM out = {EC::Terminate, "Interrupted by user"};
    if (!quiet) {
      AMPromptManager::Instance().ErrorFormat(out);
    }
    return out;
  }
  return {EC::Success, ""};
}

ECM AMDomain::filesystem::AMFileSystem::TestRTT(int times, amf interrupt_flag) {
  amf flag = interrupt_flag ? interrupt_flag : TaskControlToken::Instance();
  if (flag && !flag->IsRunning()) {
    ECM out = {EC::Terminate, "Interrupted by user"};
    AMPromptManager::Instance().ErrorFormat(out);
    return out;
  }

  auto client = AMInterface::ApplicationAdapters::Runtime::CurrentClient();
  if (!client) {
    ECM out = {EC::ClientNotFound, "Client not found"};
    AMPromptManager::Instance().ErrorFormat(out);
    return out;
  }
  if (client->ConfigPort().GetProtocol() == ClientProtocol::LOCAL) {
    ECM out = {EC::InvalidArg, "Local client does not support RTT"};
    AMPromptManager::Instance().ErrorFormat(out);
    return out;
  }
  if (times <= 0) {
    times = 1;
  }
  double rtt = client->IOPort().GetRTT(times);
  if (rtt < 0.0) {
    ECM out = {EC::CommonFailure, "RTT measurement failed"};
    AMPromptManager::Instance().ErrorFormat(out);
    return out;
  }
  AMPromptManager::Instance().FmtPrint("{} ms", rtt);
  return {EC::Success, ""};
}

/**
 * @brief Run one shell command on current SFTP/local client.
 *
 * The final command is built from host config:
 * - no prefix: cmd
 * - prefix + wrapped cmd when wrap_cmd is true
 * - prefix + cmd when wrap_cmd is false
 */
CR AMDomain::filesystem::AMFileSystem::ShellRun(const std::string &cmd, int max_time_ms,
                          amf interrupt_flag) {
  amf flag = interrupt_flag ? interrupt_flag : TaskControlToken::Instance();
  if (flag && !flag->IsRunning()) {
    return {ECM{EC::Terminate, "Interrupted by user"}, {"", -1}};
  }

  const std::string command = AMStr::Strip(cmd);
  if (command.empty()) {
    return {ECM{EC::InvalidArg, "Empty shell command"}, {"", -1}};
  }

  auto client = AMInterface::ApplicationAdapters::Runtime::CurrentClient();
  if (!client) {
    client = AMInterface::ApplicationAdapters::Runtime::LocalClient();
  }
  if (!client) {
    return {ECM{EC::ClientNotFound, "Client not found"}, {"", -1}};
  }

  const ClientProtocol protocol = client->ConfigPort().GetProtocol();
  if (protocol != ClientProtocol::SFTP && protocol != ClientProtocol::LOCAL) {
    return {ECM{EC::OperationUnsupported,
                "Shell command only supported by SFTP/local client"},
            {"", -1}};
  }

  std::string nickname = client->ConfigPort().GetNickname();
  if (nickname.empty()) {
    nickname = "local";
  }

  std::string cmd_prefix;
  bool wrap_cmd = false;
  if (AMStr::lowercase(nickname) == "local") {
    auto [cfg_rcm, cfg] = AMInterface::ApplicationAdapters::Runtime::HostConfigManagerOrThrow().GetLocalConfig();
    if (cfg_rcm.first == EC::Success) {
      cmd_prefix = cfg.metadata.cmd_prefix;
      wrap_cmd = cfg.metadata.wrap_cmd;
    }
  } else {
    auto [cfg_rcm, cfg] = AMInterface::ApplicationAdapters::Runtime::HostConfigManagerOrThrow().GetClientConfig(nickname);
    if (cfg_rcm.first == EC::Success) {
      cmd_prefix = cfg.metadata.cmd_prefix;
      wrap_cmd = cfg.metadata.wrap_cmd;
    }
  }

  std::string final_cmd =
      BuildShellCommandWithPrefix_(command, cmd_prefix, wrap_cmd, protocol);
  AMPromptManager::Instance().Print(final_cmd);
  return client->IOPort().ConductCmd(final_cmd, max_time_ms);
}

/**
 * @brief Resolve a path using client workdir/home and print the absolute path.
 * @param path Input path supporting "host@path" or a plain path; empty uses the
 *        current client workdir.
 * @param interrupt_flag Optional interrupt flag shared with other operations.
 * @param timeout_ms Reserved for interface compatibility (unused).
 * @return ECM status describing success or failure.
 */
ECM AMDomain::filesystem::AMFileSystem::realpath(const std::string &path, amf interrupt_flag,
                           int timeout_ms) {
  (void)interrupt_flag;
  (void)timeout_ms;

  std::string input = AMStr::Strip(path);
  std::string nickname;
  std::string resolved_path;
  ClientHandle client_ptr;
  ECM rcm = {EC::Success, ""};

  if (input.empty()) {
    client_ptr = AMInterface::ApplicationAdapters::Runtime::CurrentClient()
                     ? AMInterface::ApplicationAdapters::Runtime::CurrentClient()
                     : AMInterface::ApplicationAdapters::Runtime::LocalClient();
    if (!client_ptr) {
      ECM out = {EC::ClientNotFound, "Client not found"};
      AMPromptManager::Instance().ErrorFormat(out);
      return out;
    }
    nickname = client_ptr->ConfigPort().GetNickname();
  } else if (!input.empty() && input.back() == '@' && input.front() != '@') {
    nickname = input.substr(0, input.size() - 1);
    std::string lowered = AMStr::lowercase(nickname);
    if (nickname.empty() || lowered == "local") {
      nickname = "local";
      client_ptr = AMInterface::ApplicationAdapters::Runtime::LocalClient();
    } else {
      auto cfg = AMInterface::ApplicationAdapters::Runtime::HostConfigManagerOrThrow().GetClientConfig(nickname);
      if (cfg.first.first != EC::Success) {
        ECM out = {EC::HostConfigNotFound,
                   AMStr::fmt("Config not found: {}", nickname)};
        AMPromptManager::Instance().ErrorFormat(out);
        return out;
      }
      client_ptr = AMInterface::ApplicationAdapters::Runtime::GetHostClient(
          nickname);
      if (!client_ptr) {
        ECM out = {EC::ClientNotFound,
                   AMStr::fmt("Client not established: {}", nickname)};
        AMPromptManager::Instance().ErrorFormat(out);
        return out;
      }
    }
  } else {
    std::tie(nickname, resolved_path, client_ptr, rcm) =
        AMInterface::ApplicationAdapters::Runtime::ParsePath(input);
    if (rcm.first != EC::Success || !client_ptr) {
      if (rcm.first == EC::HostConfigNotFound) {
        ECM out = {EC::HostConfigNotFound,
                   AMStr::fmt("Config not found: {}", nickname)};
        AMPromptManager::Instance().ErrorFormat(out);
        return out;
      }
      if (rcm.first == EC::ClientNotFound) {
        ECM out = {EC::ClientNotFound,
                   AMStr::fmt("Client not established: {}", nickname)};
        AMPromptManager::Instance().ErrorFormat(out);
        return out;
      }
      if (!client_ptr && rcm.first == EC::Success) {
        ECM out = {EC::ClientNotFound, "Client not found"};
        AMPromptManager::Instance().ErrorFormat(out);
        return out;
      }
      AMPromptManager::Instance().ErrorFormat(rcm);
      return rcm;
    }
  }

  std::string cwd = AMInterface::ApplicationAdapters::Runtime::GetOrInitWorkdir(client_ptr);
  if (resolved_path.empty()) {
    AMPromptManager::Instance().Print(cwd);
    return {EC::Success, ""};
  }
  const std::string home =
      AMPathStr::UnifyPathSep(client_ptr->ConfigPort().GetHomeDir(), "/");
  const std::string abs_path =
      AMFS::abspath(resolved_path, true, home, cwd, "/");
  AMPromptManager::Instance().Print(abs_path);
  return {EC::Success, ""};
}

ECM AMDomain::filesystem::AMFileSystem::mkdir(const std::string &path, amf interrupt_flag,
                        int timeout_ms) {
  std::vector<std::string> targets = SplitTargets(path);
  return mkdir(targets, interrupt_flag, timeout_ms);
}

/** Create directories (recursive) for multiple paths. */
ECM AMDomain::filesystem::AMFileSystem::mkdir(const std::vector<std::string> &paths,
                        amf interrupt_flag, int timeout_ms) {
  amf flag = interrupt_flag ? interrupt_flag : TaskControlToken::Instance();
  std::vector<std::string> targets = AMStr::UniqueTargetsKeepOrder(paths);
  if (targets.empty()) {
    ECM out = {EC::InvalidArg, "Empty path"};
    AMPromptManager::Instance().ErrorFormat(out);
    return out;
  }
  ECM last = {EC::Success, ""};
  for (const auto &target : targets) {
    if (flag && !flag->IsRunning()) {
      last = {EC::Terminate, "Interrupted by user"};
      AMPromptManager::Instance().ErrorFormat(last);
      return last;
    }
    auto [nickname, resolved_path, client_ptr, rcm] =
        AMInterface::ApplicationAdapters::Runtime::ParsePath(target, flag);
    if (rcm.first != EC::Success || !client_ptr) {
      last = rcm;
      continue;
    }
    if (resolved_path.empty()) {
      last = {EC::InvalidArg, "Empty path"};
      continue;
    }
    ClientRef client{nickname, client_ptr};
    std::string abs_path = BuildPath(client, resolved_path);
    int64_t start_time = AMTime::miliseconds();
    ECM rcm2 = client.client->IOPort().mkdirs(abs_path, timeout_ms, start_time);
    if (rcm2.first != EC::Success) {
      last = rcm2;
    }
  }
  return last;
}

ECM AMDomain::filesystem::AMFileSystem::rm(const std::string &path, bool quiet, amf interrupt_flag,
                     int timeout_ms) {
  std::vector<std::string> targets = SplitTargets(path);
  return rm(targets, false, false, quiet, interrupt_flag, timeout_ms);
}

/** Remove paths using safe removal. */
ECM AMDomain::filesystem::AMFileSystem::rm(const std::vector<std::string> &paths, bool quiet,
                     amf interrupt_flag, int timeout_ms) {
  return rm(paths, false, false, quiet, interrupt_flag, timeout_ms);
}

/** Remove paths using safe or permanent removal with optional force. */
ECM AMDomain::filesystem::AMFileSystem::rm(const std::vector<std::string> &paths, bool permanent,
                     bool force, bool quiet, amf interrupt_flag,
                     int timeout_ms) {
  amf flag = interrupt_flag ? interrupt_flag : TaskControlToken::Instance();
  std::vector<std::string> targets = AMStr::UniqueTargetsKeepOrder(paths);
  if (targets.empty()) {
    return {EC::InvalidArg, "Empty path"};
  }
  ECM last = {EC::Success, ""};
  for (const auto &target : targets) {
    if (flag && !flag->IsRunning()) {
      if (!quiet) {
        AMPromptManager::Instance().ErrorFormat(
            ECM{EC::Terminate, "Interrupted by user"});
      }
      return {EC::Terminate, "Interrupted by user"};
    }
    if (permanent || !force) {
      bool canceled = false;
      std::string prompt =
          permanent
              ? AMStr::fmt("Remove path permanently? [{}] (y/N): ", target)
              : AMStr::fmt("Remove path? [{}] (y/N): ", target);
      if (!AMPromptManager::Instance().PromptYesNo(prompt, &canceled)) {
        last = {EC::Terminate, "Remove canceled"};
        if (!quiet) {
          AMPromptManager::Instance().ErrorFormat(
              ECM{EC::ConfigCanceled, "Remove canceled"});
        }
        continue;
      }
    }
    auto [nickname, resolved_path, client_ptr, rcm] =
        AMInterface::ApplicationAdapters::Runtime::ParsePath(target, flag);
    if (rcm.first != EC::Success || !client_ptr) {
      last = rcm.first == EC::Success
                 ? ECM{EC::ClientNotFound, "Client not found"}
                 : rcm;
      if (!quiet) {
        AMPromptManager::Instance().ErrorFormat(last);
      }
      continue;
    }
    if (resolved_path.empty()) {
      last = {EC::InvalidArg, "Empty path"};
      if (!quiet) {
        AMPromptManager::Instance().ErrorFormat(last);
      }
      continue;
    }
    ClientRef client{nickname, client_ptr};
    std::string abs_path = BuildPath(client, resolved_path);
    try {
      int64_t start_time = AMTime::miliseconds();
      ECM rcm;
      RMR errors = {};
      if (permanent) {
        AMFS::WalkErrorCallback error_cb = MakeWalkErrorCallback("rm", quiet);
        auto tmp_res = client.client->IOPort().remove(abs_path, error_cb,
                                                      timeout_ms, start_time);
        rcm = tmp_res.first;
        errors = tmp_res.second;
      } else {
        rcm = client.client->IOPort().saferm(abs_path, timeout_ms, start_time);
      }
      if (rcm.first != EC::Success) {
        last = rcm;
        if (!errors.empty()) {
          last = {EC::UnknownError, errors.back().second.second};
        }
        if (!quiet) {
          AMPromptManager::Instance().ErrorFormat(last);
        }
      }
    } catch (const std::exception &ex) {
      last = {EC::UnImplentedMethod, ex.what()};
      if (!quiet) {
        AMPromptManager::Instance().ErrorFormat(last);
      }
    }
  }
  return last;
}

std::vector<std::string>
AMDomain::filesystem::AMFileSystem::SplitTargets(const std::string &input) const {
  std::vector<std::string> targets;
  std::istringstream iss(input);
  std::string token;
  while (iss >> token) {
    targets.push_back(token);
  }
  return targets;
}

std::string AMDomain::filesystem::AMFileSystem::BuildPath(const ClientRef &client,
                                    const std::string &path) const {
  return AMInterface::ApplicationAdapters::Runtime::BuildPath(client.client, path);
}

void AMDomain::filesystem::AMFileSystem::UpdateHistory(const std::string &nickname,
                                 const std::string &path) {
  if (path.empty()) {
    return;
  }
  static const int max_history = std::max<int>(
      1, AMInterface::ApplicationAdapters::Runtime::ResolveSettingInt(
             {"Options", "FileSystem", "max_cd_history"}, 5));

  const std::string entry = nickname + "@" + path;
  if (!cd_history_.empty() && cd_history_.back() == entry) {
    return;
  }
  cd_history_.push_back(entry);
  while (cd_history_.size() > max_history) {
    cd_history_.pop_front();
  }
}

/**
 * @brief Build aligned status table widths from resolved client rows.
 */
AMDomain::filesystem::AMFileSystem::ClientStatusFormat AMDomain::filesystem::AMFileSystem::BuildClientStatusFormat_(
    const std::vector<ClientRef> &clients) const {
  ClientStatusFormat format;
  for (const auto &entry : clients) {
    if (!entry.client) {
      continue;
    }
    const std::string protocol =
        "[" + std::string(AMStr::ToString(entry.client->ConfigPort().GetProtocol())) + "]";
    const std::string nickname = entry.nickname;
    const std::string cwd =
        AMInterface::ApplicationAdapters::Runtime::GetOrInitWorkdir(entry.client);
    format.protocol_width = std::max(format.protocol_width, protocol.size());
    format.nickname_width = std::max(format.nickname_width, nickname.size());
    format.cwd_width = std::max(format.cwd_width, cwd.size());
  }
  return format;
}

ECM AMDomain::filesystem::AMFileSystem::PrintClientStatus(const ClientRef &client, bool update,
                                    amf interrupt_flag,
                                    const ClientStatusFormat *format) {
  amf flag = interrupt_flag ? interrupt_flag : TaskControlToken::Instance();
  (void)flag;
  ECM rcm = update ? client.client->IOPort().Check()
                   : client.client->ConfigPort().GetState().second;
  std::string cwd = AMInterface::ApplicationAdapters::Runtime::GetOrInitWorkdir(client.client);
  const std::string proto_label =
      "[" + std::string(AMStr::ToString(client.client->ConfigPort().GetProtocol())) + "]";
  const std::string nickname_label = client.nickname;
  const std::string padded_proto =
      format ? PadRight_(proto_label, format->protocol_width) : proto_label;
  const std::string padded_nickname =
      format ? PadRight_(nickname_label, format->nickname_width)
             : nickname_label;
  const std::string padded_cwd =
      format ? PadRight_(cwd, format->cwd_width) : cwd;
  const std::string styled_proto =
      AMInterface::ApplicationAdapters::Runtime::Format(padded_proto, "protocol");
  const std::string styled_nickname =
      AMInterface::ApplicationAdapters::Runtime::Format(padded_nickname, "nickname");
  PathInfo cwd_info;
  cwd_info.type = PathType::DIR;
  cwd_info.path = cwd;
  cwd_info.name = AMPathStr::basename(cwd);
  std::string styled_cwd = StylePath(cwd_info, padded_cwd);

  std::ostringstream header;
  header << (rcm.first == EC::Success ? "✅  " : "❌  ") << styled_proto << "  "
         << styled_nickname << "  " << styled_cwd;
  if (rcm.first == EC::Success) {
    AMPromptManager::Instance().Print(header.str());
    return rcm;
  }
  std::string ec_name = std::string(magic_enum::enum_name(rcm.first));
  const std::string styled_ec =
      AMInterface::ApplicationAdapters::Runtime::Format(ec_name, "error");
  const std::string styled_msg =
      AMInterface::ApplicationAdapters::Runtime::Format(rcm.second, "error");
  std::string line =
      AMStr::fmt("{}  {}  {}", header.str(), styled_ec, styled_msg);
  AMPromptManager::Instance().Print(line);
  return rcm;
}

std::string AMDomain::filesystem::AMFileSystem::FormatTimestamp(double value) const {
  if (value <= 0) {
    return "";
  }
  return FormatTime(static_cast<size_t>(value), "%Y/%m/%d %H:%M:%S");
}

std::string AMDomain::filesystem::AMFileSystem::FormatStatOutput(const PathInfo &info) const {
  const size_t width = 12;
  std::ostringstream out;
  const std::string display_path = AMPathStr::UnifyPathSep(info.path, "/");
  out << display_path << "\n";

  out << std::left << std::setw(static_cast<int>(width)) << "type" << " : "
      << AMStr::ToString(info.type) << "\n";
  out << std::left << std::setw(static_cast<int>(width)) << "owner" << " : "
      << info.owner << "\n";
  out << std::left << std::setw(static_cast<int>(width)) << "mode" << " : "
      << info.mode_str << "\n";
  out << std::left << std::setw(static_cast<int>(width)) << "size" << " : "
      << AMStr::FormatSize(info.size) << "\n";

  out << std::left << std::setw(static_cast<int>(width)) << "create_time"
      << " : " << FormatTimestamp(info.create_time) << "\n";
  out << std::left << std::setw(static_cast<int>(width)) << "modify_time"
      << " : " << FormatTimestamp(info.modify_time) << "\n";
  out << std::left << std::setw(static_cast<int>(width)) << "access_time"
      << " : " << FormatTimestamp(info.access_time) << "\n";
  return out.str();
}

/** Create a walk error callback that prints formatted errors. */
AMFS::WalkErrorCallback
AMDomain::filesystem::AMFileSystem::MakeWalkErrorCallback(const std::string &func_name,
                                    bool quiet) const {
  if (quiet) {
    return nullptr;
  }
  return std::make_shared<
      std::function<void(const std::string &, const ECM &)>>(
      [this, func_name](const std::string &path, const ECM &rcm) {
        if (rcm.first == EC::Success) {
          return;
        }
        std::string msg = rcm.second;
        if (!func_name.empty()) {
          msg = AMStr::fmt("{} error: {}", func_name, msg);
        }
        AMPromptManager::Instance().ErrorFormat(ECM{rcm.first, msg});
      });
}

std::string AMDomain::filesystem::AMFileSystem::StylePath(const PathInfo &info,
                                    const std::string &path) const {
  std::string base_key = "regular";
  if (info.type == PathType::DIR) {
    base_key = "dir";
  } else if (info.type == PathType::SYMLINK) {
    base_key = "symlink";
  } else if (info.type != PathType::FILE) {
    base_key = "otherspecial";
  }

  const std::string display_path = AMPathStr::UnifyPathSep(path, "/");
  return AMInterface::ApplicationAdapters::Runtime::Format(display_path, base_key, &info);
}







