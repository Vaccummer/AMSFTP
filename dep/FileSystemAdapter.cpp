#include "interface/adapters/filesystem/FileSystemAdapter.hpp"

#include "foundation/core/Path.hpp"
#include "foundation/tools/string.hpp"
#include "interface/prompt/Prompt.hpp"

#include <algorithm>
#include <iomanip>
#include <sstream>

namespace AMInterface::filesystem {
namespace {
/**
 * @brief Return true when client interrupt flag reports interrupted state.
 */
bool IsInterrupted_(AMDomain::client::amf interrupt_flag) {
  return interrupt_flag && interrupt_flag->IsInterrupted();
}

/**
 * @brief Keep the latest failure while preserving success state.
 */
ECM MergeStatus_(const ECM &current, const ECM &next) {
  return isok(next) ? current : next;
}

/**
 * @brief Normalize one path and trim trailing slash for depth calculations.
 */
std::string NormalizePathForDepth_(const std::string &path) {
  std::string normalized = AMPathStr::UnifyPathSep(path, "/");
  while (normalized.size() > 1 && normalized.back() == '/') {
    normalized.pop_back();
  }
  return normalized;
}

/**
 * @brief Count relative depth from root to one full path.
 */
size_t RelativeDepth_(const std::string &root, const std::string &full_path) {
  const std::string normalized_root = NormalizePathForDepth_(root);
  const std::string normalized_full = NormalizePathForDepth_(full_path);
  if (normalized_root.empty() || normalized_full.empty()) {
    return 0;
  }
  if (normalized_full == normalized_root) {
    return 0;
  }
  if (normalized_full.rfind(normalized_root, 0) != 0) {
    return 0;
  }

  std::string relative = normalized_full.substr(normalized_root.size());
  while (!relative.empty() && relative.front() == '/') {
    relative.erase(relative.begin());
  }
  if (relative.empty()) {
    return 0;
  }
  return static_cast<size_t>(
             std::count(relative.begin(), relative.end(), '/')) +
         1;
}
} // namespace

/**
 * @brief Construct direct CLI adapter from client app service and prompt
 * manager.
 */
FileSystemCliAdapter::FileSystemCliAdapter(
    AMApplication::client::ClientAppService &client_service,
    AMPromptIOManager &prompt_manager)
    : client_service_(client_service), prompt_io_manager_(prompt_manager) {}

std::tuple<ECM, AMDomain::client::ClientHandle, std::string>
FileSystemCliAdapter::ResolveClientPath_(
    const std::string &raw_path, AMDomain::client::amf interrupt_flag) const {
  const std::string token = raw_path.empty() ? "." : raw_path;
  const auto parsed = client_service_.ParseScopedPath(token, interrupt_flag);
  const ECM parse_rcm = std::get<3>(parsed);
  if (!isok(parse_rcm)) {
    return {parse_rcm, nullptr, ""};
  }

  std::string nickname = std::get<0>(parsed);
  std::string path = std::get<1>(parsed);
  AMDomain::client::ClientHandle client = std::get<2>(parsed);
  if (!client) {
    client = nickname.empty() ? client_service_.GetCurrentClient()
                              : client_service_.GetClient(nickname);
  }
  if (!client && nickname.empty()) {
    client = client_service_.GetLocalClient();
  }
  if (!client) {
    return {Err(EC::ClientNotFound, "Resolved client is null"), nullptr, ""};
  }

  if (path.empty()) {
    path = ".";
  }
  const std::string abs_path = client_service_.BuildAbsolutePath(client, path);
  return {Ok(), client, abs_path};
}

/**
 * @brief Check clients by nickname list.
 */
ECM FileSystemCliAdapter::CheckClients(
    const std::vector<std::string> &nicknames, bool detail,
    AMDomain::client::amf interrupt_flag) const {
  const AMDomain::client::amf client_interrupt = interrupt_flag;
  const AMDomain::client::ClientControlComponent control =
      AMDomain::client::MakeClientControlComponent(client_interrupt);
  std::vector<std::string> targets = nicknames;
  if (targets.empty()) {
    targets = client_service_.GetClientNames();
  }
  if (targets.empty()) {
    return Err(EC::ClientNotFound, "No client to check");
  }

  ECM status = Ok();
  for (const auto &name : targets) {
    if (IsInterrupted_(interrupt_flag)) {
      return Err(EC::Terminate, "Interrupted by user");
    }
    const auto check_result =
        client_service_.CheckClient(name, false, detail, control);
    const ECM &rcm = check_result.rcm;
    status = MergeStatus_(status, rcm);
  }
  return status;
}

/**
 * @brief List clients.
 */
ECM FileSystemCliAdapter::ListClients(
    bool detail, AMDomain::client::amf interrupt_flag) const {
  return CheckClients({}, detail, interrupt_flag);
}

/**
 * @brief Disconnect clients by nickname list.
 */
ECM FileSystemCliAdapter::DisconnectClients(
    const std::vector<std::string> &nicknames) const {
  if (nicknames.empty()) {
    return Err(EC::InvalidArg, "No nickname is given");
  }
  ECM status = Ok();
  for (const auto &name : nicknames) {
    status = MergeStatus_(status, client_service_.RemoveClient(name));
  }
  return status;
}

/**
 * @brief Query stat results for one or more paths.
 */
ECM FileSystemCliAdapter::StatPaths(const std::vector<std::string> &paths,
                                    AMDomain::client::amf interrupt_flag,
                                    int timeout_ms) const {
  if (paths.empty()) {
    return Err(EC::InvalidArg, "No path is given");
  }
  const AMDomain::client::amf client_interrupt = interrupt_flag;
  ECM status = Ok();
  for (const auto &raw : paths) {
    if (IsInterrupted_(interrupt_flag)) {
      return Err(EC::Terminate, "Interrupted by user");
    }
    auto [resolve_rcm, client, abs_path] =
        ResolveClientPath_(raw, interrupt_flag);
    if (!isok(resolve_rcm) || !client) {
      status = MergeStatus_(status, resolve_rcm);
      continue;
    }
    auto [rcm, _info] = client->IOPort().stat(abs_path, false, timeout_ms, -1,
                                              client_interrupt);
    status = MergeStatus_(status, rcm);
  }
  return status;
}

/**
 * @brief Query list results for one path.
 */
ECM FileSystemCliAdapter::ListPath(const std::string &path, bool list_like,
                                   bool show_all,
                                   AMDomain::client::amf interrupt_flag,
                                   int timeout_ms) const {
  (void)list_like;
  const AMDomain::client::amf client_interrupt = interrupt_flag;
  auto [resolve_rcm, client, abs_path] =
      ResolveClientPath_(path, interrupt_flag);
  if (!isok(resolve_rcm) || !client) {
    return resolve_rcm;
  }

  auto [stat_rcm, info] =
      client->IOPort().stat(abs_path, false, timeout_ms, -1, client_interrupt);
  if (!isok(stat_rcm)) {
    return stat_rcm;
  }
  if (info.type != PathType::DIR) {
    return Ok();
  }

  auto [list_rcm, entries] =
      client->IOPort().listdir(abs_path, timeout_ms, -1, client_interrupt);
  if (!isok(list_rcm)) {
    return list_rcm;
  }
  if (!show_all) {
    entries.erase(std::remove_if(entries.begin(), entries.end(),
                                 [](const PathInfo &item) {
                                   return item.name == "." || item.name == "..";
                                 }),
                  entries.end());
  }
  return Ok();
}

/**
 * @brief Query size results for one or more paths.
 */
ECM FileSystemCliAdapter::GetSize(const std::vector<std::string> &paths,
                                  AMDomain::client::amf interrupt_flag,
                                  int timeout_ms) const {
  if (paths.empty()) {
    return Err(EC::InvalidArg, "No path is given");
  }
  const AMDomain::client::amf client_interrupt = interrupt_flag;
  ECM status = Ok();
  for (const auto &raw : paths) {
    if (IsInterrupted_(interrupt_flag)) {
      return Err(EC::Terminate, "Interrupted by user");
    }
    auto [resolve_rcm, client, abs_path] =
        ResolveClientPath_(raw, interrupt_flag);
    if (!isok(resolve_rcm) || !client) {
      status = MergeStatus_(status, resolve_rcm);
      continue;
    }
    auto [stat_rcm, _info] = client->IOPort().stat(abs_path, false, timeout_ms,
                                                   -1, client_interrupt);
    if (!isok(stat_rcm)) {
      status = MergeStatus_(status, stat_rcm);
      continue;
    }
    (void)client->IOPort().getsize(abs_path, true, timeout_ms, -1,
                                   client_interrupt);
  }
  return status;
}

/**
 * @brief Query find results for one path.
 */
ECM FileSystemCliAdapter::Find(const std::string &path, SearchType type,
                               AMDomain::client::amf interrupt_flag,
                               int timeout_ms) const {
  const AMDomain::client::amf client_interrupt = interrupt_flag;
  auto [resolve_rcm, client, abs_path] =
      ResolveClientPath_(path, interrupt_flag);
  if (!isok(resolve_rcm) || !client) {
    return resolve_rcm;
  }
  auto [stat_rcm, _info] =
      client->IOPort().stat(abs_path, false, timeout_ms, -1, client_interrupt);
  if (!isok(stat_rcm)) {
    return stat_rcm;
  }
  (void)client->IOPort().find(abs_path, type, timeout_ms, -1, client_interrupt);
  return Ok();
}

/**
 * @brief Create directories for one or more paths.
 */
ECM FileSystemCliAdapter::Mkdir(const std::vector<std::string> &paths,
                                AMDomain::client::amf interrupt_flag,
                                int timeout_ms) const {
  if (paths.empty()) {
    return Err(EC::InvalidArg, "No path is given");
  }
  const AMDomain::client::amf client_interrupt = interrupt_flag;
  ECM status = Ok();
  for (const auto &raw : paths) {
    if (IsInterrupted_(interrupt_flag)) {
      return Err(EC::Terminate, "Interrupted by user");
    }
    auto [resolve_rcm, client, abs_path] =
        ResolveClientPath_(raw, interrupt_flag);
    if (!isok(resolve_rcm) || !client) {
      status = MergeStatus_(status, resolve_rcm);
      continue;
    }
    status =
        MergeStatus_(status, client->IOPort().mkdirs(abs_path, timeout_ms, -1,
                                                     client_interrupt));
  }
  return status;
}

/**
 * @brief Remove paths with interface-owned confirmation behavior.
 */
ECM FileSystemCliAdapter::Remove(const std::vector<std::string> &paths,
                                 bool permanent, bool quiet,
                                 AMDomain::client::amf interrupt_flag,
                                 int timeout_ms) const {
  if (paths.empty()) {
    return Err(EC::InvalidArg, "No path is given");
  }
  const AMDomain::client::amf client_interrupt = interrupt_flag;
  if (!quiet) {
    bool canceled = false;
    const bool confirmed = prompt_io_manager_.PromptYesNo(
        AMStr::fmt("Remove {} path(s)? (y/N): ", paths.size()), &canceled);
    if (canceled || !confirmed) {
      return Err(EC::ConfigCanceled, "remove canceled");
    }
  }

  ECM status = Ok();
  for (const auto &raw : paths) {
    if (IsInterrupted_(interrupt_flag)) {
      return Err(EC::Terminate, "Interrupted by user");
    }
    auto [resolve_rcm, client, abs_path] =
        ResolveClientPath_(raw, interrupt_flag);
    if (!isok(resolve_rcm) || !client) {
      status = MergeStatus_(status, resolve_rcm);
      continue;
    }
    if (permanent) {
      auto [rcm, _errors] = client->IOPort().remove(
          abs_path, nullptr, timeout_ms, -1, client_interrupt);
      status = MergeStatus_(status, rcm);
      continue;
    }
    status =
        MergeStatus_(status, client->IOPort().saferm(abs_path, timeout_ms, -1,
                                                     client_interrupt));
  }
  return status;
}

/**
 * @brief Query walk results.
 */
ECM FileSystemCliAdapter::Walk(const std::string &path, bool only_file,
                               bool only_dir, bool show_all,
                               bool ignore_special_file, bool quiet,
                               AMDomain::client::amf interrupt_flag,
                               int timeout_ms) const {
  (void)quiet;
  const AMDomain::client::amf client_interrupt = interrupt_flag;
  auto [resolve_rcm, client, abs_path] =
      ResolveClientPath_(path, interrupt_flag);
  if (!isok(resolve_rcm) || !client) {
    return resolve_rcm;
  }
  auto [walk_rcm, walk_payload] =
      client->IOPort().iwalk(abs_path, show_all, ignore_special_file, nullptr,
                             timeout_ms, -1, client_interrupt);
  ECM status = walk_rcm;
  for (const auto &info : walk_payload.first) {
    if (only_file && info.type != PathType::FILE) {
      continue;
    }
    if (only_dir && info.type != PathType::DIR) {
      continue;
    }
  }
  for (const auto &err : walk_payload.second) {
    status = MergeStatus_(status, err.second);
  }
  return status;
}

/**
 * @brief Query tree results.
 */
ECM FileSystemCliAdapter::Tree(const std::string &path, int max_depth,
                               bool only_dir, bool show_all,
                               bool ignore_special_file, bool quiet,
                               AMDomain::client::amf interrupt_flag,
                               int timeout_ms) const {
  const AMDomain::client::amf client_interrupt = interrupt_flag;
  auto [resolve_rcm, client, abs_path] =
      ResolveClientPath_(path, interrupt_flag);
  if (!isok(resolve_rcm) || !client) {
    return resolve_rcm;
  }
  auto [walk_rcm, walk_payload] =
      client->IOPort().iwalk(abs_path, show_all, ignore_special_file, nullptr,
                             timeout_ms, -1, client_interrupt);
  std::vector<PathInfo> items = walk_payload.first;
  std::sort(items.begin(), items.end(),
            [](const PathInfo &lhs, const PathInfo &rhs) {
              return lhs.path < rhs.path;
            });

  ECM status = walk_rcm;
  for (const auto &err : walk_payload.second) {
    status = MergeStatus_(status, err.second);
  }

  if (quiet) {
    return status;
  }

  const std::string root = abs_path.empty() ? "." : abs_path;
  prompt_io_manager_.Print(root);
  for (const auto &item : items) {
    if (only_dir && item.type != PathType::DIR) {
      continue;
    }
    const size_t depth = RelativeDepth_(root, item.path);
    if (max_depth >= 0 && static_cast<int>(depth) > max_depth) {
      continue;
    }
    prompt_io_manager_.Print(std::string(depth * 2, ' ') + item.name);
  }
  return status;
}

/**
 * @brief Query realpath result.
 */
ECM FileSystemCliAdapter::Realpath(const std::string &path,
                                   AMDomain::client::amf interrupt_flag,
                                   int timeout_ms) const {
  const AMDomain::client::amf client_interrupt = interrupt_flag;
  auto [resolve_rcm, client, abs_path] =
      ResolveClientPath_(path, interrupt_flag);
  if (!isok(resolve_rcm) || !client) {
    return resolve_rcm;
  }
  auto [rcm, _real] =
      client->IOPort().realpath(abs_path, timeout_ms, -1, client_interrupt);
  return rcm;
}

/**
 * @brief Measure RTT for current client.
 */
ECM FileSystemCliAdapter::TestRtt(int times,
                                  AMDomain::client::amf interrupt_flag) const {
  if (IsInterrupted_(interrupt_flag)) {
    return Err(EC::Terminate, "Interrupted by user");
  }
  auto client = client_service_.GetCurrentClient();
  if (!client) {
    return Err(EC::ClientNotFound, "Current client not initialized");
  }
  const double rtt = client->IOPort().GetRTT(times);
  std::ostringstream oss;
  oss << std::fixed << std::setprecision(2) << rtt;
  prompt_io_manager_.FmtPrint("RTT: {} ms", oss.str());
  return Ok();
}

/**
 * @brief Change current workdir.
 */
ECM FileSystemCliAdapter::Cd(const std::string &path,
                             AMDomain::client::amf interrupt_flag,
                             bool from_history) const {
  (void)from_history;
  const AMDomain::client::amf client_interrupt = interrupt_flag;
  const std::string token = path.empty() ? "." : path;
  const auto parsed = client_service_.ParseScopedPath(token, client_interrupt);
  ECM parse_rcm = std::get<3>(parsed);
  if (!isok(parse_rcm)) {
    return parse_rcm;
  }

  std::string nickname = std::get<0>(parsed);
  std::string resolved = std::get<1>(parsed);
  AMDomain::client::ClientHandle client = std::get<2>(parsed);
  if (!client) {
    client = nickname.empty() ? client_service_.GetCurrentClient()
                              : client_service_.GetClient(nickname);
  }
  if (!client && nickname.empty()) {
    client = client_service_.GetLocalClient();
  }
  if (!client) {
    return Err(EC::ClientNotFound, "Resolved client is null");
  }

  if (resolved.empty()) {
    resolved = ".";
  }
  const std::string abs_path =
      client_service_.BuildAbsolutePath(client, resolved);
  auto [stat_rcm, stat_info] =
      client->IOPort().stat(abs_path, false, -1, -1, client_interrupt);
  if (!isok(stat_rcm)) {
    return stat_rcm;
  }
  if (stat_info.type != PathType::DIR) {
    return Err(EC::NotADirectory, "Target is not a directory");
  }

  const std::string key =
      nickname.empty() ? client->ConfigPort().GetNickname() : nickname;
  auto state = client_service_.GetWorkdirState(key);
  state.cwd = abs_path;
  ECM set_rcm = client_service_.SetWorkdirState(key, state);
  if (!isok(set_rcm)) {
    return set_rcm;
  }
  client_service_.SetCurrentClient(client);
  return Ok();
}

/**
 * @brief Execute one shell command and return output + code.
 */
std::pair<ECM, std::pair<std::string, int>>
FileSystemCliAdapter::ShellRun(const std::string &cmd, int max_time_ms,
                               AMDomain::client::amf interrupt_flag) const {
  const AMDomain::client::amf client_interrupt = interrupt_flag;
  if (IsInterrupted_(interrupt_flag)) {
    return {Err(EC::Terminate, "Interrupted by user"), {"", -1}};
  }
  auto client = client_service_.GetCurrentClient();
  if (!client) {
    return {Err(EC::ClientNotFound, "Current client not found"), {"", -1}};
  }
  return client->IOPort().ConductCmd(cmd, max_time_ms, client_interrupt);
}
} // namespace AMInterface::filesystem
