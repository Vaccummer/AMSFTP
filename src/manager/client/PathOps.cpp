#include "AMManager/Client.hpp"
#include <filesystem>

namespace AMClientManage {
namespace {
inline bool IsLocalNickname_(const std::string &nickname) {
  const std::string lowered = AMStr::lowercase(AMStr::Strip(nickname));
  return lowered.empty() || lowered == "local";
}
} // namespace

std::tuple<std::string, std::string, std::shared_ptr<BaseClient>, ECM>
PathOps::ParsePath(const std::string &input) {
  if (!input.empty() && input.front() == '@') {
    return {"local", input.substr(1), LocalClient(), Ok()};
  }

  const auto pos = input.find('@');
  if (pos == std::string::npos || pos + 1 >= input.size()) {
    std::shared_ptr<BaseClient> current = CurrentClient();
    const std::string nickname = current ? current->GetNickname() : "local";
    return {nickname, input, current, Ok()};
  }

  const std::string prefix = input.substr(0, pos);
  const std::string path = input.substr(pos + 1);
  if (IsLocalNickname_(prefix)) {
    return {"local", path, LocalClient(), Ok()};
  }

  auto cfg = hostm_.GetClientConfig(prefix);
  if (cfg.first.first != EC::Success) {
    return {prefix, path, nullptr,
            Err(EC::HostConfigNotFound,
                AMStr::fmt("Host config not found: {}", prefix))};
  }

  auto existing = Clients().GetHost(prefix);
  if (!existing) {
    return {prefix, path, nullptr,
            Err(EC::ClientNotFound,
                AMStr::fmt("Client not created: {}", prefix))};
  }
  return {prefix, path, existing, Ok()};
}

std::tuple<std::string, std::string, std::shared_ptr<BaseClient>, ECM>
PathOps::ParsePath(const std::string &input, amf interrupt_flag) {
  if (!input.empty() && input.front() == '@') {
    return {"local", input.substr(1), LocalClient(), Ok()};
  }

  const auto pos = input.find('@');
  if (pos == std::string::npos || pos + 1 >= input.size()) {
    std::shared_ptr<BaseClient> current = CurrentClient();
    const std::string nickname = current ? current->GetNickname() : "local";
    return {nickname, input, current, Ok()};
  }

  const std::string prefix = input.substr(0, pos);
  const std::string path = input.substr(pos + 1);
  if (IsLocalNickname_(prefix)) {
    return {"local", path, LocalClient(), Ok()};
  }

  auto cfg = hostm_.GetClientConfig(prefix);
  if (cfg.first.first != EC::Success) {
    return {prefix, path, nullptr,
            Err(EC::HostConfigNotFound,
                AMStr::fmt("Host config not found: {}", prefix))};
  }

  auto existing = Clients().GetHost(prefix);
  if (!existing) {
    if (AMIsInteractive.load(std::memory_order_relaxed)) {
      bool canceled = false;
      if (!prompt_.PromptYesNo("Client not found. Create it? (y/N): ",
                               &canceled)) {
        return {prefix, path, nullptr,
                Err(EC::Terminate,
                    AMStr::fmt("Aborted creating client: {}", prefix))};
      }
    }
    auto created = AddClient(prefix, nullptr, false, false, {}, interrupt_flag);
    if (created.first.first != EC::Success) {
      return {prefix, path, created.second, created.first};
    }
    return {prefix, path, created.second, Ok()};
  }
  return {prefix, path, existing, Ok()};
}

std::string PathOps::AbsPath(const std::string &path,
                             const std::shared_ptr<BaseClient> &client) const {
  if (!client) {
    return path;
  }
  if (path.empty()) {
    return GetOrInitWorkdir(client);
  }
  const std::string cwd = GetOrInitWorkdir(client);
  const std::string home = client->GetHomeDir();
  return AMFS::abspath(path, true, home, cwd, "/");
}

std::string
PathOps::GetOrInitWorkdir(const std::shared_ptr<BaseClient> &client) const {
  if (!client) {
    return "";
  }
  std::string workdir = AMPathStr::UnifyPathSep(client->GetCwd(), "/");
  if (!workdir.empty()) {
    if (!AMPathStr::IsAbs(workdir, "/")) {
      const std::string home =
          AMPathStr::UnifyPathSep(client->GetHomeDir(), "/");
      workdir = AMFS::abspath(workdir, true, home, home, "/");
      client->SetCwd(workdir);
    }
    return workdir;
  }

  std::string login_dir = AMPathStr::UnifyPathSep(client->GetLoginDir(), "/");
  if (!login_dir.empty()) {
    if (!AMPathStr::IsAbs(login_dir, "/")) {
      const std::string home =
          AMPathStr::UnifyPathSep(client->GetHomeDir(), "/");
      login_dir = AMFS::abspath(login_dir, true, home, home, "/");
    }
    client->SetCwd(login_dir);
    return login_dir;
  }

  const std::string home = AMPathStr::UnifyPathSep(client->GetHomeDir(), "/");
  client->SetCwd(home);
  return home;
}

void PathOps::SetClientWorkdir(const std::shared_ptr<BaseClient> &client,
                               const std::string &path) const {
  if (!client) {
    return;
  }
  std::string normalized = AMPathStr::UnifyPathSep(path, "/");
  if (normalized.empty()) {
    normalized = AMPathStr::UnifyPathSep(client->GetHomeDir(), "/");
  }
  if (!normalized.empty() && !AMPathStr::IsAbs(normalized, "/")) {
    const std::string base = GetOrInitWorkdir(client);
    const std::string home = AMPathStr::UnifyPathSep(client->GetHomeDir(), "/");
    normalized = AMFS::abspath(normalized, true, home, base, "/");
  }
  client->SetCwd(normalized);
}

std::string PathOps::BuildPath(const std::shared_ptr<BaseClient> &client,
                               const std::string &path) const {
  if (!client) {
    return path;
  }
  if (path.empty()) {
    return GetOrInitWorkdir(client);
  }
  const std::string cwd = GetOrInitWorkdir(client);
  const std::string home = client->GetHomeDir();
  return AMFS::abspath(path, true, home, cwd, "/");
}

void PathOps::InitClientWorkdir(
    const std::shared_ptr<BaseClient> &client) const {
  if (!client) {
    return;
  }
  const std::string value = AMPathStr::UnifyPathSep(client->GetCwd(), "/");
  if (!value.empty()) {
    return;
  }
  const std::string home = AMPathStr::UnifyPathSep(client->GetHomeDir(), "/");
  client->SetCwd(home);
}

void PathOps::ApplyLoginDir(const std::string &nickname,
                            const std::shared_ptr<BaseClient> &client,
                            const std::string &login_dir,
                            amf flag) const {
  if (!client) {
    return;
  }

  std::string resolved = login_dir;
  bool need_persist = false;
  if (resolved.empty()) {
    resolved = client->GetHomeDir();
    need_persist = true;
  } else {
    bool exists = false;
    if (client->GetProtocol() == ClientProtocol::LOCAL) {
      std::error_code ec;
      exists = std::filesystem::exists(resolved, ec);
    } else {
      auto [rcm, info] = client->stat(resolved, false, flag);
      exists = rcm.first == EC::Success && info.type == PathType::DIR;
    }
    if (!exists) {
      resolved = client->GetHomeDir();
      need_persist = true;
    }
  }

  const std::string normalized = AMPathStr::UnifyPathSep(resolved, "/");
  client->SetCwd(normalized);
  client->SetLoginDir(normalized);

  if (need_persist && !IsLocalNickname_(nickname)) {
    (void)hostm_.SetHostValue(nickname, configkn::login_dir, resolved);
  }
}

} // namespace AMClientManage
