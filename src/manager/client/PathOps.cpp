#include "AMManager/Client.hpp"

namespace AMClientManage {

PathOps::PathOps(AMConfigManager &config) : Operator(config) {}

std::tuple<std::string, std::string, std::shared_ptr<BaseClient>, ECM>
PathOps::ParsePath(const std::string &input) {
  if (!input.empty() && input.front() == '@') {
    std::string path = input.substr(1);
    return {"local", path, LocalClientBase(), ECM{EC::Success, ""}};
  }

  auto pos = input.find('@');
  if (pos == std::string::npos || pos + 1 >= input.size()) {
    std::shared_ptr<BaseClient> current = manager_ref_.CurrentClient()
                                              ? manager_ref_.CurrentClient()
                                              : manager_ref_.LocalClientBase();
    std::string nickname = current ? current->GetNickname() : "local";
    return {nickname, input, current, ECM{EC::Success, ""}};
  }

  std::string prefix = input.substr(0, pos);
  std::string path = input.substr(pos + 1);
  std::string lowered = AMStr::lowercase(prefix);
  if (prefix.empty() || lowered == "local") {
    return {"local", path, manager_ref_.LocalClientBase(),
            ECM{EC::Success, ""}};
  }

  auto cfg = manager_ref_.GetClientConfig(prefix);
  if (cfg.first.first != EC::Success) {
    const std::string styled = manager_ref_.config_.Format(prefix, "nickname");
    return {prefix, path, nullptr,
            ECM{EC::HostConfigNotFound,
                AMStr::amfmt("Host config not found: {}", styled)}};
  }

  auto existing = manager_ref_.Clients().GetHost(prefix);
  if (!existing) {
    const std::string styled = manager_ref_.config_.Format(prefix, "nickname");
    return {prefix, path, nullptr,
            ECM{EC::ClientNotFound,
                AMStr::amfmt("Client not created: {}", styled)}};
  }
  return {prefix, path, existing, ECM{EC::Success, ""}};
}

std::tuple<std::string, std::string, std::shared_ptr<BaseClient>, ECM>
PathOps::ParsePath(const std::string &input, amf interrupt_flag) {
  if (!input.empty() && input.front() == '@') {
    std::string path = input.substr(1);
    return {"local", path, manager_ref_.LocalClientBase(),
            ECM{EC::Success, ""}};
  }

  auto pos = input.find('@');
  if (pos == std::string::npos || pos + 1 >= input.size()) {
    std::shared_ptr<BaseClient> current = manager_ref_.CurrentClient()
                                              ? manager_ref_.CurrentClient()
                                              : manager_ref_.LocalClientBase();
    std::string nickname = current ? current->GetNickname() : "local";
    return {nickname, input, current, ECM{EC::Success, ""}};
  }

  std::string prefix = input.substr(0, pos);
  std::string path = input.substr(pos + 1);
  std::string lowered = AMStr::lowercase(prefix);
  if (prefix.empty() || lowered == "local") {
    return {"local", path, manager_ref_.LocalClientBase(),
            ECM{EC::Success, ""}};
  }

  auto cfg = manager_ref_.GetClientConfig(prefix);
  if (cfg.first.first != EC::Success) {
    const std::string styled = manager_ref_.config_.Format(prefix, "nickname");
    return {prefix, path, nullptr,
            ECM{EC::HostConfigNotFound,
                AMStr::amfmt("Host config not found: {}", styled)}};
  }

  auto existing = manager_ref_.Clients().GetHost(prefix);
  if (!existing) {
    if (AMIsInteractive.load(std::memory_order_relaxed)) {
      bool canceled = false;
      if (!AMPromptManager::Instance().PromptYesNo(
              "Client not found. Create it? (y/N): ", &canceled)) {
        return {prefix, path, nullptr,
                ECM{EC::Terminate, AMStr::amfmt("🚫  Aborted creating: {}",
                                                manager_ref_.config_.Format(
                                                    prefix, "nickname"))}};
      }
    }
    auto created = manager_ref_.AddClient(prefix, nullptr, false, false, {},
                                          interrupt_flag);
    if (created.first.first != EC::Success) {
      return {prefix, path, created.second, created.first};
    }
    return {prefix, path, created.second, ECM{EC::Success, ""}};
  }
  return {prefix, path, existing, ECM{EC::Success, ""}};
}

std::string PathOps::AbsPath(const std::string &path,
                             const std::shared_ptr<BaseClient> &client) const {
  if (!client) {
    return path;
  }
  if (path.empty()) {
    return GetOrInitWorkdir(client);
  }
  std::string cwd = GetOrInitWorkdir(client);
  std::string home = client->GetHomeDir();
  return AMFS::abspath(path, true, home, cwd, "/");
}

std::string
PathOps::GetOrInitWorkdir(const std::shared_ptr<BaseClient> &client) const {
  if (!client) {
    return "";
  }
  std::string workdir;
  if (client->GetPublicValue("workdir", &workdir)) {
    workdir = AMPathStr::UnifyPathSep(workdir, "/");
    if (workdir.empty()) {
      workdir = AMPathStr::UnifyPathSep(client->GetHomeDir(), "/");
      (void)client->SetPulbicValue("workdir", workdir, true);
      return workdir;
    }
    if (!workdir.empty() && !AMPathStr::IsAbs(workdir, "/")) {
      const std::string home =
          AMPathStr::UnifyPathSep(client->GetHomeDir(), "/");
      workdir = AMFS::abspath(workdir, true, home, home, "/");
      (void)client->SetPulbicValue("workdir", workdir, true);
    }
    return workdir;
  }

  std::string home = AMPathStr::UnifyPathSep(client->GetHomeDir(), "/");
  (void)client->SetPulbicValue("workdir", home, true);
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
  (void)client->SetPulbicValue("workdir", normalized, true);
}

std::string PathOps::BuildPath(const std::shared_ptr<BaseClient> &client,
                               const std::string &path) const {
  if (!client) {
    return path;
  }
  if (path.empty()) {
    return GetOrInitWorkdir(client);
  }
  std::string cwd = GetOrInitWorkdir(client);
  std::string home = client->GetHomeDir();
  return AMFS::abspath(path, true, home, cwd, "/");
}

void PathOps::InitClientWorkdir(
    const std::shared_ptr<BaseClient> &client) const {
  if (!client) {
    return;
  }
  std::string value;
  if (client->GetPublicValue("workdir", &value)) {
    return;
  }
  (void)client->SetPulbicValue(
      "workdir", AMPathStr::UnifyPathSep(client->GetHomeDir(), "/"), true);
}

void PathOps::ApplyLoginDir(const std::string &nickname,
                            const std::shared_ptr<BaseClient> &client,
                            const std::string &login_dir,
                            const amf &flag) const {
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
  (void)client->SetPulbicValue("workdir", normalized, true);
  (void)client->SetPulbicValue("login_dir", normalized, true);

  if (need_persist) {
    (void)manager_ref_.config_.SetHostField(nickname, "login_dir", resolved,
                                            true);
  }
}

} // namespace AMClientManage
