#include "interface/adapters/config/ConfigInterfaceService.hpp"

#include "domain/host/HostDomainService.hpp"
#include "foundation/tools/string.hpp"
#include <algorithm>
#include <array>
#include <filesystem>
#include <unordered_set>
#include <utility>
#include <vector>

namespace AMInterface::config {
namespace {
using DocumentKind = AMDomain::config::DocumentKind;
using AMDomain::host::HostService::IsLocalNickname;
using AMDomain::host::HostService::NormalizeNickname;
using AMDomain::host::HostService::ValidateNickname;

std::string NormalizeProfileNickname_(const std::string &nickname) {
  const std::string stripped = AMStr::Strip(nickname);
  if (stripped.empty()) {
    return "";
  }
  std::string normalized = NormalizeNickname(stripped);
  if (IsLocalNickname(normalized)) {
    normalized = AMDomain::host::klocalname;
  }
  return normalized;
}

std::string DisplayPath_(const std::filesystem::path &path) {
  std::filesystem::path display = path;
  display.make_preferred();
  return display.string();
}

std::string AbsoluteDisplayPath_(const std::filesystem::path &path) {
  if (path.empty()) {
    return "";
  }
  std::error_code ec;
  const std::filesystem::path abs_path = std::filesystem::absolute(path, ec);
  if (ec) {
    return DisplayPath_(path.lexically_normal());
  }
  return DisplayPath_(abs_path.lexically_normal());
}

std::string DefaultFileNameForKind_(DocumentKind kind) {
  switch (kind) {
  case DocumentKind::Config:
    return "config.toml";
  case DocumentKind::Settings:
    return "settings.toml";
  case DocumentKind::KnownHosts:
    return "known_hosts.toml";
  case DocumentKind::History:
    return "history.toml";
  default:
    return "config.toml";
  }
}

std::filesystem::path ResolveExportFileName_(
    AMApplication::config::ConfigAppService &config_service, DocumentKind kind) {
  std::filesystem::path src_path = {};
  if (config_service.GetDataPath(kind, &src_path) && !src_path.empty() &&
      src_path.has_filename()) {
    return src_path.filename();
  }
  return std::filesystem::path(DefaultFileNameForKind_(kind));
}
} // namespace

ConfigInterfaceService::ConfigInterfaceService(
    AMApplication::config::ConfigAppService &config_service,
    AMApplication::host::HostAppService &host_service,
    AMInterface::prompt::AMPromptIOManager &prompt_io_manager)
    : config_service_(config_service), host_service_(host_service),
      prompt_io_manager_(prompt_io_manager) {}

ECM ConfigInterfaceService::PrintPaths() const {
  const std::filesystem::path project_dir = config_service_.ProjectRoot();
  const std::string project_display = AbsoluteDisplayPath_(project_dir);
  std::vector<std::pair<std::string, std::string>> rows = {
      {"\\[ProjectDir]", project_display.empty() ? "<empty>" : project_display}};

  const std::array<std::pair<DocumentKind, std::string>, 4> docs = {
      std::pair{DocumentKind::Config, "\\[Config]"},
      std::pair{DocumentKind::Settings, "\\[Settings]"},
      std::pair{DocumentKind::KnownHosts, "\\[KnownHosts]"},
      std::pair{DocumentKind::History, "\\[History]"},
  };

  for (const auto &[kind, label] : docs) {
    std::filesystem::path data_path = {};
    if (!config_service_.GetDataPath(kind, &data_path)) {
      rows.emplace_back(label, "<unavailable>");
      continue;
    }
    const std::string display = AbsoluteDisplayPath_(data_path);
    rows.emplace_back(label, display.empty() ? "<empty>" : display);
  }

  size_t label_width = 0;
  for (const auto &row : rows) {
    label_width = std::max(label_width, row.first.size());
  }

  for (const auto &row : rows) {
    prompt_io_manager_.FmtPrint(
        "{}   {}", AMStr::PadRightAscii(row.first, label_width), row.second);
  }
  return OK;
}

ECM ConfigInterfaceService::SaveAll() const {
  prompt_io_manager_.SyncCurrentHistory();
  ECM rcm = config_service_.FlushDirtyParticipants();
  if (!(rcm)) {
    return rcm;
  }
  return config_service_.DumpAll(false);
}

ECM ConfigInterfaceService::BackupAll() const {
  prompt_io_manager_.SyncCurrentHistory();
  ECM rcm = config_service_.FlushDirtyParticipants();
  if (!(rcm)) {
    return rcm;
  }

  const auto backup_rcms =
      config_service_.Backup({DocumentKind::Config, DocumentKind::Settings,
                              DocumentKind::KnownHosts, DocumentKind::History});
  ECM first_error = OK;
  for (const ECM &item : backup_rcms) {
    if (!(item) && (first_error)) {
      first_error = item;
    }
  }
  return first_error;
}

ECM ConfigInterfaceService::Export(const std::string &path) const {
  const std::string raw_dir = AMStr::Strip(path);
  if (raw_dir.empty()) {
    return Err(EC::InvalidArg, "config export", "<path>", "path is empty");
  }
  if (raw_dir.find('@') != std::string::npos) {
    return Err(EC::InvalidArg, "config export", raw_dir,
               "path must be a local directory");
  }

  const std::filesystem::path export_dir =
      std::filesystem::path(raw_dir).lexically_normal();
  std::error_code ec = {};
  if (std::filesystem::exists(export_dir, ec) &&
      !std::filesystem::is_directory(export_dir, ec)) {
    return Err(EC::InvalidArg, "config export", DisplayPath_(export_dir),
               "path exists but is not a directory");
  }

  prompt_io_manager_.SyncCurrentHistory();
  ECM rcm = config_service_.FlushDirtyParticipants();
  if (!(rcm)) {
    return rcm;
  }
  rcm = config_service_.EnsureDirectory(export_dir);
  if (!(rcm)) {
    return rcm;
  }

  const std::array<DocumentKind, 4> docs = {
      DocumentKind::Config,
      DocumentKind::Settings,
      DocumentKind::KnownHosts,
      DocumentKind::History,
  };

  ECM first_error = OK;
  for (DocumentKind kind : docs) {
    const std::filesystem::path dst_path =
        export_dir / ResolveExportFileName_(config_service_, kind);
    const ECM dump_rcm = config_service_.Dump(kind, dst_path.string(), false);
    if (!(dump_rcm) && (first_error)) {
      first_error = dump_rcm;
    }
  }
  return first_error;
}

ECM ConfigInterfaceService::EditProfile(const std::string &nickname) const {
  const std::string stripped = AMStr::Strip(nickname);
  if (stripped.empty()) {
    return Err(EC::InvalidArg, "profile edit", "",
               "empty profile nickname");
  }
  if (!ValidateNickname(stripped)) {
    return Err(EC::InvalidArg, "profile edit", stripped,
               "invalid profile nickname literal");
  }
  const std::string target = NormalizeProfileNickname_(stripped);
  if (target == AMDomain::prompt::kPromptProfileDefault) {
    return Err(EC::InvalidArg, "profile edit", target,
               "profile nickname must be a host nickname");
  }
  const auto host_query = host_service_.GetClientConfig(target, true);
  if (!(host_query)) {
    return Err(EC::HostConfigNotFound, "profile edit", target,
               AMStr::fmt("host nickname not found: {}", target));
  }
  return prompt_io_manager_.Edit(target);
}

ECM ConfigInterfaceService::GetProfile(
    const std::vector<std::string> &nicknames) const {
  if (nicknames.empty()) {
    return Err(EC::InvalidArg, "profile get", "",
               "profile get requires at least one nickname");
  }

  std::vector<std::string> targets = {};
  std::unordered_set<std::string> seen = {};
  targets.reserve(nicknames.size());
  for (const auto &name : nicknames) {
    const std::string stripped = AMStr::Strip(name);
    if (stripped.empty()) {
      return Err(EC::InvalidArg, "profile get", "",
                 "empty profile nickname");
    }
    if (!ValidateNickname(stripped)) {
      return Err(EC::InvalidArg, "profile get", stripped,
                 "invalid profile nickname literal");
    }
    const std::string target = NormalizeProfileNickname_(stripped);
    if (target == AMDomain::prompt::kPromptProfileDefault) {
      return Err(EC::InvalidArg, "profile get", target,
                 "profile nickname must be a host nickname");
    }
    const auto host_query = host_service_.GetClientConfig(target, true);
    if (!(host_query)) {
      return Err(EC::HostConfigNotFound, "profile get", target,
                 AMStr::fmt("host nickname not found: {}", target));
    }
    if (seen.insert(target).second) {
      targets.push_back(target);
    }
  }
  return prompt_io_manager_.Get(targets);
}

} // namespace AMInterface::config
