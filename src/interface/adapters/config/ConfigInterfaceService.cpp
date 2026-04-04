#include "interface/adapters/config/ConfigInterfaceService.hpp"

#include "foundation/tools/string.hpp"
#include <algorithm>
#include <array>
#include <filesystem>
#include <utility>
#include <vector>

namespace AMInterface::config {
namespace {
using DocumentKind = AMDomain::config::DocumentKind;

std::string DisplayPath_(const std::filesystem::path &path) {
  std::filesystem::path display = path;
  display.make_preferred();
  return display.string();
}

std::string RelativeDisplayPath_(const std::filesystem::path &path,
                                 const std::filesystem::path &project_dir) {
  if (path.empty()) {
    return "";
  }
  if (project_dir.empty()) {
    return DisplayPath_(path.lexically_normal());
  }

  std::error_code ec;
  const auto relative = std::filesystem::relative(path, project_dir, ec);
  if (!ec && !relative.empty()) {
    const auto it = relative.begin();
    if (it == relative.end() || *it != "..") {
      return DisplayPath_(relative.lexically_normal());
    }
  }
  return DisplayPath_(path.lexically_normal());
}
} // namespace

ConfigInterfaceService::ConfigInterfaceService(
    AMApplication::config::ConfigAppService &config_service,
    AMInterface::prompt::AMPromptIOManager &prompt_io_manager)
    : config_service_(config_service), prompt_io_manager_(prompt_io_manager) {}

ECM ConfigInterfaceService::PrintPaths() const {
  const std::filesystem::path project_dir = config_service_.ProjectRoot();
  const std::string project_display = RelativeDisplayPath_(project_dir, {});
  std::vector<std::pair<std::string, std::string>> rows = {
      {"[ProjectDir]", project_display.empty() ? "<empty>" : project_display}};

  const std::array<std::pair<DocumentKind, std::string>, 4> docs = {
      std::pair{DocumentKind::Config, "[Config]"},
      std::pair{DocumentKind::Settings, "[Settings]"},
      std::pair{DocumentKind::KnownHosts, "[KnownHosts]"},
      std::pair{DocumentKind::History, "[History]"},
  };

  for (const auto &[kind, label] : docs) {
    std::filesystem::path data_path = {};
    if (!config_service_.GetDataPath(kind, &data_path)) {
      rows.push_back({label, "<unavailable>"});
      continue;
    }
    const std::string display = RelativeDisplayPath_(data_path, project_dir);
    rows.push_back({label, display.empty() ? "<empty>" : display});
  }

  size_t label_width = 0;
  for (const auto &row : rows) {
    label_width = std::max(label_width, row.first.size());
  }

  for (const auto &row : rows) {
    prompt_io_manager_.FmtPrint("{} {}", AMStr::PadRightAscii(row.first, label_width),
                                row.second);
  }
  return OK;
}

ECM ConfigInterfaceService::SaveAll() const {
  ECM rcm = config_service_.FlushDirtyParticipants();
  if (!(rcm)) {
    return rcm;
  }
  return config_service_.DumpAll(false);
}

ECM ConfigInterfaceService::BackupAll() const {
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

} // namespace AMInterface::config
