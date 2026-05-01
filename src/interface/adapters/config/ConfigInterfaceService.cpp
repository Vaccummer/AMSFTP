#include "interface/adapters/config/ConfigInterfaceService.hpp"
#include "domain/config/ConfigSchema.hpp"
#include "domain/host/HostDomainService.hpp"
#include "foundation/tools/path.hpp"
#include "foundation/tools/string.hpp"

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <initializer_list>
#include <unordered_set>
#include <utility>
#include <vector>

namespace AMInterface::config {
namespace {
using DocumentKind = AMDomain::config::DocumentKind;
using ConfigDocumentState = AMApplication::config::ConfigDocumentState;
using AMDomain::host::HostService::IsLocalNickname;
using AMDomain::host::HostService::NormalizeNickname;
using AMDomain::host::HostService::ValidateNickname;

std::string AbsoluteDisplayPath_(const std::filesystem::path &path) {
  if (path.empty()) {
    return "";
  }
  std::error_code ec;
  const std::filesystem::path abs_path = std::filesystem::absolute(path, ec);
  if (ec) {
    return path.lexically_normal().string();
  }
  return abs_path.lexically_normal().string();
}

std::string DefaultFileNameForKind_(DocumentKind kind) {
  switch (kind) {
  case DocumentKind::Config:
    return "config.toml";
  case DocumentKind::Settings:
    return "settings.toml";
  case DocumentKind::KnownHosts:
    return "known_hosts.toml";
  default:
    return "config.toml";
  }
}

std::filesystem::path
ResolveExportFileName_(AMApplication::config::ConfigAppService &config_service,
                       DocumentKind kind) {
  std::filesystem::path src_path = {};
  if (config_service.GetDataPath(kind, &src_path) && !src_path.empty() &&
      src_path.has_filename()) {
    return src_path.filename();
  }
  return DefaultFileNameForKind_(kind);
}

struct TemplateVarInfo_ {
  const char *name = "";
  const char *type = "";
  const char *description = "";
};

std::string DataPathForKind_(
    const AMApplication::config::ConfigAppService &config_service,
    DocumentKind kind) {
  std::filesystem::path data_path = {};
  if (config_service.GetDataPath(kind, &data_path)) {
    return AbsoluteDisplayPath_(data_path);
  }
  return AbsoluteDisplayPath_(config_service.ProjectRoot() /
                              DefaultFileNameForKind_(kind));
}

void PrintTemplateInfoBlock_(
    AMInterface::prompt::PromptIOManager &prompt,
    const std::string &name,
    const std::string &purpose,
    const std::string &file_path,
    const std::string &key,
    const std::string &engine,
    std::initializer_list<TemplateVarInfo_> variables,
    std::initializer_list<const char *> notes = {}) {
  prompt.FmtPrint("Template: {}", name);
  prompt.FmtPrint("Purpose : {}", purpose);
  prompt.FmtPrint("File    : {}", file_path);
  prompt.FmtPrint("Key     : {}", key);
  prompt.FmtPrint("Engine  : {}", engine);
  if (notes.size() > 0U) {
    prompt.Print("Notes   :");
    for (const char *note : notes) {
      prompt.FmtPrint("  - {}", note);
    }
  }
  prompt.Print("Variables:");
  size_t name_width = 0U;
  size_t type_width = 0U;
  for (const auto &var : variables) {
    name_width = std::max(name_width, std::string(var.name).size());
    type_width = std::max(type_width, std::string(var.type).size());
  }
  for (const auto &var : variables) {
    prompt.FmtPrint("  {}   {}   {}",
                    AMStr::PadRightAscii(var.name, name_width),
                    AMStr::PadRightAscii(var.type, type_width),
                    var.description);
  }
}
} // namespace

ConfigInterfaceService::ConfigInterfaceService(
    AMApplication::config::ConfigAppService &config_service,
    AMApplication::host::HostAppService &host_service,
    AMInterface::prompt::PromptIOManager &prompt_io_manager,
    AMApplication::prompt::PromptProfileManager &prompt_profile_manager,
    AMInterface::prompt::IsoclineProfileManager &prompt_profile_history_manager)
    : config_service_(config_service), host_service_(host_service),
      prompt_io_manager_(prompt_io_manager),
      prompt_profile_manager_(prompt_profile_manager),
      prompt_profile_history_manager_(prompt_profile_history_manager),
      prompt_profile_editor_(prompt_io_manager, prompt_profile_manager,
                             prompt_profile_history_manager) {}

ECM ConfigInterfaceService::PrintPaths() const {
  const std::filesystem::path project_dir = config_service_.ProjectRoot();
  const std::string project_display = AbsoluteDisplayPath_(project_dir);
  std::vector<std::pair<std::string, std::string>> rows = {
      {"\\[ProjectDir]", config_service_.ProjectRoot().string()},
  };

  for (const ConfigDocumentState &doc : config_service_.ListDocuments()) {
    const std::string display = AbsoluteDisplayPath_(doc.data_path);
    rows.emplace_back(AMStr::fmt("\\[{}]", doc.kind), display);
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

ECM ConfigInterfaceService::PrintTemplateInfo() const {
  const std::string config_path =
      DataPathForKind_(config_service_, DocumentKind::Config);
  const std::string settings_path =
      DataPathForKind_(config_service_, DocumentKind::Settings);

  PrintTemplateInfoBlock_(
      prompt_io_manager_, "command",
      "Render the final shell command used by cmd.",
      config_path, "HOSTS.<nickname>.cmd_template",
      "Lua. The script must return a string.",
      {
          {"cmd", "string", "Original command text typed by the user."},
          {"nickname", "string", "Current host nickname."},
          {"protocol", "string", "Current protocol, such as local, sftp, or ftp."},
          {"hostname", "string", "Current host name."},
          {"username", "string", "Current user name."},
          {"port", "int", "Current host port."},
          {"password", "string", "Current password value."},
          {"keyfile", "string", "Current key file path."},
          {"compression", "bool", "Whether compression is enabled."},
          {"trash_dir", "string", "Host trash directory."},
          {"login_dir", "string", "Host login directory."},
          {"cwd", "string", "Current client working directory."},
          {"cmd_template", "string", "Raw command template."},
          {"is_cwd_exists", "bool", "Whether cwd is non-empty."},
      });
  prompt_io_manager_.Print("");

  PrintTemplateInfoBlock_(
      prompt_io_manager_, "terminal.banner",
      "Render the banner shown when entering a terminal session.",
      settings_path, "Style.Terminal.banner.template",
      "Lua. The script must return a string.",
      {
          {"os_type", "string", "Target client OS type."},
          {"clientname", "string", "Client nickname that owns the terminal."},
          {"termname", "string", "Terminal session nickname."},
          {"hostname", "string", "Target host name."},
          {"username", "string", "Target user name."},
          {"nickname", "string", "Terminal session nickname."},
          {"port", "int", "Target host port."},
          {"sysicon", "string", "Icon resolved from Style.CLIPrompt.icons."},
      });
  prompt_io_manager_.Print("");

  PrintTemplateInfoBlock_(
      prompt_io_manager_, "terminal.control_note",
      "Render the note shown while terminal control mode is active.",
      settings_path, "Style.Terminal.control_note.template",
      "Lua. The script must return a string.",
      {
          {"os_type", "string", "Target client OS type."},
          {"clientname", "string", "Client nickname that owns the terminal."},
          {"termname", "string", "Terminal session nickname."},
          {"hostname", "string", "Target host name."},
          {"username", "string", "Target user name."},
          {"nickname", "string", "Terminal session nickname."},
          {"port", "int", "Target host port."},
          {"sysicon", "string", "Icon resolved from Style.CLIPrompt.icons."},
      });
  prompt_io_manager_.Print("");

  PrintTemplateInfoBlock_(
      prompt_io_manager_, "prompt.core",
      "Render the interactive CLI prompt.",
      settings_path, "Style.CLIPrompt.template.core_prompt",
      "Lua. The script must return a string.",
      {
          {"nickname", "string", "Current client nickname."},
          {"username", "string", "Current user name."},
          {"hostname", "string", "Current host name."},
          {"cwd", "string", "Current client working directory."},
          {"os_type", "string", "Current client OS type."},
          {"sysicon", "string", "Icon resolved from Style.CLIPrompt.icons."},
          {"task_pending", "int", "Number of pending transfer tasks."},
          {"task_running", "int", "Number of running transfer tasks."},
          {"task_paused", "int", "Number of paused transfer tasks."},
          {"success_task", "int", "Number of successful transfer tasks."},
          {"failed_task", "int", "Number of failed transfer tasks."},
          {"channel_num", "int", "Number of channels on the current terminal."},
          {"term_num", "int", "Number of known terminal sessions."},
          {"channel_ok", "int", "Number of healthy channels."},
          {"channel_disconnected", "int", "Number of disconnected channels."},
          {"term_ok", "int", "Number of healthy terminal sessions."},
          {"term_disconnected", "int", "Number of disconnected terminal sessions."},
          {"channel_name", "string", "Current channel name, or empty if none."},
          {"time_now", "string", "Current time text."},
          {"elapsed", "string", "Elapsed time text for the previous command."},
          {"is_success", "bool", "Whether the previous command succeeded."},
          {"ec_name", "string", "Previous command error code name."},
          {"ec_code", "int", "Previous command error code value."},
      },
      {"A tab character aligns the following text to the right edge of the "
       "terminal line."});
  return OK;
}

ECM ConfigInterfaceService::CheckLock() const {
  const bool held = config_service_.HasConfigWriteLock();
  const std::filesystem::path lock_path =
      config_service_.GetConfigWriteLockPath();
  const std::string owner = config_service_.GetConfigWriteLockOwnerInfo();

  prompt_io_manager_.FmtPrint("\\[ConfigWriteLock]");
  prompt_io_manager_.FmtPrint("  held:       {}", held ? "true" : "false");
  if (!lock_path.empty()) {
    prompt_io_manager_.FmtPrint("  lock_path:  {}", lock_path.string());
  }
  if (!owner.empty()) {
    prompt_io_manager_.FmtPrint("  owner:      {}", owner);
  }
  return OK;
}

ECM ConfigInterfaceService::BackupAll() const {
  prompt_io_manager_.SyncCurrentHistory();
  ECM rcm = config_service_.FlushDirtyParticipants();
  if (!(rcm)) {
    return rcm;
  }

  std::vector<DocumentKind> kinds = {};
  for (const ConfigDocumentState &doc : config_service_.ListDocuments()) {
    kinds.push_back(doc.kind);
  }

  const auto backup_rcms = config_service_.Backup(kinds);
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
    return {EC::InvalidArg, "config export", "<path>", "path is empty"};
  }
  if (raw_dir.find('@') != std::string::npos) {
    return {EC::InvalidArg, "config export", raw_dir,
            "path must be a local directory"};
  }

  const std::filesystem::path export_dir =
      std::filesystem::path(raw_dir).lexically_normal();
  std::error_code ec = {};
  if (std::filesystem::exists(export_dir, ec) &&
      !std::filesystem::is_directory(export_dir, ec)) {
    return {EC::InvalidArg, "config export", export_dir.string(),
            "path exists but is not a directory"};
  }

  prompt_io_manager_.SyncCurrentHistory();
  ECM rcm = config_service_.FlushDirtyParticipants();
  if (!(rcm)) {
    return rcm;
  }
  rcm = AMPath::mkdirs(export_dir);
  if (!(rcm)) {
    return rcm;
  }

  ECM first_error = OK;
  for (const ConfigDocumentState &doc : config_service_.ListDocuments()) {
    const std::filesystem::path dst_path =
        export_dir / ResolveExportFileName_(config_service_, doc.kind);
    const ECM dump_rcm =
        config_service_.Dump(doc.kind, dst_path.string(), false);
    if (!(dump_rcm) && (first_error)) {
      first_error = dump_rcm;
    }
  }
  return first_error;
}

ECM ConfigInterfaceService::ExportSchema(const std::string &export_dir) const {
  const std::filesystem::path schema_dir =
      std::filesystem::path(export_dir) / "schema";
  std::error_code ec;
  if (std::filesystem::exists(schema_dir, ec) &&
      !std::filesystem::is_directory(schema_dir, ec)) {
    return {EC::InvalidArg, "config export schema", schema_dir.string(),
            "schema path exists but is not a directory"};
  }
  ECM rcm = AMPath::mkdirs(schema_dir);
  if (!(rcm)) {
    return rcm;
  }

  ECM first_error = OK;
  for (const ConfigDocumentState &doc : config_service_.ListDocuments()) {
    const char *schema_json =
        AMDomain::config::schema::GetSchemaJson(doc.kind);
    // build .schema.json filename from the .toml default (e.g. config.toml → config.schema.json)
    const std::string toml_name = DefaultFileNameForKind_(doc.kind);
    const std::filesystem::path toml_path(toml_name);
    const std::string json_name =
        toml_path.stem().string() + ".schema.json";
    const std::filesystem::path dst = schema_dir / json_name;

    std::ofstream ofs(dst, std::ios::binary | std::ios::trunc);
    if (!ofs.is_open()) {
      first_error = {EC::FilesystemNoSpace, "config export schema",
                     dst.string(), "failed to open schema file for writing"};
      break;
    }
    ofs << schema_json;
    ofs.close();
    if (ofs.fail() && (first_error)) {
      first_error = {EC::FilesystemNoSpace, "config export schema",
                     dst.string(), "write failed"};
      break;
    }
  }
  return first_error;
}

ECM ConfigInterfaceService::EditProfile(const std::string &nickname) {
  const std::string stripped = AMStr::Strip(nickname);
  if (stripped.empty()) {
    return {EC::InvalidArg, "profile edit", "", "empty profile nickname"};
  }
  if (!ValidateNickname(stripped)) {
    return {EC::InvalidArg, "profile edit", stripped,
            "invalid profile nickname literal"};
  }
  const std::string target = NormalizeNickname(stripped);
  if (target == AMDomain::prompt::kPromptProfileDefault) {
    return {EC::InvalidArg, "profile edit", target,
            "profile nickname must be a host nickname"};
  }
  const auto host_query = host_service_.GetClientConfig(target, true);
  if (!(host_query)) {
    return {EC::HostConfigNotFound, "profile edit", target,
            AMStr::fmt("host nickname not found: {}", target)};
  }
  return prompt_profile_editor_.Edit(target);
}

ECM ConfigInterfaceService::GetProfile(
    const std::vector<std::string> &nicknames) {
  if (nicknames.empty()) {
    return {EC::InvalidArg, "profile get", "",
            "profile get requires at least one nickname"};
  }

  std::vector<std::string> targets = {};
  std::unordered_set<std::string> seen = {};
  targets.reserve(nicknames.size());
  for (const auto &name : nicknames) {
    const std::string stripped = AMStr::Strip(name);
    if (stripped.empty()) {
      return {EC::InvalidArg, "profile get", "", "empty profile nickname"};
    }
    if (!ValidateNickname(stripped)) {
      return {EC::InvalidArg, "profile get", stripped,
              "invalid profile nickname literal"};
    }
    const std::string target = NormalizeNickname(stripped);
    if (target == AMDomain::prompt::kPromptProfileDefault) {
      return {EC::InvalidArg, "profile get", target,
              "profile nickname must be a host nickname"};
    }
    const auto host_query = host_service_.GetClientConfig(target, true);
    if (!(host_query)) {
      return {EC::HostConfigNotFound, "profile get", target,
              AMStr::fmt("host nickname not found: {}", target)};
    }
    if (seen.insert(target).second) {
      targets.push_back(target);
    }
  }
  return prompt_profile_editor_.Get(targets);
}

ECM ConfigInterfaceService::CleanProfile() {
  std::vector<std::string> stale_profiles = {};
  for (const auto &profile_name : prompt_profile_manager_.ListZones()) {
    if (profile_name == AMDomain::prompt::kPromptProfileDefault) {
      continue;
    }
    if (!host_service_.HostExists(profile_name)) {
      stale_profiles.push_back(profile_name);
    }
  }

  if (stale_profiles.empty()) {
    prompt_io_manager_.Print("No stale profiles to clean.");
    return OK;
  }

  prompt_io_manager_.Print(AMStr::join(stale_profiles, " "));
  bool canceled = false;
  const bool confirmed = prompt_io_manager_.PromptYesNo(
      "Are you sure to remove these profiles? (y/n): ", &canceled);
  if (canceled || !confirmed) {
    return Err(EC::ConfigCanceled, "profile clean", "",
               "profile clean canceled");
  }

  const std::vector<std::string> removed =
      prompt_profile_manager_.RemoveZones(stale_profiles);
  const std::string current_nickname =
      prompt_profile_history_manager_.CurrentNickname();
  if (std::find(removed.begin(), removed.end(), current_nickname) !=
      removed.end()) {
    const ECM change_rcm = prompt_profile_history_manager_.ChangeClient(
        AMDomain::prompt::kPromptProfileDefault);
    if (!(change_rcm)) {
      return change_rcm;
    }
  }
  return OK;
}

} // namespace AMInterface::config
