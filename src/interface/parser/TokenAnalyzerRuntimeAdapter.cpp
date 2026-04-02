#include "interface/parser/TokenAnalyzerRuntimeAdapter.hpp"

#include "domain/filesystem/FileSystemDomainService.hpp"
#include "domain/host/HostModel.hpp"
#include "foundation/tools/path.hpp"
#include "foundation/tools/string.hpp"

namespace AMInterface::parser {
namespace {

std::string NormalizePath_(const std::string &path) {
  return AMDomain::filesystem::services::NormalizePath(AMStr::Strip(path));
}

std::string ResolveWorkdir_(const AMDomain::host::ClientMetaData &metadata,
                            const std::string &home_dir) {
  const std::string cwd = NormalizePath_(metadata.cwd);
  if (!cwd.empty()) {
    return cwd;
  }
  const std::string login_dir = NormalizePath_(metadata.login_dir);
  if (!login_dir.empty()) {
    return login_dir;
  }
  const std::string home = NormalizePath_(home_dir);
  if (!home.empty()) {
    return home;
  }
  return ".";
}

} // namespace

AMDomain::client::ClientHandle
TokenAnalyzerRuntimeAdapter::CurrentClient() const {
  return client_service_.GetCurrentClient();
}

AMDomain::client::ClientHandle TokenAnalyzerRuntimeAdapter::LocalClient() const {
  return client_service_.GetLocalClient();
}

AMDomain::client::ClientHandle
TokenAnalyzerRuntimeAdapter::GetClient(const std::string &nickname) const {
  auto client = client_service_.GetClient(nickname, true);
  if (!(client.rcm)) {
    return nullptr;
  }
  return client.data;
}

bool TokenAnalyzerRuntimeAdapter::HostExists(const std::string &nickname) const {
  return host_service_.HostExists(nickname);
}

bool TokenAnalyzerRuntimeAdapter::HasVarDomain(const std::string &zone) const {
  auto all_vars = var_service_.GetAllVar();
  if (!(all_vars.rcm)) {
    return false;
  }
  return all_vars.data.find(zone) != all_vars.data.end();
}

std::string TokenAnalyzerRuntimeAdapter::CurrentVarDomain() const {
  std::string current = AMStr::Strip(client_service_.CurrentNickname());
  if (current.empty()) {
    current = "local";
  }
  return current;
}

ECMData<AMDomain::var::VarInfo>
TokenAnalyzerRuntimeAdapter::GetVar(const std::string &zone,
                                    const std::string &varname) const {
  return var_service_.GetVar(zone, varname);
}

ITokenAnalyzerRuntime::PromptPathOptions
TokenAnalyzerRuntimeAdapter::ResolvePromptPathOptions(
    const std::string &nickname) const {
  auto query = prompt_profile_manager_.GetZoneProfile(nickname);
  PromptPathOptions out = {};
  out.highlight_enable = query.profile.highlight.path.enable;
  out.highlight_timeout_ms = query.profile.highlight.path.timeout_ms;
  return out;
}

std::string
TokenAnalyzerRuntimeAdapter::SubstitutePathLike(const std::string &raw) const {
  return var_interface_service_.SubstitutePathLike(raw);
}

std::string TokenAnalyzerRuntimeAdapter::BuildPath(
    AMDomain::client::ClientHandle client, const std::string &raw_path) const {
  if (!client) {
    return NormalizePath_(raw_path);
  }

  const std::string input = raw_path.empty() ? "." : raw_path;
  const std::string home_dir = client->ConfigPort().GetHomeDir();
  AMDomain::host::ClientMetaData metadata = {};
  auto metadata_opt =
      client->MetaDataPort().QueryTypedValue<AMDomain::host::ClientMetaData>();
  if (metadata_opt.has_value()) {
    metadata = *metadata_opt;
  }
  const std::string cwd = ResolveWorkdir_(metadata, home_dir);
  return AMPath::abspath(input, true, home_dir, cwd);
}

ECMData<PathInfo> TokenAnalyzerRuntimeAdapter::StatPath(
    AMDomain::client::ClientHandle client, const std::string &abs_path,
    int timeout_ms) const {
  if (!client) {
    return {PathInfo{}, Err(EC::InvalidHandle, "", "", "client is null")};
  }
  auto control =
      AMDomain::client::ClientControlComponent(nullptr, timeout_ms);
  auto stat_result = client->IOPort().stat({abs_path, false}, control);
  return {stat_result.data.info, stat_result.rcm};
}

std::string TokenAnalyzerRuntimeAdapter::FormatPath(
    const std::string &segment, const PathInfo *path_info) const {
  return style_service_.Format(segment, AMInterface::style::StyleIndex::PathLike,
                               path_info);
}

std::string TokenAnalyzerRuntimeAdapter::ResolveSettingString(
    const std::vector<std::string> &path,
    const std::string &default_value) const {
  const auto style_cfg = style_service_.GetInitArg().style;
  if (path.size() < 3 || path[0] != "Style") {
    return default_value;
  }

  const std::string &section = path[1];
  const std::string &key = path[2];

  if (section == "InputHighlight") {
    if (key == "module") {
      return style_cfg.input_highlight.module;
    }
    if (key == "command") {
      return style_cfg.input_highlight.command;
    }
    if (key == "public_varname") {
      return style_cfg.input_highlight.public_varname;
    }
    if (key == "nonexistent_varname") {
      return style_cfg.input_highlight.nonexistent_varname;
    }
    if (key == "varvalue") {
      return style_cfg.input_highlight.varvalue;
    }
    if (key == "nickname") {
      return style_cfg.input_highlight.nickname;
    }
    if (key == "unestablished_nickname") {
      return style_cfg.input_highlight.unestablished_nickname;
    }
    if (key == "nonexistent_nickname") {
      return style_cfg.input_highlight.nonexistent_nickname;
    }
    if (key == "builtin_arg") {
      return style_cfg.input_highlight.builtin_arg;
    }
    if (key == "valid_new_nickname") {
      return style_cfg.input_highlight.valid_new_nickname;
    }
    if (key == "invalid_new_nickname") {
      return style_cfg.input_highlight.invalid_new_nickname;
    }
    if (key == "string") {
      return style_cfg.input_highlight.string;
    }
    if (key == "option") {
      return style_cfg.input_highlight.option;
    }
    if (key == "atsign") {
      return style_cfg.input_highlight.atsign;
    }
    if (key == "dollarsign") {
      return style_cfg.input_highlight.dollarsign;
    }
    if (key == "leftbrace") {
      return default_value;
    }
    if (key == "rightbrace") {
      return default_value;
    }
    if (key == "colonsign") {
      return default_value;
    }
    if (key == "equalsign") {
      return style_cfg.input_highlight.equalsign;
    }
    if (key == "escapedsign") {
      return style_cfg.input_highlight.escapedsign;
    }
    if (key == "path_like") {
      return style_cfg.input_highlight.path_like;
    }
    if (key == "file" || key == "dir" || key == "symlink" ||
        key == "special" || key == "nonexistentpath") {
      return default_value;
    }
    if (key == "bangsign") {
      return style_cfg.input_highlight.bangsign;
    }
    if (key == "shell_cmd") {
      return style_cfg.input_highlight.shell_cmd;
    }
    if (key == "illegal_command") {
      return style_cfg.input_highlight.illegal_command;
    }
    if (key == "common") {
      return style_cfg.input_highlight.common;
    }
    return default_value;
  }

  if (section == "Path") {
    if (key == "regular") {
      return style_cfg.path.regular;
    }
    if (key == "dir") {
      return style_cfg.path.dir;
    }
    if (key == "symlink") {
      return style_cfg.path.symlink;
    }
    if (key == "otherspecial") {
      return style_cfg.path.otherspecial;
    }
    if (key == "nonexistent") {
      return style_cfg.path.nonexistent;
    }
    return default_value;
  }

  if (section == "shortcut") {
    const auto it = style_cfg.cli_prompt.shortcut.find(key);
    if (it != style_cfg.cli_prompt.shortcut.end()) {
      return it->second;
    }
    return default_value;
  }

  return default_value;
}

} // namespace AMInterface::parser

