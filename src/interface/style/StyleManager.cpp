#include "interface/style/StyleManager.hpp"
#include "domain/style/StyleDomainService.hpp"
#include "foundation/tools/string.hpp"

#include <algorithm>

namespace AMInterface::style {
namespace detail {
const std::string *
ResolveInputStyleByIndex(const AMDomain::style::StyleConfig &cfg,
                         StyleIndex style_index) {
  switch (style_index) {
  case StyleIndex::Protocol:
    return &cfg.common.type_protocol;
  case StyleIndex::Abort:
    return &cfg.common.type_abort;
  case StyleIndex::Error:
    return &cfg.common.type_error;
  case StyleIndex::Common:
    return &cfg.common.default_style;
  case StyleIndex::Module:
    return &cfg.common.cli_module;
  case StyleIndex::Command:
    return &cfg.common.cli_command;
  case StyleIndex::IllegalCommand:
    return &cfg.common.cli_unexpected;
  case StyleIndex::Option:
    return &cfg.common.cli_option;
  case StyleIndex::String:
    return &cfg.common.type_string;
  case StyleIndex::PublicVarname:
    return &cfg.common.varname_public;
  case StyleIndex::PrivateVarname:
    return &cfg.common.varname_private;
  case StyleIndex::VarnameZone:
    return &cfg.common.varname_zone;
  case StyleIndex::NonexistentVarname:
    return &cfg.common.varname_nonexistent;
  case StyleIndex::VarValue:
    return &cfg.common.varvalue;
  case StyleIndex::Nickname:
    return &cfg.common.nickname_ok;
  case StyleIndex::DisconnectedNickname:
    return &cfg.common.nickname_disconnected;
  case StyleIndex::UnestablishedNickname:
    return &cfg.common.nickname_unestablished;
  case StyleIndex::NonexistentNickname:
    return &cfg.common.nickname_nonexistent;
  case StyleIndex::ValidNewNickname:
    return &cfg.common.nickname_new_valid;
  case StyleIndex::InvalidNewNickname:
    return &cfg.common.nickname_new_invalid;
  case StyleIndex::TerminalName:
    return &cfg.common.termname_ok;
  case StyleIndex::DisconnectedTerminalName:
    return &cfg.common.termname_disconnected;
  case StyleIndex::NonexistentTerminalName:
    return &cfg.common.termname_nonexistent;
  case StyleIndex::ValidNewTerminalName:
    return &cfg.common.termname_new_valid;
  case StyleIndex::InvalidNewTerminalName:
    return &cfg.common.termname_new_invalid;
  case StyleIndex::BuiltinArg:
    return &cfg.common.attr_valid;
  case StyleIndex::NonexistentBuiltinArg:
    return &cfg.common.attr_invalid;
  case StyleIndex::Username:
    return &cfg.common.type_username;
  case StyleIndex::AtSign:
    return &cfg.common.nickname_at;
  case StyleIndex::TermnameAtSign:
    return &cfg.common.termname_at;
  case StyleIndex::DollarSign:
    return &cfg.common.varname_dollar;
  case StyleIndex::EqualSign:
    return &cfg.common.varname_equal;
  case StyleIndex::LeftBraceSign:
    return &cfg.common.varname_left_brace;
  case StyleIndex::RightBraceSign:
    return &cfg.common.varname_right_brace;
  case StyleIndex::ColonSign:
    return &cfg.common.varname_colon;
  case StyleIndex::EscapedSign:
    return &cfg.common.sign_escaped;
  case StyleIndex::BangSign:
    return &cfg.common.sign_bang;
  case StyleIndex::ShellCmd:
    return &cfg.common.type_shell_cmd;
  case StyleIndex::Cwd:
    return &cfg.path.type_dir;
  case StyleIndex::Number:
    return &cfg.common.type_number;
  case StyleIndex::Timestamp:
    return &cfg.common.default_style;
  case StyleIndex::PathLike:
    return &cfg.common.default_style;
  case StyleIndex::FindPattern:
    return &cfg.path.find_pattern;
  case StyleIndex::TableSkeleton:
    return &cfg.common.type_table_skeleton;
  case StyleIndex::None:
  default:
    return nullptr;
  }
}

std::string NormalizeStyleTag(const std::string &raw_tag) {
  std::string trimmed = AMStr::Strip(raw_tag);
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
  if (!AMDomain::style::service::IsStyleString(trimmed)) {
    return "";
  }
  return trimmed;
}

std::string ApplyStyleTag(const std::string &tag, const std::string &text) {
  if (tag.empty()) {
    return text;
  }
  return tag + text + "[/]";
}

std::string ExtractHexColorFromStyleTag(const std::string &raw_tag) {
  std::string tag = NormalizeStyleTag(raw_tag);
  if (tag.size() < 3) {
    return "";
  }
  std::string body = tag.substr(1, tag.size() - 2);
  const size_t style_sep = body.find(' ');
  if (style_sep != std::string::npos) {
    body = body.substr(0, style_sep);
  }
  return AMDomain::style::service::IsHexColorString(body) ? body : "";
}

std::string ResolveInputStyleTag(const AMDomain::style::StyleConfig &cfg,
                                 StyleIndex style_index) {
  const auto *raw_tag = ResolveInputStyleByIndex(cfg, style_index);
  if (!raw_tag) {
    return "";
  }
  return NormalizeStyleTag(*raw_tag);
}

std::string ResolvePathStyleTag(const AMDomain::style::StyleConfig &cfg,
                                const PathInfo *path_info) {
  if (!path_info) {
    return "";
  }

  const std::string *path_tag = &cfg.path.type_regular;
  if (path_info->path.empty()) {
    path_tag = &cfg.path.type_nonexistent;
  } else if (path_info->type == PathType::DIR) {
    path_tag = &cfg.path.type_dir;
  } else if (path_info->type == PathType::SYMLINK) {
    path_tag = &cfg.path.type_symlink;
  } else if (path_info->type != PathType::FILE) {
    path_tag = &cfg.path.type_otherspecial;
  }
  return NormalizeStyleTag(*path_tag);
}

AMProgressBarStyle
BuildProgressBarStyle(const AMDomain::style::StyleConfig &cfg) {
  AMProgressBarStyle style{};
  style.prefix_template = cfg.progress_bar.prefix_template;
  style.bar_template = cfg.progress_bar.bar_template;
  style.refresh_interval_ms =
      std::max<int64_t>(1, cfg.progress_bar.refresh_interval_ms);
  style.prefix_fixed_width =
      static_cast<int>(cfg.progress_bar.prefix_fixed_width);
  style.fill =
      cfg.progress_bar.bar.fill.empty() ? "█" : cfg.progress_bar.bar.fill;
  style.lead =
      cfg.progress_bar.bar.lead.empty() ? "▓" : cfg.progress_bar.bar.lead;
  style.remaining = cfg.progress_bar.bar.remaining;
  style.bar_width =
      static_cast<size_t>(std::max<int64_t>(1, cfg.progress_bar.bar.bar_width));
  style.speed_num_fixed_width = static_cast<size_t>(
      std::max<int64_t>(0, cfg.progress_bar.speed.speed_num_fixed_width));
  style.speed_num_max_float_digits = static_cast<int>(
      std::max<int64_t>(0, cfg.progress_bar.speed.speed_num_max_float_digits));
  style.speed_window_ms =
      std::max<int64_t>(1, cfg.progress_bar.speed.speed_window_ms);
  style.totol_size_fixed_width = static_cast<size_t>(
      std::max<int64_t>(0, cfg.progress_bar.size.totol_size_fixed_width));
  style.totol_size_max_float_digits = static_cast<int>(
      std::max<int64_t>(0, cfg.progress_bar.size.totol_size_max_float_digits));
  style.transferred_size_fixed_width = static_cast<size_t>(
      std::max<int64_t>(0, cfg.progress_bar.size.transferred_size_fixed_width));
  style.transferred_size_max_float_digits = static_cast<int>(std::max<int64_t>(
      0, cfg.progress_bar.size.transferred_size_max_float_digits));
  return style;
}
} // namespace detail

AMStyleService::AMStyleService(StyleConfigArg arg)
    : StyleConfigManager(std::move(arg)),
      progress_bar_style_(std::optional<AMProgressBarStyle>{}) {}

ECM AMStyleService::Init() {
  ECM rcm = StyleConfigManager::Init();
  if (!rcm) {
    return rcm;
  }
  progress_bar_style_.lock().store(std::nullopt);
  return rcm;
}

std::string AMStyleService::Format(const std::string &ori_str,
                                   StyleIndex style_index,
                                   const PathInfo *path_info) const {
  const auto cfg = init_arg_.lock()->style;
  const std::string escaped = AMStr::BBCEscape(ori_str);
  const std::string path_tag = detail::ResolvePathStyleTag(cfg, path_info);
  if (!path_tag.empty()) {
    return detail::ApplyStyleTag(path_tag, escaped);
  }
  return detail::ApplyStyleTag(detail::ResolveInputStyleTag(cfg, style_index),
                               escaped);
}

std::string AMStyleService::FormatUtf8Table(
    const std::vector<std::string> &keys,
    const std::vector<std::vector<std::string>> &rows) const {
  const auto cfg = GetInitArg().style;
  const std::string skeleton_color =
      detail::ExtractHexColorFromStyleTag(cfg.common.type_table_skeleton);
  return AMStr::FormatUtf8Table(keys, rows, skeleton_color, 1, 1, 0, 0);
}

std::unique_ptr<BaseProgressBar>
AMStyleService::CreateProgressBar(int64_t total_size,
                                  const std::string &prefix) {
  (void)prefix;
  {
    const auto cached = progress_bar_style_.lock().load();
    if (cached.has_value()) {
      auto bar = std::make_unique<BaseProgressBar>(cached.value());
      bar->SetTotal(total_size);
      return bar;
    }
  }

  const auto cfg = GetInitArg().style;
  const AMProgressBarStyle built = detail::BuildProgressBarStyle(cfg);

  auto cached = progress_bar_style_.lock();
  if (!cached->has_value()) {
    cached->emplace(built);
  }
  auto bar = std::make_unique<BaseProgressBar>(cached->value());
  bar->SetTotal(total_size);
  return bar;
}
} // namespace AMInterface::style
