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
    return &cfg.common.protocol;
  case StyleIndex::Abort:
    return &cfg.common.abort;
  case StyleIndex::Common:
    return &cfg.common.common;
  case StyleIndex::Module:
    return &cfg.common.module;
  case StyleIndex::Command:
    return &cfg.common.command;
  case StyleIndex::IllegalCommand:
    return &cfg.common.unexpected;
  case StyleIndex::Option:
    return &cfg.common.option;
  case StyleIndex::String:
    return &cfg.common.string;
  case StyleIndex::PublicVarname:
    return &cfg.common.public_varname;
  case StyleIndex::PrivateVarname:
    return &cfg.common.private_varname;
  case StyleIndex::NonexistentVarname:
    return &cfg.common.nonexistent_varname;
  case StyleIndex::VarValue:
    return &cfg.common.varvalue;
  case StyleIndex::Nickname:
    return &cfg.common.nickname;
  case StyleIndex::DisconnectedNickname:
    return &cfg.common.disconnected_nickname;
  case StyleIndex::UnestablishedNickname:
    return &cfg.common.unestablished_nickname;
  case StyleIndex::NonexistentNickname:
    return &cfg.common.nonexistent_nickname;
  case StyleIndex::ValidNewNickname:
    return &cfg.common.valid_new_nickname;
  case StyleIndex::InvalidNewNickname:
    return &cfg.common.invalid_new_nickname;
  case StyleIndex::TerminalName:
    return &cfg.common.termname;
  case StyleIndex::DisconnectedTerminalName:
    return &cfg.common.disconnected_termname;
  case StyleIndex::UnestablishedTerminalName:
    return &cfg.common.unestablished_termname;
  case StyleIndex::NonexistentTerminalName:
    return &cfg.common.nonexistent_termname;
  case StyleIndex::ChannelName:
    return &cfg.common.channelname;
  case StyleIndex::DisconnectedChannelName:
    return &cfg.common.disconnected_channelname;
  case StyleIndex::NonexistentChannelName:
    return &cfg.common.nonexistent_channelname;
  case StyleIndex::ValidNewChannelName:
    return &cfg.common.valid_new_channelname;
  case StyleIndex::InvalidNewChannelName:
    return &cfg.common.invalid_new_channelname;
  case StyleIndex::BuiltinArg:
    return &cfg.common.builtin_arg;
  case StyleIndex::NonexistentBuiltinArg:
    return &cfg.common.nonexistent_builtin_arg;
  case StyleIndex::Username:
    return &cfg.common.username;
  case StyleIndex::AtSign:
    return &cfg.common.atsign;
  case StyleIndex::DollarSign:
    return &cfg.common.dollarsign;
  case StyleIndex::EqualSign:
    return &cfg.common.equalsign;
  case StyleIndex::EscapedSign:
    return &cfg.common.escapedsign;
  case StyleIndex::BangSign:
    return &cfg.common.bangsign;
  case StyleIndex::ShellCmd:
    return &cfg.common.shell_cmd;
  case StyleIndex::Cwd:
    return &cfg.path.cwd;
  case StyleIndex::Number:
    return &cfg.common.number;
  case StyleIndex::Timestamp:
    return &cfg.common.timestamp;
  case StyleIndex::PathLike:
    return &cfg.common.path_like;
  case StyleIndex::Error:
    return &cfg.system_info.error;
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

  const std::string *path_tag = &cfg.path.regular;
  if (path_info->path.empty()) {
    path_tag = &cfg.path.nonexistent;
  } else if (path_info->type == PathType::DIR) {
    path_tag = &cfg.path.dir;
  } else if (path_info->type == PathType::SYMLINK) {
    path_tag = &cfg.path.symlink;
  } else if (path_info->type != PathType::FILE) {
    path_tag = &cfg.path.otherspecial;
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
  const auto cfg = GetInitArg().style.table;
  const size_t left =
      static_cast<size_t>(std::max<int64_t>(0, cfg.left_padding));
  const size_t right =
      static_cast<size_t>(std::max<int64_t>(0, cfg.right_padding));
  const size_t top = static_cast<size_t>(std::max<int64_t>(0, cfg.top_padding));
  const size_t bottom =
      static_cast<size_t>(std::max<int64_t>(0, cfg.bottom_padding));
  return AMStr::FormatUtf8Table(keys, rows, cfg.color, left, right, top,
                                bottom);
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
