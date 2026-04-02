#include "interface/style/StyleManager.hpp"
#include "domain/style/StyleDomainService.hpp"
#include "foundation/tools/string.hpp"

#include <algorithm>
#include <unordered_map>
#include <variant>

namespace AMInterface::style {
namespace detail {
const std::string *
LookupPromptShortcut_(const AMDomain::style::StyleConfig &cfg,
                      const std::string &key) {
  const auto it = cfg.cli_prompt.shortcut.find(key);
  if (it == cfg.cli_prompt.shortcut.end()) {
    return nullptr;
  }
  return &it->second;
}

const std::string *
ResolveInputStyleByIndex(const AMDomain::style::StyleConfig &cfg,
                         StyleIndex style_index) {
  switch (style_index) {
  case StyleIndex::Protocol:
    return &cfg.input_highlight.protocol;
  case StyleIndex::Abort:
    return &cfg.input_highlight.abort;
  case StyleIndex::Common:
    return &cfg.input_highlight.common;
  case StyleIndex::Module:
    return &cfg.input_highlight.module;
  case StyleIndex::Command:
    return &cfg.input_highlight.command;
  case StyleIndex::IllegalCommand:
    return &cfg.input_highlight.illegal_command;
  case StyleIndex::Option:
    return &cfg.input_highlight.option;
  case StyleIndex::String:
    return &cfg.input_highlight.string;
  case StyleIndex::PublicVarname:
    return &cfg.input_highlight.public_varname;
  case StyleIndex::PrivateVarname:
    return &cfg.input_highlight.private_varname;
  case StyleIndex::NonexistentVarname:
    return &cfg.input_highlight.nonexistent_varname;
  case StyleIndex::VarValue:
    return &cfg.input_highlight.varvalue;
  case StyleIndex::Nickname:
    return &cfg.input_highlight.nickname;
  case StyleIndex::UnestablishedNickname:
    return &cfg.input_highlight.unestablished_nickname;
  case StyleIndex::NonexistentNickname:
    return &cfg.input_highlight.nonexistent_nickname;
  case StyleIndex::ValidNewNickname:
    return &cfg.input_highlight.valid_new_nickname;
  case StyleIndex::InvalidNewNickname:
    return &cfg.input_highlight.invalid_new_nickname;
  case StyleIndex::BuiltinArg:
    return &cfg.input_highlight.builtin_arg;
  case StyleIndex::NonexistentBuiltinArg:
    return &cfg.input_highlight.nonexistent_builtin_arg;
  case StyleIndex::Username:
    return &cfg.input_highlight.username;
  case StyleIndex::AtSign:
    return &cfg.input_highlight.atsign;
  case StyleIndex::DollarSign:
    return &cfg.input_highlight.dollarsign;
  case StyleIndex::EqualSign:
    return &cfg.input_highlight.equalsign;
  case StyleIndex::EscapedSign:
    return &cfg.input_highlight.escapedsign;
  case StyleIndex::BangSign:
    return &cfg.input_highlight.bangsign;
  case StyleIndex::ShellCmd:
    return &cfg.input_highlight.shell_cmd;
  case StyleIndex::Cwd:
    return &cfg.input_highlight.cwd;
  case StyleIndex::Number:
    return &cfg.input_highlight.number;
  case StyleIndex::Timestamp:
    return &cfg.input_highlight.timestamp;
  case StyleIndex::PathLike:
    return &cfg.input_highlight.path_like;
  case StyleIndex::PromptUn:
    return LookupPromptShortcut_(cfg, "un");
  case StyleIndex::PromptAt:
    return LookupPromptShortcut_(cfg, "at");
  case StyleIndex::PromptHn:
    return LookupPromptShortcut_(cfg, "hn");
  case StyleIndex::PromptEn:
    return LookupPromptShortcut_(cfg, "en");
  case StyleIndex::PromptNn:
    return LookupPromptShortcut_(cfg, "nn");
  case StyleIndex::PromptCwd:
    return LookupPromptShortcut_(cfg, "cwd");
  case StyleIndex::PromptDs:
    return LookupPromptShortcut_(cfg, "ds");
  case StyleIndex::PromptWhite:
    return LookupPromptShortcut_(cfg, "white");
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
  if (!AMDomain::style::services::IsStyleString(trimmed)) {
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

std::variant<indicators::Color, std::string>
ParseProgressBarColor(const std::string &value) {
  const std::string trimmed = AMStr::Strip(value);
  if (trimmed.empty()) {
    return indicators::Color::unspecified;
  }
  if (trimmed.front() == '#') {
    auto ansi = AMStr::HexToAnsi(trimmed);
    if (ansi) {
      return *ansi;
    }
  }
  const std::string token = AMStr::lowercase(trimmed);
  static const std::unordered_map<std::string, indicators::Color> color_map = {
      {"unspecified", indicators::Color::unspecified},
      {"red", indicators::Color::red},
      {"green", indicators::Color::green},
      {"yellow", indicators::Color::yellow},
      {"blue", indicators::Color::blue},
      {"magenta", indicators::Color::magenta},
      {"cyan", indicators::Color::cyan},
      {"white", indicators::Color::white},
      {"grey", indicators::Color::grey},
  };
  const auto it = color_map.find(token);
  if (it == color_map.end()) {
    return indicators::Color::unspecified;
  }
  return it->second;
}

AMProgressBarStyle
BuildProgressBarStyle(const AMDomain::style::StyleConfig &cfg) {
  AMProgressBarStyle style{};
  style.bar_width =
      static_cast<size_t>(std::max<int64_t>(1, cfg.progress_bar.bar_width));
  style.width_offset = static_cast<int>(cfg.progress_bar.width_offset);
  style.start = cfg.progress_bar.start;
  style.end = cfg.progress_bar.end;
  style.fill = cfg.progress_bar.fill.empty() ? "█" : cfg.progress_bar.fill;
  style.lead = cfg.progress_bar.lead.empty() ? "▓" : cfg.progress_bar.lead;
  style.remainder = cfg.progress_bar.remaining;
  style.color = ParseProgressBarColor(cfg.progress_bar.color);
  style.show_percentage = cfg.progress_bar.show_percentage;
  style.show_elapsed_time = cfg.progress_bar.show_elapsed_time;
  style.show_remaining_time = cfg.progress_bar.show_remaining_time;
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

AMProgressBar AMStyleService::CreateProgressBar(int64_t total_size,
                                                const std::string &prefix) {
  {
    const auto cached = progress_bar_style_.lock().load();
    if (cached.has_value()) {
      return AMProgressBar(total_size, prefix, cached.value());
    }
  }

  const auto cfg = GetInitArg().style;
  const AMProgressBarStyle built = detail::BuildProgressBarStyle(cfg);

  auto cached = progress_bar_style_.lock();
  if (!cached->has_value()) {
    cached->emplace(built);
  }
  return AMProgressBar(total_size, prefix, cached->value());
}
} // namespace AMInterface::style

