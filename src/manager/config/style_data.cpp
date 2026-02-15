#include "AMBase/CommonTools.hpp"
#include "AMManager/Config.hpp"

using cls = AMConfigManager;
using Bar = AMProgressBar;
using BarStyle = AMProgressBarStyle;

namespace {

/**
 * @brief Normalize a configured style into a bbcode opening tag.
 */
std::string NormalizeStyleTag_(const std::string &raw) {
  std::string trimmed = AMStr::Strip(raw);

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
  return trimmed;
}

/**
 * @brief Wrap text with a bbcode tag when provided.
 */
inline std::string ApplyStyleTag_(const std::string &tag,
                                  const std::string &text) {
  if (tag.empty()) {
    return text;
  }
  return tag + text + "[/]";
}

/**
 * @brief Map a progress bar color name or hex to indicators::Color/ANSI.
 */
std::variant<indicators::Color, std::string>
ParseProgressBarColor(const std::string &value) {
  const std::string trimmed = AMStr::Strip(value);
  if (trimmed.empty()) {
    return indicators::Color::unspecified;
  }
  if (!trimmed.empty() && trimmed[0] == '#') {
    auto ansi = HexToAnsi(trimmed);
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
  auto it = color_map.find(token);
  if (it != color_map.end()) {
    return it->second;
  }
  return indicators::Color::unspecified;
}

} // namespace

/**
 * @brief Apply a named style to a string with optional path context.
 */
std::string cls::Format(const std::string &ori_str_f,
                        const std::string &style_name,
                        const PathInfo *path_info) const {
  const std::string ori_str = AMStr::BBCEscape(ori_str_f);

  auto apply_input_style = [&](const std::string &name,
                               const std::string &text) -> std::string {
    if (name.empty()) {
      return text;
    }
    std::vector<std::string> key = {"Style", "InputHighlight", name};
    if (name.rfind("Prompt.", 0) == 0) {
      key = {"Style", "Prompt", name.substr(7)};
    }
    std::string raw = AMStr::Strip(
        ResolveArg<std::string>(DocumentKind::Settings, key, "", {}));
    if (raw.empty()) {
      return text;
    }
    if (raw.front() != '[' || raw.back() != ']') {
      return text;
    }
    if (raw.find("[/") != std::string::npos) {
      return text;
    }
    return raw + text + "[/]";
  };

  if (!path_info) {
    return apply_input_style(style_name, ori_str);
  }

  std::string base_key = "regular";
  switch (path_info->type) {
  case PathType::DIR:
    base_key = "dir";
    break;
  case PathType::SYMLINK:
    base_key = "symlink";
    break;
  case PathType::FILE:
    base_key = "regular";
    break;
  default:
    base_key = "otherspecial";
    break;
  }

  std::string main_tag = NormalizeStyleTag_(ResolveArg<std::string>(
      DocumentKind::Settings, {"Style", "Path", base_key}, "", {}));

  const bool is_exist = !path_info->path.empty();
  if (!is_exist) {
    std::string missing_tag = NormalizeStyleTag_(ResolveArg<std::string>(
        DocumentKind::Settings, {"Style", "Path", "nonexistent"}, "", {}));
    if (!missing_tag.empty()) {
      main_tag = std::move(missing_tag);
    }
  }

  return main_tag.empty() ? apply_input_style(style_name, ori_str)
                          : ApplyStyleTag_(main_tag, ori_str);
}

/**
 * @brief Create a progress bar using the current style configuration.
 */
Bar cls::CreateProgressBar(int64_t total_size,
                           const std::string &prefix) const {
  if (!progress_bar_style_) {
    progress_bar_style_ = BuildProgressBarStyle_();
  }
  return Bar(total_size, prefix, *progress_bar_style_);
}

/**
 * @brief Format a UTF-8 table using configured style defaults.
 */
std::string
cls::FormatUtf8Table(const std::vector<std::string> &keys,
                     const std::vector<std::vector<std::string>> &rows) const {
  auto skeleton_color = ResolveArg<std::string>(
      DocumentKind::Settings, {"Style", "Table", "color"}, "", {});

  auto clamp_padding = [](int value, size_t fallback) -> size_t {
    if (value < 0) {
      return fallback;
    }
    return static_cast<size_t>(value);
  };

  auto pad_left_raw = ResolveArg<int64_t>(
      DocumentKind::Settings, {"Style", "Table", "left_padding"}, 1, {});
  auto pad_right_raw = ResolveArg<int64_t>(
      DocumentKind::Settings, {"Style", "Table", "right_padding"}, 1, {});
  auto pad_top_raw = ResolveArg<int64_t>(
      DocumentKind::Settings, {"Style", "Table", "top_padding"}, 0, {});
  auto pad_bottom_raw = ResolveArg<int64_t>(
      DocumentKind::Settings, {"Style", "Table", "bottom_padding"}, 0, {});
  const size_t pad_left = clamp_padding(static_cast<int>(pad_left_raw), 0);
  const size_t pad_right = clamp_padding(static_cast<int>(pad_right_raw), 0);
  const size_t pad_top = clamp_padding(static_cast<int>(pad_top_raw), 0);
  const size_t pad_bottom = clamp_padding(static_cast<int>(pad_bottom_raw), 0);

  return AMStr::FormatUtf8Table(keys, rows, skeleton_color, pad_left, pad_right,
                                pad_top, pad_bottom);
}

/**
 * @brief Read an integer setting from settings JSON.
 */
/**
 * @brief Build progress bar style from settings.
 */
BarStyle cls::BuildProgressBarStyle_() const {
  BarStyle style;
  int width = static_cast<int>(ResolveArg<int64_t>(
      DocumentKind::Settings, {"Style", "ProgressBar", "bar_width"}, -1, {}));
  if (width <= 0) {
    width = static_cast<int>(ResolveArg<int64_t>(
        DocumentKind::Settings, {"Style", "ProgressBar", "Width"}, -1, {}));
  }
  if (width > 0) {
    style.bar_width = static_cast<size_t>(width);
  }
  style.width_offset = static_cast<int>(
      ResolveArg<int64_t>(DocumentKind::Settings,
                          {"Style", "ProgressBar", "width_offset"}, 30, {}));

  style.start = ResolveArg<std::string>(
      DocumentKind::Settings, {"Style", "ProgressBar", "lborder"}, "", {});

  style.end = ResolveArg<std::string>(
      DocumentKind::Settings, {"Style", "ProgressBar", "rborder"}, "", {});

  auto fill = ResolveArg<std::string>(
      DocumentKind::Settings, {"Style", "ProgressBar", "fill"}, "▓", {});
  style.fill = fill.empty() ? "█" : fill;
  auto lead = ResolveArg<std::string>(
      DocumentKind::Settings, {"Style", "ProgressBar", "head"}, "█", {});
  style.lead = lead.empty() ? "▓" : lead;

  style.remainder = ResolveArg<std::string>(
      DocumentKind::Settings, {"Style", "ProgressBar", "remain"}, " ", {});

  style.color = ParseProgressBarColor(ResolveArg<std::string>(
      DocumentKind::Settings, {"Style", "ProgressBar", "color"}, "#FFFFFF",
      {}));

  style.show_percentage = ResolveArg<bool>(
      DocumentKind::Settings, {"Style", "ProgressBar", "show_percentage"},
      style.show_percentage, {});
  style.show_elapsed_time = ResolveArg<bool>(
      DocumentKind::Settings, {"Style", "ProgressBar", "show_elapsed_time"},
      style.show_elapsed_time, {});
  style.show_remaining_time = ResolveArg<bool>(
      DocumentKind::Settings, {"Style", "ProgressBar", "show_remaining_time"},
      style.show_remaining_time, {});

  return style;
}
