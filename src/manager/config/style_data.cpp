#include "internal_func.hpp"

using namespace AMConfigInternal;

/**
 * @brief Construct a style layer with no bound storage.
 */
AMConfigStyleData::AMConfigStyleData() = default;

/**
 * @brief Bind the storage layer used for style configuration lookups.
 */
void AMConfigStyleData::BindStorage(AMConfigStorage *storage) {
  storage_ = storage;
  progress_bar_style_.reset();
}

/**
 * @brief Apply a named style to a string with optional path context.
 */
std::string AMConfigStyleData::Format(const std::string &ori_str_f,
                                      const std::string &style_name,
                                      const PathInfo *path_info) const {
  const std::string ori_str = AMStr::BBCEscape(ori_str_f);
  if (!storage_) {
    return ori_str;
  }

  auto apply_input_style = [&](const std::string &name,
                               const std::string &text) -> std::string {
    if (name.empty()) {
      return text;
    }
    std::vector<std::string> key = {"style", "InputHighlight", name};
    if (name.rfind("Prompt.", 0) == 0) {
      key = {"style", "Prompt", name.substr(7)};
    }
    const Json *node =
        FindJsonNode(storage_->GetJson(DocumentKind::Settings).value().get(),
                     key);
    if (!node || !node->is_string()) {
      return text;
    }
    std::string raw = TrimCopy(node->get<std::string>());
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

  std::string main_tag =
      NormalizeStyleTag_(GetSettingString_({"style", "Path1", base_key}, ""));
  const std::string path_name =
      !path_info->name.empty()
          ? path_info->name
          : (ori_str_f.empty() ? std::string()
                               : AMPathStr::basename(ori_str_f));
  if (path_info->type == PathType::FILE) {
    const std::string ext = AMPathStr::extname(path_name);
    if (!ext.empty()) {
      std::string ext_tag =
          NormalizeStyleTag_(GetSettingString_({"style", "File2", ext}, ""));
      if (!ext_tag.empty()) {
        main_tag = ext_tag;
      }
    }
  }

  std::string styled = main_tag.empty() ? apply_input_style(style_name, ori_str)
                                        : ApplyStyleTag_(main_tag, ori_str);

  const bool is_hidden = !path_name.empty() && path_name.front() == '.';
  const bool is_nowrite =
      path_info->mode_int != 0 && (path_info->mode_int & 0222) == 0;
  const bool is_exist = !path_info->path.empty();

  auto resolve_extra = [&](const std::string &key) -> std::string {
    std::string tag = NormalizeStyleTag_(
        GetSettingString_({"style", "PathExtraStyle", key}, ""));
    if (!tag.empty()) {
      return tag;
    }
    return NormalizeStyleTag_(
        GetSettingString_({"style", "PathSpecific3", key}, ""));
  };

  if (!is_exist) {
    const std::string extra_tag = resolve_extra("nonexist");
    if (!extra_tag.empty()) {
      styled = ApplyStyleTag_(extra_tag, styled);
    }
  }
  if (is_hidden) {
    const std::string extra_tag = resolve_extra("hidden");
    if (!extra_tag.empty()) {
      styled = ApplyStyleTag_(extra_tag, styled);
    }
  }
  if (is_nowrite) {
    const std::string extra_tag = resolve_extra("nowrite");
    if (!extra_tag.empty()) {
      styled = ApplyStyleTag_(extra_tag, styled);
    }
  }
  return styled;
}

/**
 * @brief Create a progress bar using the current style configuration.
 */
AMProgressBar
AMConfigStyleData::CreateProgressBar(int64_t total_size,
                                     const std::string &prefix) const {
  if (!progress_bar_style_) {
    progress_bar_style_ = BuildProgressBarStyle_();
  }
  return AMProgressBar(total_size, prefix, *progress_bar_style_);
}

/**
 * @brief Format a UTF-8 table using configured style defaults.
 */
std::string AMConfigStyleData::FormatUtf8Table(
    const std::vector<std::string> &keys,
    const std::vector<std::vector<std::string>> &rows) const {
  static const std::string skeleton_color =
      GetSettingString_({"style", "Table", "color"}, "");

  auto clamp_padding = [](int value, size_t fallback) -> size_t {
    if (value < 0) {
      return fallback;
    }
    return static_cast<size_t>(value);
  };

  static const size_t pad_left =
      clamp_padding(GetSettingInt_({"style", "Table", "left_padding"}, 1), 0);
  static const size_t pad_right =
      clamp_padding(GetSettingInt_({"style", "Table", "right_padding"}, 1), 0);
  static const size_t pad_top =
      clamp_padding(GetSettingInt_({"style", "Table", "top_padding"}, 0), 0);
  static const size_t pad_bottom =
      clamp_padding(GetSettingInt_({"style", "Table", "bottom_padding"}, 0), 0);

  return AMStr::FormatUtf8Table(keys, rows, skeleton_color, pad_left, pad_right,
                                pad_top, pad_bottom);
}

/**
 * @brief Read an integer setting from settings JSON.
 */
int AMConfigStyleData::GetSettingInt_(const std::vector<std::string> &path,
                                      int default_value) const {
  if (!storage_) {
    return default_value;
  }
  const Json *node =
      FindJsonNode(storage_->GetJson(DocumentKind::Settings).value().get(),
                   path);
  return GetSettingValueImpl<int>(node, default_value);
}

/**
 * @brief Read a string setting from settings JSON.
 */
std::string
AMConfigStyleData::GetSettingString_(const std::vector<std::string> &path,
                                     const std::string &default_value) const {
  if (!storage_) {
    return default_value;
  }
  const Json *node =
      FindJsonNode(storage_->GetJson(DocumentKind::Settings).value().get(),
                   path);
  return GetSettingValueImpl<std::string>(node, default_value);
}

/**
 * @brief Build progress bar style from settings.
 */
AMProgressBarStyle AMConfigStyleData::BuildProgressBarStyle_() const {
  AMProgressBarStyle style;
  int width = GetSettingInt_({"style", "ProgressBar", "bar_width"}, -1);
  if (width <= 0) {
    width = GetSettingInt_({"style", "ProgressBar", "Width"}, -1);
  }
  if (width > 0) {
    style.bar_width = static_cast<size_t>(width);
  }
  style.width_offset =
      GetSettingInt_({"style", "ProgressBar", "width_offset"}, 30);

  style.start = GetSettingString_({"style", "ProgressBar", "lborder"}, "");

  style.end = GetSettingString_({"style", "ProgressBar", "rborder"}, "");

  std::string fill = GetSettingString_({"style", "ProgressBar", "fill"}, "▓");
  style.fill = fill.empty() ? "█" : fill;
  std::string lead = GetSettingString_({"style", "ProgressBar", "head"}, "█");
  style.lead = lead.empty() ? "▓" : lead;

  style.remainder = GetSettingString_({"style", "ProgressBar", "remain"}, " ");

  style.color = ParseProgressBarColor(
      GetSettingString_({"style", "ProgressBar", "color"}, "#FFFFFF"));

  auto parse_bool = [&](const std::vector<std::string> &path,
                        bool default_value) {
    std::string raw = GetSettingString_(path, default_value ? "true" : "false");
    bool value = default_value;
    ParseBoolToken(raw, &value);
    return value;
  };

  style.show_percentage = parse_bool(
      {"style", "ProgressBar", "show_percentage"}, style.show_percentage);
  style.show_elapsed_time = parse_bool(
      {"style", "ProgressBar", "show_elapsed_time"}, style.show_elapsed_time);
  style.show_remaining_time =
      parse_bool({"style", "ProgressBar", "show_remaining_time"},
                 style.show_remaining_time);

  return style;
}
