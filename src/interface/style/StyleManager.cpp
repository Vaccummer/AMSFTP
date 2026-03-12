#include "interface/style/StyleManager.hpp"

#include "foundation/tools/enum_related.hpp"
#include "foundation/tools/string.hpp"
#include <algorithm>
#include <unordered_map>

namespace AMInterface::style {
ECM AMStyleService::Init(
    AMApplication::config::AMConfigAppService *config_service) {
  if (!config_service) {
    return Err(EC::InvalidArg, "config service is null");
  }
  {
    std::lock_guard<std::mutex> lock(mtx_);
    config_service_ = config_service;
  }

  ECM reload_rcm = ReloadFromConfigService();
  if (!isok(reload_rcm)) {
    return reload_rcm;
  }

  {
    std::lock_guard<std::mutex> lock(mtx_);
    initialized_ = true;
  }
  return Ok();
}

ECM AMStyleService::ReloadFromConfigService() {
  AMApplication::config::AMConfigAppService *config_service = nullptr;
  {
    std::lock_guard<std::mutex> lock(mtx_);
    config_service = config_service_;
  }
  if (!config_service) {
    return Err(EC::ConfigNotInitialized, "config service is not bound");
  }

  AMStyleSnapshot snapshot = {};
  if (!config_service->Read(&snapshot)) {
    return Err(EC::ConfigLoadFailed, "failed to load style settings");
  }
  snapshot.Normalize();

  std::lock_guard<std::mutex> lock(mtx_);
  snapshot_ = std::move(snapshot);
  progress_bar_style_.reset();
  return Ok();
}

std::string
AMStyleService::ResolveInputStyleTag_(const std::string &style_name) const {
  const std::string trimmed = AMStr::Strip(style_name);
  if (trimmed.empty()) {
    return "";
  }

  auto it = snapshot_.input_highlight.find(trimmed);
  if (it != snapshot_.input_highlight.end()) {
    return NormalizeStyleTag_(it->second);
  }

  if (trimmed.rfind("Prompt.", 0) == 0) {
    const std::string shortcut_key = trimmed.substr(7);
    auto shortcut_it = snapshot_.cli_prompt.shortcut.find(shortcut_key);
    if (shortcut_it != snapshot_.cli_prompt.shortcut.end()) {
      return NormalizeStyleTag_(shortcut_it->second);
    }
  }
  return "";
}

std::string AMStyleService::NormalizeStyleTag_(const std::string &raw_tag) {
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
  return trimmed;
}

std::string AMStyleService::ApplyStyleTag_(const std::string &tag,
                                           const std::string &text) {
  if (tag.empty()) {
    return text;
  }
  return tag + text + "[/]";
}

std::string AMStyleService::Format(const std::string &ori_str,
                                   const std::string &style_name,
                                   const PathInfo *path_info) const {
  std::lock_guard<std::mutex> lock(mtx_);
  const std::string escaped = AMStr::BBCEscape(ori_str);

  if (!path_info) {
    return ApplyStyleTag_(ResolveInputStyleTag_(style_name), escaped);
  }

  std::string path_key = "regular";
  if (path_info->path.empty()) {
    path_key = "nonexistent";
  } else {
    switch (path_info->type) {
    case PathType::DIR:
      path_key = "dir";
      break;
    case PathType::SYMLINK:
      path_key = "symlink";
      break;
    case PathType::FILE:
      path_key = "regular";
      break;
    default:
      path_key = "otherspecial";
      break;
    }
  }

  auto path_it = snapshot_.path.find(path_key);
  if (path_it != snapshot_.path.end()) {
    const std::string path_tag = NormalizeStyleTag_(path_it->second);
    if (!path_tag.empty()) {
      return ApplyStyleTag_(path_tag, escaped);
    }
  }

  return ApplyStyleTag_(ResolveInputStyleTag_(style_name), escaped);
}

std::string AMStyleService::FormatUtf8Table(
    const std::vector<std::string> &keys,
    const std::vector<std::vector<std::string>> &rows) const {
  std::lock_guard<std::mutex> lock(mtx_);
  const size_t left =
      static_cast<size_t>(std::max<int64_t>(0, snapshot_.table.left_padding));
  const size_t right =
      static_cast<size_t>(std::max<int64_t>(0, snapshot_.table.right_padding));
  const size_t top =
      static_cast<size_t>(std::max<int64_t>(0, snapshot_.table.top_padding));
  const size_t bottom =
      static_cast<size_t>(std::max<int64_t>(0, snapshot_.table.bottom_padding));

  return AMStr::FormatUtf8Table(keys, rows, snapshot_.table.color, left, right,
                                top, bottom);
}

std::variant<indicators::Color, std::string>
AMStyleService::ParseProgressBarColor_(const std::string &value) {
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
  auto it = color_map.find(token);
  if (it == color_map.end()) {
    return indicators::Color::unspecified;
  }
  return it->second;
}

AMProgressBarStyle AMStyleService::BuildProgressBarStyle_() const {
  AMProgressBarStyle style{};
  const auto &cfg = snapshot_.progress_bar;
  style.bar_width = static_cast<size_t>(std::max<int64_t>(1, cfg.bar_width));
  style.width_offset = static_cast<int>(cfg.width_offset);
  style.start = cfg.lborder;
  style.end = cfg.rborder;
  style.fill = cfg.fill.empty() ? "█" : cfg.fill;
  style.lead = cfg.head.empty() ? "▓" : cfg.head;
  style.remainder = cfg.remain;
  style.color = ParseProgressBarColor_(cfg.color);
  style.show_percentage = cfg.show_percentage;
  style.show_elapsed_time = cfg.show_elapsed_time;
  style.show_remaining_time = cfg.show_remaining_time;
  return style;
}

AMProgressBar AMStyleService::CreateProgressBar(int64_t total_size,
                                                const std::string &prefix) {
  std::lock_guard<std::mutex> lock(mtx_);
  if (!progress_bar_style_) {
    progress_bar_style_ = BuildProgressBarStyle_();
  }
  return AMProgressBar(total_size, prefix, *progress_bar_style_);
}

std::string AMStyleService::ResolveCorePromptTemplate() const {
  std::lock_guard<std::mutex> lock(mtx_);
  return snapshot_.cli_prompt.prompt_template.core_prompt;
}

std::string AMStyleService::ResolveHistorySearchPrompt() const {
  std::lock_guard<std::mutex> lock(mtx_);
  return snapshot_.cli_prompt.prompt_template.history_search_prompt;
}

std::string AMStyleService::ResolveShortcutStyle(const std::string &key) const {
  std::lock_guard<std::mutex> lock(mtx_);
  auto it = snapshot_.cli_prompt.shortcut.find(key);
  if (it == snapshot_.cli_prompt.shortcut.end()) {
    return "";
  }
  return it->second;
}

AMStyleSnapshot AMStyleService::Snapshot() const {
  std::lock_guard<std::mutex> lock(mtx_);
  return snapshot_;
}
} // namespace AMInterface::style
