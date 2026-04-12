#pragma once

#include "domain/style/StyleDomainModel.hpp"
#include <algorithm>
#include <cctype>
#include <limits>
#include <string_view>
#include <utility>

namespace AMDomain::style::services {
namespace detail {
[[nodiscard]] inline int64_t ClampInt64(int64_t value, int64_t min_value,
                                        int64_t max_value) {
  if (min_value > max_value) {
    std::swap(min_value, max_value);
  }
  return std::max<int64_t>(min_value, std::min<int64_t>(value, max_value));
}

[[nodiscard]] inline std::string_view TrimView(std::string_view text) {
  size_t begin = 0;
  while (begin < text.size() &&
         std::isspace(static_cast<unsigned char>(text[begin]))) {
    ++begin;
  }
  size_t end = text.size();
  while (end > begin &&
         std::isspace(static_cast<unsigned char>(text[end - 1]))) {
    --end;
  }
  return text.substr(begin, end - begin);
}

[[nodiscard]] inline std::string LowerTrim(std::string_view text) {
  const std::string_view trimmed = TrimView(text);
  std::string out(trimmed.begin(), trimmed.end());
  std::transform(out.begin(), out.end(), out.begin(),
                 [](unsigned char ch) -> char {
                   return static_cast<char>(std::tolower(ch));
                 });
  return out;
}

[[nodiscard]] inline bool NextToken(std::string_view text, size_t *cursor,
                                    std::string_view *token) {
  if (!cursor || !token) {
    return false;
  }
  size_t pos = *cursor;
  while (pos < text.size() &&
         std::isspace(static_cast<unsigned char>(text[pos]))) {
    ++pos;
  }
  if (pos >= text.size()) {
    *cursor = pos;
    return false;
  }
  const size_t start = pos;
  while (pos < text.size() &&
         !std::isspace(static_cast<unsigned char>(text[pos]))) {
    ++pos;
  }
  *cursor = pos;
  *token = text.substr(start, pos - start);
  return true;
}
} // namespace detail

[[nodiscard]] inline bool IsHexColorString(std::string_view color) {
  const std::string_view text = detail::TrimView(color);
  if (text.size() != 7 || text.front() != '#') {
    return false;
  }
  for (size_t i = 1; i < text.size(); ++i) {
    const unsigned char ch = static_cast<unsigned char>(text[i]);
    if (!std::isxdigit(ch)) {
      return false;
    }
  }
  return true;
}

[[nodiscard]] inline bool IsStyleString(std::string_view style) {
  const std::string_view trimmed = detail::TrimView(style);
  if (trimmed.size() < 3 || trimmed.front() != '[' || trimmed.back() != ']') {
    return false;
  }

  const std::string_view body =
      detail::TrimView(trimmed.substr(1, trimmed.size() - 2));
  if (body.empty()) {
    return false;
  }

  size_t cursor = 0;
  std::string_view token;
  bool has_any = false;
  bool flag_b = false;
  bool flag_i = false;
  bool flag_u = false;
  bool flag_s = false;

  if (!detail::NextToken(body, &cursor, &token)) {
    return false;
  }

  if (IsHexColorString(token)) {
    has_any = true;
    if (!detail::NextToken(body, &cursor, &token)) {
      return true;
    }
  }

  if (token == "on") {
    if (!detail::NextToken(body, &cursor, &token)) {
      return false;
    }
    if (!IsHexColorString(token)) {
      return false;
    }
    has_any = true;
    if (!detail::NextToken(body, &cursor, &token)) {
      return true;
    }
  }

  do {
    if (token.size() != 1) {
      return false;
    }
    const char lower = static_cast<char>(
        std::tolower(static_cast<unsigned char>(token.front())));
    if (lower == 'b') {
      if (flag_b) {
        return false;
      }
      flag_b = true;
      has_any = true;
      continue;
    }
    if (lower == 'i') {
      if (flag_i) {
        return false;
      }
      flag_i = true;
      has_any = true;
      continue;
    }
    if (lower == 'u') {
      if (flag_u) {
        return false;
      }
      flag_u = true;
      has_any = true;
      continue;
    }
    if (lower == 's') {
      if (flag_s) {
        return false;
      }
      flag_s = true;
      has_any = true;
      continue;
    }
    return false;
  } while (detail::NextToken(body, &cursor, &token));

  return has_any;
}

inline void NormalizeStyleToken(std::string *value,
                                const std::string &fallback = "") {
  if (!value) {
    return;
  }
  if (value->empty()) {
    *value = fallback;
    return;
  }
  if (!IsStyleString(*value)) {
    *value = fallback;
  }
}

inline void NormalizeCompleteMenu(CompleteMenuStyle *style) {
  if (!style) {
    return;
  }
  const CompleteMenuStyle defaults = {};
  if (style->item_select_sign.empty()) {
    style->item_select_sign = defaults.item_select_sign;
  }
  NormalizeStyleToken(&style->order_num_style, defaults.order_num_style);
  NormalizeStyleToken(&style->help_style, defaults.help_style);
}

inline void NormalizeTable(TableStyle *style) {
  if (!style) {
    return;
  }
  const TableStyle defaults = {};
  style->left_padding = std::max<int64_t>(0, style->left_padding);
  style->right_padding = std::max<int64_t>(0, style->right_padding);
  style->top_padding = std::max<int64_t>(0, style->top_padding);
  style->bottom_padding = std::max<int64_t>(0, style->bottom_padding);
  style->refresh_interval_ms = std::max<int64_t>(1, style->refresh_interval_ms);
  style->speed_window_size = std::max<int64_t>(1, style->speed_window_size);
  if (!IsHexColorString(style->color)) {
    style->color = defaults.color;
  }
}

inline void NormalizeProgressBar(ProgressBarStyle *style) {
  if (!style) {
    return;
  }
  const ProgressBarStyle defaults = {};
  style->refresh_interval_ms = std::max<int64_t>(1, style->refresh_interval_ms);
  style->prefix_fixed_width = std::max<int64_t>(0, style->prefix_fixed_width);
  style->bar.bar_width = std::max<int64_t>(1, style->bar.bar_width);
  style->speed.speed_num_fixed_width =
      std::max<int64_t>(0, style->speed.speed_num_fixed_width);
  style->speed.speed_num_max_float_digits =
      std::max<int64_t>(0, style->speed.speed_num_max_float_digits);
  style->speed.speed_window_ms = std::max<int64_t>(1, style->speed.speed_window_ms);
  style->size.totol_size_fixed_width =
      std::max<int64_t>(0, style->size.totol_size_fixed_width);
  style->size.totol_size_max_float_digits =
      std::max<int64_t>(0, style->size.totol_size_max_float_digits);
  style->size.transferred_size_fixed_width =
      std::max<int64_t>(0, style->size.transferred_size_fixed_width);
  style->size.transferred_size_max_float_digits =
      std::max<int64_t>(0, style->size.transferred_size_max_float_digits);
  if (style->prefix_template.empty()) {
    style->prefix_template = defaults.prefix_template;
  }
  if (style->bar_template.empty()) {
    style->bar_template = defaults.bar_template;
  }
  if (style->bar.fill.empty()) {
    style->bar.fill = defaults.bar.fill;
  }
  if (style->bar.lead.empty()) {
    style->bar.lead = defaults.bar.lead;
  }
  if (style->bar.remaining.empty()) {
    style->bar.remaining = defaults.bar.remaining;
  }
}

inline void NormalizePromptTemplate(PromptTemplateStyle *style) {
  if (!style) {
    return;
  }
  const PromptTemplateStyle defaults = {};
  if (style->history_search_prompt.empty()) {
    style->history_search_prompt = defaults.history_search_prompt;
  }
}

inline void NormalizeCLIPromptShortcut(CLIPromptShortcutStyle *style) {
  if (!style) {
    return;
  }
  CLIPromptShortcutStyle normalized = {};
  for (const auto &[raw_key, raw_value] : *style) {
    const std::string key = detail::LowerTrim(raw_key);
    if (key.empty()) {
      continue;
    }
    std::string value = raw_value;
    NormalizeStyleToken(&value);
    normalized[key] = std::move(value);
  }
  *style = std::move(normalized);
}

inline void NormalizeCLIPromptNamedStyles(CLIPromptNamedStyles *style) {
  if (!style) {
    return;
  }
  const CLIPromptNamedStyles defaults = {};
  NormalizeStyleToken(&style->un, defaults.un);
  NormalizeStyleToken(&style->at, defaults.at);
  NormalizeStyleToken(&style->hn, defaults.hn);
  NormalizeStyleToken(&style->en, defaults.en);
  NormalizeStyleToken(&style->nn, defaults.nn);
  NormalizeStyleToken(&style->cwd, defaults.cwd);
  NormalizeStyleToken(&style->ds, defaults.ds);
  NormalizeStyleToken(&style->white, defaults.white);
}

inline void NormalizeCLIPrompt(CLIPromptStyle *style) {
  if (!style) {
    return;
  }
  NormalizeCLIPromptShortcut(&style->shortcut);
  NormalizeCLIPromptNamedStyles(&style->named_styles);
  NormalizePromptTemplate(&style->prompt_template);
}

inline void NormalizeInputHighlight(InputHighlightStyle *style) {
  if (!style) {
    return;
  }
  const InputHighlightStyle defaults = {};
  NormalizeStyleToken(&style->protocol, defaults.protocol);
  NormalizeStyleToken(&style->abort, defaults.abort);
  NormalizeStyleToken(&style->common, defaults.common);
  NormalizeStyleToken(&style->module, defaults.module);
  NormalizeStyleToken(&style->command, defaults.command);
  NormalizeStyleToken(&style->unexpected, defaults.unexpected);
  NormalizeStyleToken(&style->illegal_command, defaults.illegal_command);
  NormalizeStyleToken(&style->option, defaults.option);
  NormalizeStyleToken(&style->string, defaults.string);
  NormalizeStyleToken(&style->public_varname, defaults.public_varname);
  NormalizeStyleToken(&style->private_varname, defaults.private_varname);
  NormalizeStyleToken(&style->nonexistent_varname,
                      defaults.nonexistent_varname);
  NormalizeStyleToken(&style->varvalue, defaults.varvalue);
  NormalizeStyleToken(&style->nickname, defaults.nickname);
  NormalizeStyleToken(&style->disconnected_nickname,
                      defaults.disconnected_nickname);
  NormalizeStyleToken(&style->unestablished_nickname,
                      defaults.unestablished_nickname);
  NormalizeStyleToken(&style->nonexistent_nickname,
                      defaults.nonexistent_nickname);
  NormalizeStyleToken(&style->valid_new_nickname, defaults.valid_new_nickname);
  NormalizeStyleToken(&style->invalid_new_nickname,
                      defaults.invalid_new_nickname);
  NormalizeStyleToken(&style->builtin_arg, defaults.builtin_arg);
  NormalizeStyleToken(&style->nonexistent_builtin_arg,
                      defaults.nonexistent_builtin_arg);
  NormalizeStyleToken(&style->username, defaults.username);
  NormalizeStyleToken(&style->atsign, defaults.atsign);
  NormalizeStyleToken(&style->dollarsign, defaults.dollarsign);
  NormalizeStyleToken(&style->equalsign, defaults.equalsign);
  NormalizeStyleToken(&style->escapedsign, defaults.escapedsign);
  NormalizeStyleToken(&style->bangsign, defaults.bangsign);
  NormalizeStyleToken(&style->shell_cmd, defaults.shell_cmd);
  NormalizeStyleToken(&style->number, defaults.number);
  NormalizeStyleToken(&style->timestamp, defaults.timestamp);
  NormalizeStyleToken(&style->path_like, defaults.path_like);
  NormalizeStyleToken(&style->termname, defaults.termname);
  NormalizeStyleToken(&style->disconnected_termname,
                      defaults.disconnected_termname);
  NormalizeStyleToken(&style->unestablished_termname,
                      defaults.unestablished_termname);
  NormalizeStyleToken(&style->nonexistent_termname,
                      defaults.nonexistent_termname);
  NormalizeStyleToken(&style->channelname, defaults.channelname);
  NormalizeStyleToken(&style->disconnected_channelname,
                      defaults.disconnected_channelname);
  NormalizeStyleToken(&style->nonexistent_channelname,
                      defaults.nonexistent_channelname);
  NormalizeStyleToken(&style->valid_new_channelname,
                      defaults.valid_new_channelname);
  NormalizeStyleToken(&style->invalid_new_channelname,
                      defaults.invalid_new_channelname);
  if (style->unexpected.empty()) {
    style->unexpected = style->illegal_command;
  }
  if (style->illegal_command.empty()) {
    style->illegal_command = style->unexpected;
  }
}

inline void NormalizeValueQueryHighlight(ValueQueryHighlightStyle *style) {
  if (!style) {
    return;
  }
  const ValueQueryHighlightStyle defaults = {};
  NormalizeStyleToken(&style->valid_value, defaults.valid_value);
  NormalizeStyleToken(&style->invalid_value, defaults.invalid_value);
  NormalizeStyleToken(&style->prompt_style, defaults.prompt_style);
}

inline void NormalizeInternalStyle(InternalStyle *style) {
  if (!style) {
    return;
  }
  const InternalStyle defaults = {};
  NormalizeStyleToken(&style->inline_hint, defaults.inline_hint);
  NormalizeStyleToken(&style->default_prompt, defaults.default_prompt);
}

inline void NormalizePathHighlight(PathHighlightStyle *style) {
  if (!style) {
    return;
  }
  const PathHighlightStyle defaults = {};
  NormalizeStyleToken(&style->cwd, defaults.cwd);
  NormalizeStyleToken(&style->path_str, defaults.path_str);
  NormalizeStyleToken(&style->root, defaults.root);
  NormalizeStyleToken(&style->node_dir_name, defaults.node_dir_name);
  NormalizeStyleToken(&style->filename, defaults.filename);
  NormalizeStyleToken(&style->dir, defaults.dir);
  NormalizeStyleToken(&style->regular, defaults.regular);
  NormalizeStyleToken(&style->symlink, defaults.symlink);
  NormalizeStyleToken(&style->otherspecial, defaults.otherspecial);
  NormalizeStyleToken(&style->nonexistent, defaults.nonexistent);
}

inline void NormalizeSystemInfo(SystemInfoStyle *style) {
  if (!style) {
    return;
  }
  const SystemInfoStyle defaults = {};
  NormalizeStyleToken(&style->info, defaults.info);
  NormalizeStyleToken(&style->success, defaults.success);
  NormalizeStyleToken(&style->error, defaults.error);
  NormalizeStyleToken(&style->warning, defaults.warning);
}

inline void NormalizeStyleConfig(StyleConfig *config) {
  if (!config) {
    return;
  }
  NormalizeCompleteMenu(&config->complete_menu);
  NormalizeTable(&config->table);
  NormalizeProgressBar(&config->progress_bar);
  NormalizeCLIPrompt(&config->cli_prompt);
  NormalizeInputHighlight(&config->common);
  NormalizeValueQueryHighlight(&config->value_query_highlight);
  NormalizeInternalStyle(&config->internal_style);
  NormalizePathHighlight(&config->path);
  NormalizeSystemInfo(&config->system_info);
}

inline void NormalizeStyleConfigArg(StyleConfigArg *arg) {
  if (!arg) {
    return;
  }
  NormalizeStyleConfig(&arg->style);
}
} // namespace AMDomain::style::services
