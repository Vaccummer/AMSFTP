#include "domain/style/StyleDomainService.hpp"

#include <algorithm>
#include <cctype>
#include <utility>

namespace AMDomain::style::service {
namespace {

[[nodiscard]] std::string_view TrimView_(std::string_view text) {
  size_t begin = 0;
  while (begin < text.size() &&
         std::isspace(static_cast<unsigned char>(text[begin]))) {
    ++begin;
  }
  size_t end = text.size();
  while (end > begin && std::isspace(static_cast<unsigned char>(text[end - 1]))) {
    --end;
  }
  return text.substr(begin, end - begin);
}

[[nodiscard]] std::string LowerTrim_(std::string_view text) {
  const std::string_view trimmed = TrimView_(text);
  std::string out(trimmed.begin(), trimmed.end());
  std::transform(out.begin(), out.end(), out.begin(),
                 [](unsigned char ch) -> char {
                   return static_cast<char>(std::tolower(ch));
                 });
  return out;
}

[[nodiscard]] bool NextToken_(std::string_view text, size_t *cursor,
                              std::string_view *token) {
  if (!cursor || !token) {
    return false;
  }
  size_t pos = *cursor;
  while (pos < text.size() && std::isspace(static_cast<unsigned char>(text[pos]))) {
    ++pos;
  }
  if (pos >= text.size()) {
    *cursor = pos;
    return false;
  }
  const size_t start = pos;
  while (pos < text.size() && !std::isspace(static_cast<unsigned char>(text[pos]))) {
    ++pos;
  }
  *cursor = pos;
  *token = text.substr(start, pos - start);
  return true;
}

} // namespace

bool IsHexColorString(std::string_view color) {
  const std::string_view text = TrimView_(color);
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

bool IsStyleString(std::string_view style) {
  const std::string_view trimmed = TrimView_(style);
  if (trimmed.size() < 3 || trimmed.front() != '[' || trimmed.back() != ']') {
    return false;
  }

  const std::string_view body = TrimView_(trimmed.substr(1, trimmed.size() - 2));
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

  if (!NextToken_(body, &cursor, &token)) {
    return false;
  }

  if (IsHexColorString(token)) {
    has_any = true;
    if (!NextToken_(body, &cursor, &token)) {
      return true;
    }
  }

  if (token == "on") {
    if (!NextToken_(body, &cursor, &token)) {
      return false;
    }
    if (!IsHexColorString(token)) {
      return false;
    }
    has_any = true;
    if (!NextToken_(body, &cursor, &token)) {
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
  } while (NextToken_(body, &cursor, &token));

  return has_any;
}

void NormalizeStyleToken(std::string *value, const std::string &fallback) {
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

void NormalizeCompleteMenu(CompleteMenuStyle *style) {
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

void NormalizeTable(TableStyle *style) {
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

void NormalizeProgressBar(ProgressBarStyle *style) {
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

void NormalizePromptTemplate(PromptTemplateStyle *style) {
  if (!style) {
    return;
  }
  const PromptTemplateStyle defaults = {};
  if (style->history_search_prompt.empty()) {
    style->history_search_prompt = defaults.history_search_prompt;
  }
}

void NormalizeCLIPromptShortcut(CLIPromptShortcutStyle *style) {
  if (!style) {
    return;
  }
  CLIPromptShortcutStyle normalized = {};
  for (const auto &[raw_key, raw_value] : *style) {
    const std::string key = LowerTrim_(raw_key);
    if (key.empty()) {
      continue;
    }
    std::string value = raw_value;
    NormalizeStyleToken(&value);
    normalized[key] = std::move(value);
  }
  *style = std::move(normalized);
}

void NormalizeCLIPrompt(CLIPromptStyle *style) {
  if (!style) {
    return;
  }
  NormalizeCLIPromptShortcut(&style->shortcut);
  NormalizePromptTemplate(&style->prompt_template);
}

void NormalizeInputHighlight(InputHighlightStyle *style) {
  if (!style) {
    return;
  }
  const InputHighlightStyle defaults = {};
  NormalizeStyleToken(&style->default_style, defaults.default_style);
  NormalizeStyleToken(&style->type_string, defaults.type_string);
  NormalizeStyleToken(&style->type_number, defaults.type_number);
  NormalizeStyleToken(&style->type_protocol, defaults.type_protocol);
  NormalizeStyleToken(&style->type_username, defaults.type_username);
  NormalizeStyleToken(&style->type_abort, defaults.type_abort);
  NormalizeStyleToken(&style->type_hostname, defaults.type_hostname);
  NormalizeStyleToken(&style->type_shell_cmd, defaults.type_shell_cmd);
  NormalizeStyleToken(&style->sign_escaped, defaults.sign_escaped);
  NormalizeStyleToken(&style->sign_bang, defaults.sign_bang);
  NormalizeStyleToken(&style->cli_command, defaults.cli_command);
  NormalizeStyleToken(&style->cli_unexpected, defaults.cli_unexpected);
  NormalizeStyleToken(&style->cli_module, defaults.cli_module);
  NormalizeStyleToken(&style->cli_option, defaults.cli_option);
  NormalizeStyleToken(&style->varname_public, defaults.varname_public);
  NormalizeStyleToken(&style->varname_private, defaults.varname_private);
  NormalizeStyleToken(&style->varname_zone, defaults.varname_zone);
  NormalizeStyleToken(&style->varname_nonexistent,
                      defaults.varname_nonexistent);
  NormalizeStyleToken(&style->varname_dollar, defaults.varname_dollar);
  NormalizeStyleToken(&style->varname_left_brace,
                      defaults.varname_left_brace);
  NormalizeStyleToken(&style->varname_right_brace,
                      defaults.varname_right_brace);
  NormalizeStyleToken(&style->varname_colon, defaults.varname_colon);
  NormalizeStyleToken(&style->varname_equal, defaults.varname_equal);
  NormalizeStyleToken(&style->varvalue, defaults.varvalue);
  NormalizeStyleToken(&style->nickname_ok, defaults.nickname_ok);
  NormalizeStyleToken(&style->nickname_at, defaults.nickname_at);
  NormalizeStyleToken(&style->nickname_disconnected,
                      defaults.nickname_disconnected);
  NormalizeStyleToken(&style->nickname_unestablished,
                      defaults.nickname_unestablished);
  NormalizeStyleToken(&style->nickname_nonexistent,
                      defaults.nickname_nonexistent);
  NormalizeStyleToken(&style->nickname_new_valid,
                      defaults.nickname_new_valid);
  NormalizeStyleToken(&style->nickname_new_invalid,
                      defaults.nickname_new_invalid);
  NormalizeStyleToken(&style->termname_ok, defaults.termname_ok);
  NormalizeStyleToken(&style->termname_at, defaults.termname_at);
  NormalizeStyleToken(&style->termname_disconnected,
                      defaults.termname_disconnected);
  NormalizeStyleToken(&style->termname_unestablished,
                      defaults.termname_unestablished);
  NormalizeStyleToken(&style->termname_nonexistent,
                      defaults.termname_nonexistent);
  NormalizeStyleToken(&style->channelname_ok, defaults.channelname_ok);
  NormalizeStyleToken(&style->channelname_disconnected,
                      defaults.channelname_disconnected);
  NormalizeStyleToken(&style->channelname_nonexistent,
                      defaults.channelname_nonexistent);
  NormalizeStyleToken(&style->channelname_new_valid,
                      defaults.channelname_new_valid);
  NormalizeStyleToken(&style->channelname_new_invalid,
                      defaults.channelname_new_invalid);
  NormalizeStyleToken(&style->attr_valid, defaults.attr_valid);
  NormalizeStyleToken(&style->attr_invalid, defaults.attr_invalid);
  if (style->type_shell_cmd.empty()) {
    style->type_shell_cmd = style->cli_command;
  }
}

void NormalizeValueQueryHighlight(ValueQueryHighlightStyle *style) {
  if (!style) {
    return;
  }
  const ValueQueryHighlightStyle defaults = {};
  NormalizeStyleToken(&style->valid_value, defaults.valid_value);
  NormalizeStyleToken(&style->invalid_value, defaults.invalid_value);
  NormalizeStyleToken(&style->prompt_style, defaults.prompt_style);
}

void NormalizeInternalStyle(InternalStyle *style) {
  if (!style) {
    return;
  }
  const InternalStyle defaults = {};
  NormalizeStyleToken(&style->inline_hint, defaults.inline_hint);
  NormalizeStyleToken(&style->default_prompt, defaults.default_prompt);
}

void NormalizePathHighlight(PathHighlightStyle *style) {
  if (!style) {
    return;
  }
  const PathHighlightStyle defaults = {};
  NormalizeStyleToken(&style->default_style, defaults.default_style);
  NormalizeStyleToken(&style->tree_root, defaults.tree_root);
  NormalizeStyleToken(&style->tree_node, defaults.tree_node);
  NormalizeStyleToken(&style->tree_leaf, defaults.tree_leaf);
  NormalizeStyleToken(&style->type_dir, defaults.type_dir);
  NormalizeStyleToken(&style->type_regular, defaults.type_regular);
  NormalizeStyleToken(&style->type_symlink, defaults.type_symlink);
  NormalizeStyleToken(&style->type_otherspecial, defaults.type_otherspecial);
  NormalizeStyleToken(&style->type_nonexistent, defaults.type_nonexistent);
  if (style->default_style.empty()) {
    style->default_style = style->type_regular;
  }
  if (style->type_regular.empty()) {
    style->type_regular = style->default_style;
  }
  if (style->tree_node.empty()) {
    style->tree_node = style->type_dir;
  }
  if (style->tree_leaf.empty()) {
    style->tree_leaf = style->type_regular;
  }
}

void NormalizeSystemInfo(SystemInfoStyle *style) {
  if (!style) {
    return;
  }
  const SystemInfoStyle defaults = {};
  NormalizeStyleToken(&style->info, defaults.info);
  NormalizeStyleToken(&style->success, defaults.success);
  NormalizeStyleToken(&style->error, defaults.error);
  NormalizeStyleToken(&style->warning, defaults.warning);
}

void NormalizeStyleConfig(StyleConfig *config) {
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

void NormalizeStyleConfigArg(StyleConfigArg *arg) {
  if (!arg) {
    return;
  }
  NormalizeStyleConfig(&arg->style);
}

} // namespace AMDomain::style::service

