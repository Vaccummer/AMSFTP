#pragma once
#include <cstdint>
#include <map>
#include <string>

namespace AMDomain::style {

struct CompleteMenuStyle {
  std::string item_select_sign = ">";
  std::string order_num_style = "";
  std::string help_style = "";
};

struct ProgressBarStyle {
  std::string prefix_template = "{$filename}";
  std::string bar_template =
      "{$progressbar} {$percentage}%!{$transferred}/{$total} "
      "\\[{$elapsed}<{$remaining} {$speed}\\]";
  int64_t refresh_interval_ms = 300;
  int64_t prefix_fixed_width = 20;
  struct Bar {
    std::string fill = "█";
    std::string lead = "▓";
    std::string remaining = " ";
    int64_t bar_width = 30;
  } bar = {};
  struct Speed {
    int64_t speed_num_fixed_width = 7;
    int64_t speed_num_max_float_digits = 1;
    int64_t speed_window_ms = 7000;
  } speed = {};
  struct Size {
    int64_t totol_size_fixed_width = 5;
    int64_t totol_size_max_float_digits = 1;
    int64_t transferred_size_fixed_width = 5;
    int64_t transferred_size_max_float_digits = 1;
  } size = {};
};

struct PromptTemplateStyle {
  std::string core_prompt = "";
  std::string history_search_prompt = "history search";
};

using CLIPromptShortcutStyle = std::map<std::string, std::string>;

struct CLIPromptIconsStyle {
  std::string default_icon = "💻";
  std::string windows = "";
  std::string linux = "";
  std::string macos = "";
  std::string freebsd = "";
  std::string unix = "";
};

struct CLIPromptStyle {
  CLIPromptShortcutStyle shortcut = {};
  CLIPromptIconsStyle icons = {};
  PromptTemplateStyle prompt_template = {};
};

struct InputHighlightStyle {
  std::string default_style = "";
  std::string type_string = "";
  std::string type_error = "";
  std::string type_number = "";
  std::string type_protocol = "";
  std::string type_username = "";
  std::string type_abort = "";
  std::string type_hostname = "";
  std::string type_shell_cmd = "";
  std::string type_table_skeleton = "";
  std::string sign_escaped = "";
  std::string sign_bang = "";
  std::string cli_command = "";
  std::string cli_unexpected = "";
  std::string cli_module = "";
  std::string cli_option = "";
  std::string varname_public = "";
  std::string varname_private = "";
  std::string varname_zone = "";
  std::string varname_nonexistent = "";
  std::string varname_dollar = "";
  std::string varname_left_brace = "";
  std::string varname_right_brace = "";
  std::string varname_colon = "";
  std::string varname_equal = "";
  std::string varvalue = "";
  std::string nickname_ok = "";
  std::string nickname_at = "";
  std::string nickname_disconnected = "";
  std::string nickname_unestablished = "";
  std::string nickname_nonexistent = "";
  std::string nickname_new_valid = "";
  std::string nickname_new_invalid = "";
  std::string termname_ok = "";
  std::string termname_at = "";
  std::string termname_disconnected = "";
  std::string termname_nonexistent = "";
  std::string termname_new_valid = "";
  std::string termname_new_invalid = "";
  std::string attr_valid = "";
  std::string attr_invalid = "";
};

struct ValueQueryHighlightStyle {
  std::string valid_value = "";
  std::string invalid_value = "";
};

struct InternalStyle {
  std::string inline_hint = "";
  std::string default_prompt = "";
};

struct PathHighlightStyle {
  std::string default_style = "";
  std::string tree_root = "";
  std::string tree_node = "";
  std::string tree_leaf = "";
  std::string type_dir = "";
  std::string type_regular = "";
  std::string type_symlink = "";
  std::string type_otherspecial = "";
  std::string type_nonexistent = "";
  std::string find_pattern = "";
};

struct TerminalStyle {
  std::string banner_template =
      "[#5e63b6 b]Welcome to use CLIPrompt![/]\n";
};

struct StyleConfig {
  CompleteMenuStyle complete_menu = {};
  ProgressBarStyle progress_bar = {};
  CLIPromptStyle cli_prompt = {};
  InputHighlightStyle common = {};
  ValueQueryHighlightStyle value_query_highlight = {};
  InternalStyle internal_style = {};
  PathHighlightStyle path = {};
  TerminalStyle terminal = {};
};

struct StyleConfigArg {
  StyleConfig style = {};
};

} // namespace AMDomain::style
