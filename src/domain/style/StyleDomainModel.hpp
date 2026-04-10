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

struct TableStyle {
  std::string color = "#00adb5";
  int64_t left_padding = 1;
  int64_t right_padding = 1;
  int64_t top_padding = 0;
  int64_t bottom_padding = 0;
  int64_t refresh_interval_ms = 300;
  int64_t speed_window_size = 25;
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
  std::string windows = "";
  std::string linux = "";
  std::string macos = "";
};

struct CLIPromptNamedStyles {
  std::string un = "";
  std::string at = "";
  std::string hn = "";
  std::string en = "";
  std::string nn = "";
  std::string cwd = "";
  std::string ds = "";
  std::string white = "";
};

struct CLIPromptStyle {
  // deprecated: use named_styles
  CLIPromptShortcutStyle shortcut = {};
  CLIPromptIconsStyle icons = {};
  CLIPromptNamedStyles named_styles = {};
  PromptTemplateStyle prompt_template = {};
};

struct InputHighlightStyle {
  std::string protocol = "";
  std::string abort = "";
  std::string common = "";
  std::string module = "";
  std::string command = "";
  std::string illegal_command = "";
  std::string option = "";
  std::string string = "";
  std::string public_varname = "";
  std::string private_varname = "";
  std::string nonexistent_varname = "";
  std::string varvalue = "";
  std::string nickname = "";
  std::string disconnected_nickname = "";
  std::string unestablished_nickname = "";
  std::string nonexistent_nickname = "";
  std::string valid_new_nickname = "";
  std::string invalid_new_nickname = "";
  std::string builtin_arg = "";
  std::string nonexistent_builtin_arg = "";
  std::string username = "";
  std::string atsign = "";
  std::string dollarsign = "";
  std::string equalsign = "";
  std::string escapedsign = "";
  std::string bangsign = "";
  std::string shell_cmd = "";
  std::string number = "";
  std::string timestamp = "";
  std::string path_like = "";
  std::string termname = "";
  std::string disconnected_termname = "";
  std::string unestablished_termname = "";
  std::string nonexistent_termname = "";
  std::string channelname = "";
  std::string disconnected_channelname = "";
  std::string nonexistent_channelname = "";
  std::string valid_new_channelname = "";
  std::string invalid_new_channelname = "";
};

struct ValueQueryHighlightStyle {
  std::string valid_value = "";
  std::string invalid_value = "";
  std::string prompt_style = "";
};

struct InternalStyle {
  std::string inline_hint = "";
  std::string default_prompt = "";
};

struct PathHighlightStyle {
  std::string cwd = "";
  std::string path_str = "";
  std::string root = "";
  std::string node_dir_name = "";
  std::string filename = "";
  std::string dir = "";
  std::string regular = "";
  std::string symlink = "";
  std::string otherspecial = "";
  std::string nonexistent = "";
};

struct SystemInfoStyle {
  std::string info = "";
  std::string success = "";
  std::string error = "";
  std::string warning = "";
};

struct StyleConfig {
  CompleteMenuStyle complete_menu = {};
  TableStyle table = {};
  ProgressBarStyle progress_bar = {};
  CLIPromptStyle cli_prompt = {};
  InputHighlightStyle common = {};
  ValueQueryHighlightStyle value_query_highlight = {};
  InternalStyle internal_style = {};
  PathHighlightStyle path = {};
  SystemInfoStyle system_info = {};
};

struct StyleConfigArg {
  StyleConfig style = {};
};

} // namespace AMDomain::style
