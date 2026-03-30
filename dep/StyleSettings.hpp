#pragma once

#include <cstdint>
#include <map>
#include <string>

namespace AMApplication::config {
/**
 * @brief Typed arguments for `Style.CompleteMenu`.
 */
struct AMStyleCompleteMenuArgs {
  int64_t maxnum = 999;
  int64_t maxrows_perpage = 5;
  std::string item_select_sign = ">";
  bool number_pick = false;
  bool auto_fillin = false;
  std::string order_num_style = "";
  std::string help_style = "";
  int64_t complete_delay_ms = 100;
  int64_t async_workers = 2;

  /**
   * @brief Normalize and clamp fields to safe runtime values.
   */
  void Normalize();
};

/**
 * @brief Typed arguments for `Style.Table`.
 */
struct AMStyleTableArgs {
  std::string color = "#00adb5";
  int64_t left_padding = 1;
  int64_t right_padding = 1;
  int64_t top_padding = 0;
  int64_t bottom_padding = 0;
  int64_t refresh_interval_ms = 300;
  int64_t speed_window_size = 25;

  /**
   * @brief Normalize and clamp fields to safe runtime values.
   */
  void Normalize();
};

/**
 * @brief Typed arguments for `Style.ProgressBar`.
 */
struct AMStyleProgressBarArgs {
  std::string start = "";
  std::string end = "";
  std::string fill = "█";
  std::string lead = "▓";
  std::string remaining = " ";
  std::string color = "#08d9d6";
  int64_t refresh_interval_ms = 300;
  int64_t speed_window_size = 25;
  int64_t bar_width = 10;
  int64_t width_offset = 12;
  bool show_percentage = true;
  bool show_elapsed_time = true;
  bool show_remaining_time = true;

  /**
   * @brief Normalize and clamp fields to safe runtime values.
   */
  void Normalize();
};

/**
 * @brief Typed prompt template fields under `Style.CLIPrompt.template`.
 */
struct AMStylePromptTemplateArgs {
  std::string core_prompt = "";
  std::string history_search_prompt = "history search";
};

/**
 * @brief Typed arguments for `Style.CLIPrompt`.
 */
struct AMStyleCLIPromptArgs {
  std::map<std::string, std::string> shortcut;
  std::map<std::string, std::string> icons;
  std::map<std::string, std::string> named_styles;
  AMStylePromptTemplateArgs prompt_template{};
};

/**
 * @brief Full typed snapshot for `Settings.Style`.
 */
struct AMStyleSnapshot {
  AMStyleCompleteMenuArgs complete_menu{};
  AMStyleTableArgs table{};
  AMStyleProgressBarArgs progress_bar{};
  AMStyleCLIPromptArgs cli_prompt{};
  std::map<std::string, std::string> input_highlight;
  std::map<std::string, std::string> value_query_highlight;
  std::map<std::string, std::string> internal_style;
  std::map<std::string, std::string> path;
  std::map<std::string, std::string> system_info;

  /**
   * @brief Normalize and clamp fields to safe runtime values.
   */
  void Normalize();
};
} // namespace AMApplication::config
