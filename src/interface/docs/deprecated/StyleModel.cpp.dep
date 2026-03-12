#include "interface/style/StyleModel.hpp"

#include "foundation/tools/string.hpp"
#include <algorithm>
#include <limits>
#include <utility>

namespace {
using Json = nlohmann::ordered_json;

/**
 * @brief Read one object member as a typed value when possible.
 */
template <typename T>
bool ReadField_(const Json &jsond, const std::string &key, T *out) {
  if (!out || !jsond.is_object()) {
    return false;
  }
  auto it = jsond.find(key);
  if (it == jsond.end()) {
    return false;
  }
  Json root = Json::object();
  root[key] = *it;
  return AMJson::QueryKey(root, {key}, out);
}

/**
 * @brief Build extras object by removing known keys from an input object.
 */
Json CollectExtras_(const Json &jsond, const std::vector<std::string> &known) {
  if (!jsond.is_object()) {
    return Json::object();
  }
  Json extras = Json::object();
  for (auto it = jsond.begin(); it != jsond.end(); ++it) {
    if (std::find(known.begin(), known.end(), it.key()) != known.end()) {
      continue;
    }
    extras[it.key()] = it.value();
  }
  return extras;
}

/**
 * @brief Read string-valued map from one JSON object.
 */
std::map<std::string, std::string> ReadStringMap_(
    const Json &jsond, bool lowercase_keys = false) {
  std::map<std::string, std::string> out;
  if (!jsond.is_object()) {
    return out;
  }
  for (auto it = jsond.begin(); it != jsond.end(); ++it) {
    if (!it.value().is_string()) {
      continue;
    }
    std::string key = it.key();
    if (lowercase_keys) {
      key = AMStr::lowercase(key);
    }
    out[key] = it.value().get<std::string>();
  }
  return out;
}

/**
 * @brief Convert one string map to JSON object.
 */
Json DumpStringMap_(const std::map<std::string, std::string> &mapd) {
  Json out = Json::object();
  for (const auto &pair : mapd) {
    out[pair.first] = pair.second;
  }
  return out;
}

/**
 * @brief Clamp signed integer into inclusive range.
 */
int64_t ClampInt64_(int64_t value, int64_t min_value, int64_t max_value) {
  if (min_value > max_value) {
    std::swap(min_value, max_value);
  }
  if (value < min_value) {
    return min_value;
  }
  if (value > max_value) {
    return max_value;
  }
  return value;
}
} // namespace

namespace AMInterface::style {
/**
 * @brief Load complete-menu arguments from JSON.
 */
void AMStyleCompleteMenuArgs::LoadFromJson(const Json &jsond) {
  if (!jsond.is_object()) {
    return;
  }
  (void)ReadField_(jsond, "maxnum", &maxnum);
  (void)ReadField_(jsond, "maxrows_perpage", &maxrows_perpage);
  (void)ReadField_(jsond, "item_select_sign", &item_select_sign);
  (void)ReadField_(jsond, "number_pick", &number_pick);
  (void)ReadField_(jsond, "auto_fillin", &auto_fillin);
  (void)ReadField_(jsond, "order_num_style", &order_num_style);
  (void)ReadField_(jsond, "help_style", &help_style);
  (void)ReadField_(jsond, "complete_delay_ms", &complete_delay_ms);
  extras = CollectExtras_(jsond, {"maxnum", "maxrows_perpage", "item_select_sign",
                                  "number_pick", "auto_fillin",
                                  "order_num_style", "help_style",
                                  "complete_delay_ms"});
}

/**
 * @brief Serialize complete-menu arguments to JSON.
 */
Json AMStyleCompleteMenuArgs::ToJson() const {
  Json out = extras.is_object() ? extras : Json::object();
  out["maxnum"] = maxnum;
  out["maxrows_perpage"] = maxrows_perpage;
  out["item_select_sign"] = item_select_sign;
  out["number_pick"] = number_pick;
  out["auto_fillin"] = auto_fillin;
  out["order_num_style"] = order_num_style;
  out["help_style"] = help_style;
  out["complete_delay_ms"] = complete_delay_ms;
  return out;
}

/**
 * @brief Clamp complete-menu arguments into runtime-safe range.
 */
void AMStyleCompleteMenuArgs::Normalize() {
  maxnum = std::max<int64_t>(1, maxnum);
  maxrows_perpage = std::max<int64_t>(1, maxrows_perpage);
  complete_delay_ms =
      ClampInt64_(complete_delay_ms, 0, std::numeric_limits<int64_t>::max());
}

/**
 * @brief Load table arguments from JSON.
 */
void AMStyleTableArgs::LoadFromJson(const Json &jsond) {
  if (!jsond.is_object()) {
    return;
  }
  (void)ReadField_(jsond, "color", &color);
  (void)ReadField_(jsond, "left_padding", &left_padding);
  (void)ReadField_(jsond, "right_padding", &right_padding);
  (void)ReadField_(jsond, "top_padding", &top_padding);
  (void)ReadField_(jsond, "bottom_padding", &bottom_padding);
  (void)ReadField_(jsond, "refresh_interval_ms", &refresh_interval_ms);
  (void)ReadField_(jsond, "speed_window_size", &speed_window_size);
  extras = CollectExtras_(jsond, {"color", "left_padding", "right_padding",
                                  "top_padding", "bottom_padding",
                                  "refresh_interval_ms", "speed_window_size"});
}

/**
 * @brief Serialize table arguments to JSON.
 */
Json AMStyleTableArgs::ToJson() const {
  Json out = extras.is_object() ? extras : Json::object();
  out["color"] = color;
  out["left_padding"] = left_padding;
  out["right_padding"] = right_padding;
  out["top_padding"] = top_padding;
  out["bottom_padding"] = bottom_padding;
  out["refresh_interval_ms"] = refresh_interval_ms;
  out["speed_window_size"] = speed_window_size;
  return out;
}

/**
 * @brief Clamp table arguments into runtime-safe range.
 */
void AMStyleTableArgs::Normalize() {
  left_padding = std::max<int64_t>(0, left_padding);
  right_padding = std::max<int64_t>(0, right_padding);
  top_padding = std::max<int64_t>(0, top_padding);
  bottom_padding = std::max<int64_t>(0, bottom_padding);
  refresh_interval_ms = std::max<int64_t>(1, refresh_interval_ms);
  speed_window_size = std::max<int64_t>(1, speed_window_size);
}

/**
 * @brief Load progress-bar arguments from JSON.
 */
void AMStyleProgressBarArgs::LoadFromJson(const Json &jsond) {
  if (!jsond.is_object()) {
    return;
  }
  (void)ReadField_(jsond, "lborder", &lborder);
  (void)ReadField_(jsond, "rborder", &rborder);
  (void)ReadField_(jsond, "fill", &fill);
  (void)ReadField_(jsond, "head", &head);
  (void)ReadField_(jsond, "remain", &remain);
  (void)ReadField_(jsond, "color", &color);
  (void)ReadField_(jsond, "refresh_interval_ms", &refresh_interval_ms);
  (void)ReadField_(jsond, "speed_window_size", &speed_window_size);
  (void)ReadField_(jsond, "bar_width", &bar_width);
  (void)ReadField_(jsond, "width_offset", &width_offset);
  (void)ReadField_(jsond, "show_percentage", &show_percentage);
  (void)ReadField_(jsond, "show_elapsed_time", &show_elapsed_time);
  (void)ReadField_(jsond, "show_remaining_time", &show_remaining_time);
  extras = CollectExtras_(jsond, {"lborder", "rborder", "fill", "head",
                                  "remain", "color", "refresh_interval_ms",
                                  "speed_window_size", "bar_width",
                                  "width_offset", "show_percentage",
                                  "show_elapsed_time", "show_remaining_time"});
}

/**
 * @brief Serialize progress-bar arguments to JSON.
 */
Json AMStyleProgressBarArgs::ToJson() const {
  Json out = extras.is_object() ? extras : Json::object();
  out["lborder"] = lborder;
  out["rborder"] = rborder;
  out["fill"] = fill;
  out["head"] = head;
  out["remain"] = remain;
  out["color"] = color;
  out["refresh_interval_ms"] = refresh_interval_ms;
  out["speed_window_size"] = speed_window_size;
  out["bar_width"] = bar_width;
  out["width_offset"] = width_offset;
  out["show_percentage"] = show_percentage;
  out["show_elapsed_time"] = show_elapsed_time;
  out["show_remaining_time"] = show_remaining_time;
  return out;
}

/**
 * @brief Clamp progress-bar arguments into runtime-safe range.
 */
void AMStyleProgressBarArgs::Normalize() {
  if (fill.empty()) {
    fill = "█";
  }
  if (head.empty()) {
    head = "▓";
  }
  bar_width = std::max<int64_t>(1, bar_width);
  refresh_interval_ms = std::max<int64_t>(1, refresh_interval_ms);
  speed_window_size = std::max<int64_t>(1, speed_window_size);
}

/**
 * @brief Load prompt template arguments from JSON.
 */
void AMStylePromptTemplateArgs::LoadFromJson(const Json &jsond) {
  if (!jsond.is_object()) {
    return;
  }
  (void)ReadField_(jsond, "core_prompt", &core_prompt);
  (void)ReadField_(jsond, "history_search_prompt", &history_search_prompt);
  extras = CollectExtras_(jsond, {"core_prompt", "history_search_prompt"});
}

/**
 * @brief Serialize prompt template arguments to JSON.
 */
Json AMStylePromptTemplateArgs::ToJson() const {
  Json out = extras.is_object() ? extras : Json::object();
  out["core_prompt"] = core_prompt;
  out["history_search_prompt"] = history_search_prompt;
  return out;
}

/**
 * @brief Load CLIPrompt arguments from JSON.
 */
void AMStyleCLIPromptArgs::LoadFromJson(const Json &jsond) {
  if (!jsond.is_object()) {
    return;
  }

  auto shortcut_it = jsond.find("shortcut");
  if (shortcut_it != jsond.end()) {
    shortcut = ReadStringMap_(*shortcut_it);
  }

  auto icons_it = jsond.find("icons");
  if (icons_it != jsond.end()) {
    icons = ReadStringMap_(*icons_it, true);
  }

  auto template_it = jsond.find("template");
  if (template_it != jsond.end() && template_it->is_object()) {
    prompt_template.LoadFromJson(*template_it);
  } else {
    auto legacy_it = jsond.find("templete");
    if (legacy_it != jsond.end() && legacy_it->is_object()) {
      prompt_template.LoadFromJson(*legacy_it);
    }
  }

  extras = CollectExtras_(jsond, {"shortcut", "icons", "template", "templete"});
}

/**
 * @brief Serialize CLIPrompt arguments to JSON.
 */
Json AMStyleCLIPromptArgs::ToJson() const {
  Json out = extras.is_object() ? extras : Json::object();
  out["shortcut"] = DumpStringMap_(shortcut);
  out["icons"] = DumpStringMap_(icons);
  out["template"] = prompt_template.ToJson();
  return out;
}

/**
 * @brief Load whole style snapshot from JSON.
 */
void AMStyleSnapshot::LoadFromJson(const Json &jsond) {
  if (!jsond.is_object()) {
    return;
  }

  auto complete_menu_it = jsond.find("CompleteMenu");
  if (complete_menu_it != jsond.end()) {
    complete_menu.LoadFromJson(*complete_menu_it);
  }

  auto table_it = jsond.find("Table");
  if (table_it != jsond.end()) {
    table.LoadFromJson(*table_it);
  }

  auto progress_bar_it = jsond.find("ProgressBar");
  if (progress_bar_it != jsond.end()) {
    progress_bar.LoadFromJson(*progress_bar_it);
  }

  auto cli_prompt_it = jsond.find("CLIPrompt");
  if (cli_prompt_it != jsond.end()) {
    cli_prompt.LoadFromJson(*cli_prompt_it);
  }

  auto input_highlight_it = jsond.find("InputHighlight");
  if (input_highlight_it != jsond.end()) {
    input_highlight = ReadStringMap_(*input_highlight_it);
  }

  auto value_query_it = jsond.find("ValueQueryHighlight");
  if (value_query_it != jsond.end()) {
    value_query_highlight = ReadStringMap_(*value_query_it);
  }

  auto path_it = jsond.find("Path");
  if (path_it != jsond.end()) {
    path = ReadStringMap_(*path_it);
  }

  extras = CollectExtras_(
      jsond, {"CompleteMenu", "Table", "ProgressBar", "CLIPrompt",
              "InputHighlight", "ValueQueryHighlight", "Path"});
}

/**
 * @brief Serialize whole style snapshot to JSON.
 */
Json AMStyleSnapshot::ToJson() const {
  Json out = extras.is_object() ? extras : Json::object();
  out["CompleteMenu"] = complete_menu.ToJson();
  out["Table"] = table.ToJson();
  out["ProgressBar"] = progress_bar.ToJson();
  out["CLIPrompt"] = cli_prompt.ToJson();
  out["InputHighlight"] = DumpStringMap_(input_highlight);
  out["ValueQueryHighlight"] = DumpStringMap_(value_query_highlight);
  out["Path"] = DumpStringMap_(path);
  return out;
}

/**
 * @brief Normalize all typed style fields.
 */
void AMStyleSnapshot::Normalize() {
  complete_menu.Normalize();
  table.Normalize();
  progress_bar.Normalize();
}
} // namespace AMInterface::style
