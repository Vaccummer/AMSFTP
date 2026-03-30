#include "bootstrap/runtime/ConfigAssembly.hpp"

#include "application/config/StyleSettings.hpp"
#include "domain/style/StyleDomainModel.hpp"
#include "foundation/tools/enum_related.hpp"
#include "infrastructure/config/ConfigStoreLayoutFactory.hpp"
#include <utility>

namespace {
std::string GetMapValue_(const std::map<std::string, std::string> &src,
                         const std::string &key) {
  const auto it = src.find(key);
  if (it == src.end()) {
    return "";
  }
  return it->second;
}

AMDomain::style::StyleConfigArg
ConvertStyleSnapshot_(const AMApplication::config::AMStyleSnapshot &snapshot) {
  AMDomain::style::StyleConfigArg out = {};

  out.style.complete_menu.maxnum = snapshot.complete_menu.maxnum;
  out.style.complete_menu.maxrows_perpage = snapshot.complete_menu.maxrows_perpage;
  out.style.complete_menu.item_select_sign = snapshot.complete_menu.item_select_sign;
  out.style.complete_menu.number_pick = snapshot.complete_menu.number_pick;
  out.style.complete_menu.auto_fillin = snapshot.complete_menu.auto_fillin;
  out.style.complete_menu.order_num_style = snapshot.complete_menu.order_num_style;
  out.style.complete_menu.help_style = snapshot.complete_menu.help_style;
  out.style.complete_menu.complete_delay_ms = snapshot.complete_menu.complete_delay_ms;
  out.style.complete_menu.async_workers = snapshot.complete_menu.async_workers;

  out.style.table.color = snapshot.table.color;
  out.style.table.left_padding = snapshot.table.left_padding;
  out.style.table.right_padding = snapshot.table.right_padding;
  out.style.table.top_padding = snapshot.table.top_padding;
  out.style.table.bottom_padding = snapshot.table.bottom_padding;
  out.style.table.refresh_interval_ms = snapshot.table.refresh_interval_ms;
  out.style.table.speed_window_size = snapshot.table.speed_window_size;

  out.style.progress_bar.start = snapshot.progress_bar.start;
  out.style.progress_bar.end = snapshot.progress_bar.end;
  out.style.progress_bar.fill = snapshot.progress_bar.fill;
  out.style.progress_bar.lead = snapshot.progress_bar.lead;
  out.style.progress_bar.remaining = snapshot.progress_bar.remaining;
  out.style.progress_bar.color = snapshot.progress_bar.color;
  out.style.progress_bar.refresh_interval_ms =
      snapshot.progress_bar.refresh_interval_ms;
  out.style.progress_bar.speed_window_size = snapshot.progress_bar.speed_window_size;
  out.style.progress_bar.bar_width = snapshot.progress_bar.bar_width;
  out.style.progress_bar.width_offset = snapshot.progress_bar.width_offset;
  out.style.progress_bar.show_percentage = snapshot.progress_bar.show_percentage;
  out.style.progress_bar.show_elapsed_time =
      snapshot.progress_bar.show_elapsed_time;
  out.style.progress_bar.show_remaining_time =
      snapshot.progress_bar.show_remaining_time;

  out.style.cli_prompt.shortcut.un = GetMapValue_(snapshot.cli_prompt.shortcut, "un");
  out.style.cli_prompt.shortcut.at = GetMapValue_(snapshot.cli_prompt.shortcut, "at");
  out.style.cli_prompt.shortcut.hn = GetMapValue_(snapshot.cli_prompt.shortcut, "hn");
  out.style.cli_prompt.shortcut.en = GetMapValue_(snapshot.cli_prompt.shortcut, "en");
  out.style.cli_prompt.shortcut.nn = GetMapValue_(snapshot.cli_prompt.shortcut, "nn");
  out.style.cli_prompt.shortcut.cwd = GetMapValue_(snapshot.cli_prompt.shortcut, "cwd");
  out.style.cli_prompt.shortcut.ds = GetMapValue_(snapshot.cli_prompt.shortcut, "ds");
  out.style.cli_prompt.shortcut.white =
      GetMapValue_(snapshot.cli_prompt.shortcut, "white");

  out.style.cli_prompt.icons.windows = GetMapValue_(snapshot.cli_prompt.icons, "windows");
  out.style.cli_prompt.icons.linux = GetMapValue_(snapshot.cli_prompt.icons, "linux");
  out.style.cli_prompt.icons.macos = GetMapValue_(snapshot.cli_prompt.icons, "macos");

  out.style.cli_prompt.named_styles.un =
      GetMapValue_(snapshot.cli_prompt.named_styles, "un");
  out.style.cli_prompt.named_styles.at =
      GetMapValue_(snapshot.cli_prompt.named_styles, "at");
  out.style.cli_prompt.named_styles.hn =
      GetMapValue_(snapshot.cli_prompt.named_styles, "hn");
  out.style.cli_prompt.named_styles.en =
      GetMapValue_(snapshot.cli_prompt.named_styles, "en");
  out.style.cli_prompt.named_styles.nn =
      GetMapValue_(snapshot.cli_prompt.named_styles, "nn");
  out.style.cli_prompt.named_styles.cwd =
      GetMapValue_(snapshot.cli_prompt.named_styles, "cwd");
  out.style.cli_prompt.named_styles.ds =
      GetMapValue_(snapshot.cli_prompt.named_styles, "ds");
  out.style.cli_prompt.named_styles.white =
      GetMapValue_(snapshot.cli_prompt.named_styles, "white");

  out.style.cli_prompt.prompt_template.core_prompt =
      snapshot.cli_prompt.prompt_template.core_prompt;
  out.style.cli_prompt.prompt_template.history_search_prompt =
      snapshot.cli_prompt.prompt_template.history_search_prompt;

  out.style.input_highlight.protocol = GetMapValue_(snapshot.input_highlight, "protocol");
  out.style.input_highlight.abort = GetMapValue_(snapshot.input_highlight, "abort");
  out.style.input_highlight.common = GetMapValue_(snapshot.input_highlight, "common");
  out.style.input_highlight.module = GetMapValue_(snapshot.input_highlight, "module");
  out.style.input_highlight.command = GetMapValue_(snapshot.input_highlight, "command");
  out.style.input_highlight.illegal_command =
      GetMapValue_(snapshot.input_highlight, "illegal_command");
  out.style.input_highlight.option = GetMapValue_(snapshot.input_highlight, "option");
  out.style.input_highlight.string = GetMapValue_(snapshot.input_highlight, "string");
  out.style.input_highlight.public_varname =
      GetMapValue_(snapshot.input_highlight, "public_varname");
  out.style.input_highlight.private_varname =
      GetMapValue_(snapshot.input_highlight, "private_varname");
  out.style.input_highlight.nonexistent_varname =
      GetMapValue_(snapshot.input_highlight, "nonexistent_varname");
  out.style.input_highlight.varvalue = GetMapValue_(snapshot.input_highlight, "varvalue");
  out.style.input_highlight.nickname = GetMapValue_(snapshot.input_highlight, "nickname");
  out.style.input_highlight.unestablished_nickname =
      GetMapValue_(snapshot.input_highlight, "unestablished_nickname");
  out.style.input_highlight.nonexistent_nickname =
      GetMapValue_(snapshot.input_highlight, "nonexistent_nickname");
  out.style.input_highlight.valid_new_nickname =
      GetMapValue_(snapshot.input_highlight, "valid_new_nickname");
  out.style.input_highlight.invalid_new_nickname =
      GetMapValue_(snapshot.input_highlight, "invalid_new_nickname");
  out.style.input_highlight.builtin_arg =
      GetMapValue_(snapshot.input_highlight, "builtin_arg");
  out.style.input_highlight.nonexistent_builtin_arg =
      GetMapValue_(snapshot.input_highlight, "nonexistent_builtin_arg");
  out.style.input_highlight.username = GetMapValue_(snapshot.input_highlight, "username");
  out.style.input_highlight.atsign = GetMapValue_(snapshot.input_highlight, "atsign");
  out.style.input_highlight.dollarsign =
      GetMapValue_(snapshot.input_highlight, "dollarsign");
  out.style.input_highlight.equalsign =
      GetMapValue_(snapshot.input_highlight, "equalsign");
  out.style.input_highlight.escapedsign =
      GetMapValue_(snapshot.input_highlight, "escapedsign");
  out.style.input_highlight.bangsign = GetMapValue_(snapshot.input_highlight, "bangsign");
  out.style.input_highlight.shell_cmd = GetMapValue_(snapshot.input_highlight, "shell_cmd");
  out.style.input_highlight.cwd = GetMapValue_(snapshot.input_highlight, "cwd");
  out.style.input_highlight.number = GetMapValue_(snapshot.input_highlight, "number");
  out.style.input_highlight.timestamp = GetMapValue_(snapshot.input_highlight, "timestamp");
  out.style.input_highlight.path_like = GetMapValue_(snapshot.input_highlight, "path_like");

  out.style.value_query_highlight.valid_value =
      GetMapValue_(snapshot.value_query_highlight, "valid_value");
  out.style.value_query_highlight.invalid_value =
      GetMapValue_(snapshot.value_query_highlight, "invalid_value");
  out.style.value_query_highlight.prompt_style =
      GetMapValue_(snapshot.value_query_highlight, "prompt_style");

  out.style.internal_style.inline_hint =
      GetMapValue_(snapshot.internal_style, "inline_hint");
  out.style.internal_style.default_prompt =
      GetMapValue_(snapshot.internal_style, "default_prompt_style");
  if (out.style.internal_style.default_prompt.empty()) {
    out.style.internal_style.default_prompt =
        GetMapValue_(snapshot.internal_style, "default_prompt");
  }

  out.style.path.path_str = GetMapValue_(snapshot.path, "path_str");
  out.style.path.root = GetMapValue_(snapshot.path, "root");
  out.style.path.node_dir_name = GetMapValue_(snapshot.path, "node_dir_name");
  out.style.path.filename = GetMapValue_(snapshot.path, "filename");
  out.style.path.dir = GetMapValue_(snapshot.path, "dir");
  out.style.path.regular = GetMapValue_(snapshot.path, "regular");
  out.style.path.symlink = GetMapValue_(snapshot.path, "symlink");
  out.style.path.otherspecial = GetMapValue_(snapshot.path, "otherspecial");
  out.style.path.nonexistent = GetMapValue_(snapshot.path, "nonexistent");

  out.style.system_info.info = GetMapValue_(snapshot.system_info, "info");
  out.style.system_info.success = GetMapValue_(snapshot.system_info, "success");
  out.style.system_info.error = GetMapValue_(snapshot.system_info, "error");
  out.style.system_info.warning = GetMapValue_(snapshot.system_info, "warning");

  return out;
}
} // namespace

namespace AMBootstrap {
/**
 * @brief Construct config assembly and pre-bind application dependencies.
 */
ConfigAssembly::ConfigAssembly() = default;

/**
 * @brief Release config resources on destruction.
 */
ConfigAssembly::~ConfigAssembly() { Close(); }

/**
 * @brief Initialize config stack using default infrastructure layout.
 */
ECM ConfigAssembly::Init(const std::filesystem::path &root_dir) {
  return Init(root_dir, AMInfra::config::BuildDefaultConfigStoreInitArg(root_dir));
}

/**
 * @brief Initialize config stack using explicit store init payload.
 */
ECM ConfigAssembly::Init(const std::filesystem::path &root_dir,
                         const AMDomain::config::ConfigStoreInitArg &init_arg) {
  Close();
  AMDomain::config::ConfigStoreInitArg effective_arg = init_arg;
  if (effective_arg.root_dir.empty()) {
    effective_arg.root_dir = root_dir;
  }
  root_dir_ = effective_arg.root_dir;

  app_service_.SetInitArg(std::move(effective_arg));
  ECM rcm = app_service_.Init();
  if (!isok(rcm)) {
    initialized_ = false;
    return rcm;
  }
  app_service_.SetDumpErrorCallback(
      [this](const ECM &err) { NotifyDumpError_(err); });

  rcm = app_service_.Load(std::nullopt, true);
  if (!isok(rcm)) {
    Close();
    return rcm;
  }

  AMApplication::config::AMStyleSnapshot style_snapshot = {};
  if (!app_service_.Read(&style_snapshot)) {
    Close();
    return Err(EC::ConfigLoadFailed, "failed to load style settings");
  }

  style_service_.SetInitArg(ConvertStyleSnapshot_(style_snapshot));
  rcm = style_service_.Init();
  if (!isok(rcm)) {
    Close();
    return rcm;
  }

  initialized_ = true;
  return Ok();
}

/**
 * @brief Close config handles and stop background writer.
 */
void ConfigAssembly::Close() {
  app_service_.CloseHandles();
  root_dir_.clear();
  initialized_ = false;
}

/**
 * @brief Bind callback invoked on dump/write failures.
 */
void ConfigAssembly::SetDumpErrorCallback(DumpErrorCallback cb) {
  dump_error_cb_ = std::move(cb);
  app_service_.SetDumpErrorCallback(
      [this](const ECM &err) { NotifyDumpError_(err); });
}

/**
 * @brief Return bound config application service.
 */
AMApplication::config::AMConfigAppService &ConfigAssembly::ConfigService() {
  return app_service_;
}

/**
 * @brief Return bound config application service.
 */
const AMApplication::config::AMConfigAppService &
ConfigAssembly::ConfigService() const {
  return app_service_;
}

/**
 * @brief Return initialized interface style service.
 */
AMInterface::style::AMStyleService &ConfigAssembly::StyleService() {
  return style_service_;
}

/**
 * @brief Return initialized interface style service.
 */
const AMInterface::style::AMStyleService &ConfigAssembly::StyleService() const {
  return style_service_;
}

/**
 * @brief Forward dump errors to bound callback when present.
 */
void ConfigAssembly::NotifyDumpError_(const ECM &err) const {
  if (dump_error_cb_) {
    dump_error_cb_(err);
  }
}
} // namespace AMBootstrap
