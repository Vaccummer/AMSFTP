#include "interface/prompt/CLICorePrompt.hpp"
#include "foundation/tools/string.hpp"
#include "foundation/tools/time.hpp"

#include <algorithm>
#include <cstdint>
#include <magic_enum/magic_enum.hpp>
#include <utility>

namespace AMInterface::prompt {
namespace {

std::string
ResolvePromptTemplate_(const AMInterface::style::AMStyleService &s) {
  const auto style = s.GetInitArg().style.cli_prompt.prompt_template;
  if (!style.core_prompt.empty()) {
    return style.core_prompt;
  }
  return "[nn]({$nickname})[/] [cwd]{$cwd}[/] [ds]> [/]";
}

} // namespace

CLIPromtRender::CLIPromtRender(
    AMInterface::style::AMStyleService &style_service)
    : style_service_(style_service) {
  RegisterDefaultGetters_();
}

void CLIPromtRender::RegisterGetter(const std::string &key, GetterFn getter) {
  const std::string normalized = AMStr::lowercase(AMStr::Strip(key));
  if (normalized.empty()) {
    return;
  }
  getters_[normalized] = std::move(getter);
}

bool CLIPromtRender::UnregisterGetter(const std::string &key) {
  const std::string normalized = AMStr::lowercase(AMStr::Strip(key));
  if (normalized.empty()) {
    return false;
  }
  return getters_.erase(normalized) > 0;
}

std::string CLIPromtRender::Render(const RenderArg &arg) {
  RefreshTemplateCache_();
  if (state_.compiled_template.empty()) {
    state_.cached_render.clear();
    state_.has_cached_render = false;
    return "";
  }

  if (!state_.parse_ok) {
    state_.cached_render = BuildFallbackPrompt_(arg);
    state_.has_cached_render = true;
    return state_.cached_render;
  }

  const auto rendered = RenderPromptFormat_(arg);
  if (!(rendered.rcm)) {
    state_.cached_render = BuildFallbackPrompt_(arg);
  } else {
    state_.cached_render = rendered.data;
  }
  state_.has_cached_render = true;
  return state_.cached_render;
}

void CLIPromtRender::InvalidateCache() {
  state_.template_raw.clear();
  state_.compiled_template.clear();
  state_.cached_render.clear();
  state_.has_cached_render = false;
  state_.parse_ok = false;
  state_.parsed_context = {};
  state_.required_vars.clear();
  state_.diagnostics = {};
}

const CLIPromtRender::RuntimeState &CLIPromtRender::State() const {
  return state_;
}

bool CLIPromtRender::HasCachedRender() const {
  return state_.has_cached_render;
}

const std::string &CLIPromtRender::GetCachedRender() const {
  return state_.cached_render;
}

void CLIPromtRender::RegisterDefaultGetters_() {
  RegisterGetter("os_type", []() { return "windows"; });
  RegisterGetter("sysicon", [this]() {
    const std::string os_type =
        AMStr::lowercase(AMStr::Strip(ResolveKeywordValue_("os_type", {})));
    const auto icons = style_service_.GetInitArg().style.cli_prompt.icons;
    if (os_type == "linux") {
      return icons.linux.empty() ? std::string("PC") : icons.linux;
    }
    if (os_type == "macos" || os_type == "mac") {
      return icons.macos.empty() ? std::string("PC") : icons.macos;
    }
    return icons.windows.empty() ? std::string("PC") : icons.windows;
  });
  RegisterGetter("username", []() { return ""; });
  RegisterGetter("hostname", []() { return ""; });
  RegisterGetter("cwd", []() { return "/"; });
  RegisterGetter("task_pending", []() { return "0"; });
  RegisterGetter("task_running", []() { return "0"; });
  RegisterGetter("time_now", []() {
    return FormatTime(static_cast<size_t>(AMTime::seconds()), "%H:%M:%S");
  });
  RegisterGetter("time_clock",
                 [this]() { return ResolveKeywordValue_("time_now", {}); });
  RegisterGetter("task_num", [this]() {
    int64_t pending = 0;
    int64_t running = 0;
    try {
      pending =
          std::stoll(AMStr::Strip(ResolveKeywordValue_("task_pending", {})));
    } catch (...) {
      pending = 0;
    }
    try {
      running =
          std::stoll(AMStr::Strip(ResolveKeywordValue_("task_running", {})));
    } catch (...) {
      running = 0;
    }
    return std::to_string(std::max<int64_t>(0, pending) +
                          std::max<int64_t>(0, running));
  });
}

std::string CLIPromtRender::ResolveKeywordValue_(const std::string &key,
                                                 const RenderArg &arg) const {
  const std::string normalized = AMStr::lowercase(AMStr::Strip(key));
  if (normalized.empty()) {
    return "";
  }

  if (normalized == "nickname") {
    return arg.current_nickname;
  }
  if (normalized == "elapsed") {
    return AMStr::fmt("{}ms", std::max<int64_t>(0, arg.elapsed_time_ms));
  }
  if (normalized == "success") {
    return arg.result.code == EC::Success ? "1" : "";
  }
  if (normalized == "ec_name") {
    if (arg.result.code == EC::Success) {
      return "";
    }
    return std::string(magic_enum::enum_name(arg.result.code));
  }

  const auto it = getters_.find(normalized);
  if (it == getters_.end() || !it->second) {
    return "";
  }
  try {
    return it->second();
  } catch (...) {
    return "";
  }
}

std::string CLIPromtRender::ResolveCorePromptFormat_() const {
  return ResolvePromptTemplate_(style_service_);
}

ECMData<std::string>
CLIPromtRender::RenderPromptFormat_(const RenderArg &arg) const {
  PromptVarMap vars = state_.required_vars;
  for (auto &entry : vars) {
    entry.second = ResolveKeywordValue_(entry.first, arg);
  }
  return interpreter_.Render(state_.parsed_context, vars);
}

std::string CLIPromtRender::BuildFallbackPrompt_(const RenderArg &arg) const {
  const std::string nickname = arg.current_nickname.empty()
                                   ? std::string("local")
                                   : arg.current_nickname;
  return "(" + nickname + ") / > ";
}

void CLIPromtRender::RefreshTemplateCache_() {
  const std::string fmt = ResolveCorePromptFormat_();
  if (fmt == state_.template_raw) {
    return;
  }

  state_.template_raw = fmt;
  state_.compiled_template = fmt;
  state_.cached_render.clear();
  state_.has_cached_render = false;

  auto parsed = interpreter_.Parse(fmt);
  state_.parse_ok = (parsed.rcm) && !parsed.data.diagnostics.HasError();
  state_.parsed_context = std::move(parsed.data.context);
  state_.required_vars = std::move(parsed.data.required_vars);
  state_.diagnostics = std::move(parsed.data.diagnostics);
}

} // namespace AMInterface::prompt
