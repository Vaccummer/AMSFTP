#include "interface/prompt/CLICorePrompt.hpp"
#include "foundation/tools/string.hpp"
#include "foundation/tools/terminal.hpp"
#include "foundation/tools/time.hpp"

#include <algorithm>
#include <cctype>
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
  return "return \"[nn](\" .. nickname .. \")[/] [cwd]\" .. cwd .. \"[/] [ds]> [/]\"";
}

std::string StripStyleForMeasure_(const std::string &text) {
  auto is_style_tag = [](const std::string &tag) {
    if (tag.empty()) {
      return false;
    }
    if (tag.front() == '#' || tag.front() == '/' || tag.front() == '!') {
      return true;
    }
    return std::all_of(tag.begin(), tag.end(), [](char ch) {
      return std::isalnum(static_cast<unsigned char>(ch)) || ch == '_' ||
             ch == '-';
    });
  };

  std::string out = {};
  out.reserve(text.size());
  for (size_t i = 0; i < text.size(); ++i) {
    const char ch = text[i];
    if (ch == '\\' && i + 1 < text.size() &&
        (text[i + 1] == '[' || text[i + 1] == ']')) {
      out.push_back(text[i + 1]);
      ++i;
      continue;
    }
    if (ch == '[') {
      const size_t close = text.find(']', i + 1);
      if (close != std::string::npos) {
        const std::string token = text.substr(i + 1, close - i - 1);
        if (is_style_tag(token)) {
          i = close;
          continue;
        }
      }
    }
    out.push_back(ch);
  }
  return out;
}

std::string ExpandPaddingTabForLine_(const std::string &line, int cols) {
  std::string out = line;
  const size_t first_tab = out.find('\t');
  if (first_tab == std::string::npos) {
    return out;
  }

  const std::string left = out.substr(0, first_tab);
  std::string right = out.substr(first_tab + 1);
  right = AMStr::replace_all(right, "\t", "   ");

  const std::string left_plain =
      AMStr::replace_all(StripStyleForMeasure_(left), "\r", "");
  const std::string right_plain =
      AMStr::replace_all(StripStyleForMeasure_(right), "\r", "");

  const size_t left_width = AMStr::DisplayWidthUtf8(left_plain);
  const size_t right_width = AMStr::DisplayWidthUtf8(right_plain);
  size_t pad_width = 3;
  const size_t total_width = left_width + right_width;
  if (cols > 0 && static_cast<size_t>(cols) > total_width) {
    pad_width = static_cast<size_t>(cols) - total_width;
  }
  return left + std::string(pad_width, ' ') + right;
}

std::string NormalizePromptOutput_(const std::string &rendered) {
  if (rendered.empty()) {
    return rendered;
  }

  const int cols = std::max(1, AMTerminalTools::GetTerminalViewportInfo().cols);
  std::string normalized = {};
  normalized.reserve(rendered.size() + 16);

  size_t start = 0;
  while (start < rendered.size()) {
    const size_t nl = rendered.find('\n', start);
    const bool has_newline = (nl != std::string::npos);
    const size_t end = has_newline ? nl : rendered.size();
    std::string line = rendered.substr(start, end - start);
    line = ExpandPaddingTabForLine_(line, cols);
    line = AMStr::replace_all(line, "\t", "   ");
    normalized += line;
    if (has_newline) {
      normalized.push_back('\n');
    }
    start = has_newline ? (nl + 1) : rendered.size();
  }

  while (!normalized.empty() &&
         (normalized.back() == '\n' || normalized.back() == '\r')) {
    normalized.pop_back();
  }
  return normalized;
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
    state_.render_ok = true;
    state_.render_error.clear();
    return "";
  }

  if (!state_.parse_ok) {
    state_.render_ok = false;
    state_.render_error = "core prompt template parse failed";
    if (!state_.diagnostics.items.empty()) {
      state_.render_error = state_.diagnostics.items.front().message;
    }
    state_.cached_render = NormalizePromptOutput_(BuildFallbackPrompt_(arg));
    state_.has_cached_render = true;
    return state_.cached_render;
  }

  const auto rendered = RenderPromptFormat_(arg);
  if (!(rendered.rcm)) {
    state_.render_ok = false;
    state_.render_error = rendered.rcm.msg();
    if (state_.render_error.empty()) {
      state_.render_error = std::string(magic_enum::enum_name(rendered.rcm.code));
    }
    state_.cached_render = NormalizePromptOutput_(BuildFallbackPrompt_(arg));
  } else {
    state_.render_ok = true;
    state_.render_error.clear();
    state_.cached_render = NormalizePromptOutput_(rendered.data);
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
  state_.render_ok = true;
  state_.render_error.clear();
  state_.parsed_context = {};
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
  RegisterGetter("task_paused", []() { return "0"; });
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
    const std::string nickname = AMStr::BBCEscape(arg.current_nickname);
    if (arg.current_client_connected || nickname.empty()) {
      return nickname;
    }
    return AMStr::fmt("[disconnected_nickname]{}[/]", nickname);
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
  const PromptVarMap vars = BuildRenderVars_(arg);
  return interpreter_.Render(state_.parsed_context, vars);
}

PromptVarMap CLIPromtRender::BuildRenderVars_(const RenderArg &arg) const {
  PromptVarMap vars = {};
  for (const auto &entry : getters_) {
    vars[entry.first] = ResolveKeywordValue_(entry.first, arg);
  }
  for (const std::string &builtin :
       {"nickname", "elapsed", "success", "ec_name"}) {
    vars[builtin] = ResolveKeywordValue_(builtin, arg);
  }
  return vars;
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
  state_.render_ok = true;
  state_.render_error.clear();

  auto parsed = interpreter_.Parse(fmt);
  state_.parse_ok = (parsed.rcm) && !parsed.data.diagnostics.HasError();
  state_.parsed_context = std::move(parsed.data.context);
  state_.compiled_template = state_.parsed_context.source;
  state_.diagnostics = std::move(parsed.data.diagnostics);
}

} // namespace AMInterface::prompt
