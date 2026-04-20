#include "interface/prompt/CLIPromtRender.hpp"
#include "foundation/tools/prompt_ui.hpp"
#include "foundation/tools/string.hpp"

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
  return "return \"[nn](\" .. nickname .. \")[/] [cwd]\" .. cwd .. \"[/] [ds]> "
         "[/]\"";
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
      AMStr::replace_all(AMPromptUI::StripStyleForMeasure(left), "\r", "");
  const std::string right_plain =
      AMStr::replace_all(AMPromptUI::StripStyleForMeasure(right), "\r", "");

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

  const int cols = AMPromptUI::TerminalCols();
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
    : style_service_(style_service) {}

std::string
CLIPromtRender::Render(const AMApplication::prompt::PromptRenderDTO &dto) {
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
    state_.cached_render = NormalizePromptOutput_(BuildFallbackPrompt_(dto));
    state_.has_cached_render = true;
    return state_.cached_render;
  }

  const auto rendered =
      interpreter_.Render(state_.parsed_context, BuildRenderVars_(dto));
  if (!(rendered.rcm)) {
    state_.render_ok = false;
    state_.render_error = rendered.rcm.msg();
    if (state_.render_error.empty()) {
      state_.render_error =
          std::string(magic_enum::enum_name(rendered.rcm.code));
    }
    state_.cached_render = NormalizePromptOutput_(BuildFallbackPrompt_(dto));
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

PromptVarMap CLIPromtRender::BuildRenderVars_(
    const AMApplication::prompt::PromptRenderDTO &dto) const {
  PromptVarMap vars = {};
  for (const auto &[attr, value] : dto.GetDict()) {
    vars[std::string(magic_enum::enum_name(attr))] =
        std::visit([](const auto &item) -> PromptVarValue { return item; }, value);
  }

  if (auto it = vars.find("nickname"); it != vars.end()) {
    const std::string escaped = AMStr::BBCEscape(dto.nickname);
    if (!escaped.empty()) {
      it->second = dto.client_connected
                       ? PromptVarValue{escaped}
                       : PromptVarValue{
                             AMStr::fmt("[disconnected_nickname]{}[/]", escaped)};
    }
  }

  vars["current_nickname"] = vars["nickname"];
  vars["current_client_connected"] = vars["client_connected"];
  return vars;
}

std::string CLIPromtRender::BuildFallbackPrompt_(
    const AMApplication::prompt::PromptRenderDTO &dto) const {
  const std::string nickname =
      dto.nickname.empty() ? std::string("local") : dto.nickname;
  return "(" + nickname + ") / > ";
}

void CLIPromtRender::RefreshTemplateCache_() {
  const std::string fmt = ResolvePromptTemplate_(style_service_);
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
