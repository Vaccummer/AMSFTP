#pragma once

#include "application/prompt/PromptRenderDTO.hpp"
#include "foundation/core/DataClass.hpp"
#include "interface/parser/PromptTemplateInterpreter.hpp"
#include "interface/style/StyleManager.hpp"

#include <string>

namespace AMInterface::prompt {

class CLIPromtRender : public NonCopyableNonMovable {
public:
  struct RuntimeState {
    std::string template_raw = "";
    std::string compiled_template = "";
    std::string cached_render = "";
    bool has_cached_render = false;
    bool parse_ok = false;
    bool render_ok = true;
    std::string render_error = "";
    PromptTemplateContext parsed_context = {};
    PromptTemplateDiagnostics diagnostics = {};
  };

  explicit CLIPromtRender(AMInterface::style::AMStyleService &style_service);
  ~CLIPromtRender() override = default;

  [[nodiscard]] std::string
  Render(const AMApplication::prompt::PromptRenderDTO &dto);

  void InvalidateCache();

  [[nodiscard]] const RuntimeState &State() const;

private:
  [[nodiscard]] PromptVarMap
  BuildRenderVars_(const AMApplication::prompt::PromptRenderDTO &dto) const;
  [[nodiscard]] std::string
  BuildFallbackPrompt_(const AMApplication::prompt::PromptRenderDTO &dto) const;
  void RefreshTemplateCache_();

private:
  AMInterface::style::AMStyleService &style_service_;
  PromptTemplateInterpreter interpreter_ = {};
  mutable RuntimeState state_ = {};
};

} // namespace AMInterface::prompt
