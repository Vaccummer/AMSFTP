#pragma once

#include "foundation/core/DataClass.hpp"
#include "interface/parser/PromptTemplateInterpreter.hpp"
#include "interface/style/StyleManager.hpp"

#include <functional>
#include <string>
#include <unordered_map>

namespace AMInterface::prompt {

class CLIPromtRender : public NonCopyableNonMovable {
public:
  using GetterFn = std::function<std::string()>;

  struct RenderArg {
    std::string current_nickname = "local";
    int64_t elapsed_time_ms = 0;
    ECM result = OK;
  };

  struct RuntimeState {
    std::string template_raw = "";
    std::string compiled_template = "";
    std::string cached_render = "";
    bool has_cached_render = false;
    bool parse_ok = false;
    PromptTemplateContext parsed_context = {};
    PromptVarMap required_vars = {};
    PromptTemplateDiagnostics diagnostics = {};
  };

  explicit CLIPromtRender(AMInterface::style::AMStyleService &style_service);
  ~CLIPromtRender() override = default;

  void RegisterGetter(const std::string &key, GetterFn getter);
  bool UnregisterGetter(const std::string &key);

  [[nodiscard]] std::string Render(const RenderArg &arg);

  void InvalidateCache();

  [[nodiscard]] const RuntimeState &State() const;
  [[nodiscard]] bool HasCachedRender() const;
  [[nodiscard]] const std::string &GetCachedRender() const;

private:
  void RegisterDefaultGetters_();
  [[nodiscard]] std::string ResolveKeywordValue_(const std::string &key,
                                                 const RenderArg &arg) const;
  [[nodiscard]] std::string ResolveCorePromptFormat_() const;
  [[nodiscard]] ECMData<std::string>
  RenderPromptFormat_(const RenderArg &arg) const;
  [[nodiscard]] std::string BuildFallbackPrompt_(const RenderArg &arg) const;
  void RefreshTemplateCache_();

private:
  AMInterface::style::AMStyleService &style_service_;
  PromptTemplateInterpreter interpreter_ = {};
  mutable RuntimeState state_ = {};
  std::unordered_map<std::string, GetterFn> getters_ = {};
};

} // namespace AMInterface::prompt
