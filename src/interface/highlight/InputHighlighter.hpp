#pragma once

#include "Isocline/isocline.h"
#include "foundation/core/DataClass.hpp"
#include "interface/input_analysis/InputAnalyzer.hpp"

namespace AMInterface::style {
class AMStyleService;
}

namespace AMInterface::highlight {

class InputHighlighter final : public NonCopyableNonMovable {
public:
  InputHighlighter() = default;
  ~InputHighlighter() override = default;

  void SetAnalyzer(AMInterface::input::InputAnalyzer *analyzer) {
    analyzer_ = analyzer;
  }
  void SetStyleService(AMInterface::style::AMStyleService *style_service) {
    style_service_ = style_service;
  }

  void RenderFormatted(const std::string &input, std::string *formatted) const;

  static void IsoclineHighlightCallback(ic_highlight_env_t *henv,
                                        const char *input, void *arg);

private:
  AMInterface::input::InputAnalyzer *analyzer_ = nullptr;
  AMInterface::style::AMStyleService *style_service_ = nullptr;
};

} // namespace AMInterface::highlight
