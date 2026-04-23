#pragma once

#include "domain/style/StyleDomainModel.hpp"

#include <string_view>

namespace AMDomain::style::service {

[[nodiscard]] bool IsHexColorString(std::string_view color);
[[nodiscard]] bool IsStyleString(std::string_view style);

void NormalizeStyleToken(std::string *value, const std::string &fallback = "");
void NormalizeCompleteMenu(CompleteMenuStyle *style);
void NormalizeProgressBar(ProgressBarStyle *style);
void NormalizePromptTemplate(PromptTemplateStyle *style);
void NormalizeCLIPromptShortcut(CLIPromptShortcutStyle *style);
void NormalizeCLIPrompt(CLIPromptStyle *style);
void NormalizeInputHighlight(InputHighlightStyle *style);
void NormalizeValueQueryHighlight(ValueQueryHighlightStyle *style);
void NormalizeInternalStyle(InternalStyle *style);
void NormalizePathHighlight(PathHighlightStyle *style);
void NormalizeStyleConfig(StyleConfig *config);
void NormalizeStyleConfigArg(StyleConfigArg *arg);

} // namespace AMDomain::style::service

