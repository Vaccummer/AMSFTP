#pragma once

#include "domain/prompt/PromptDomainModel.hpp"

namespace AMDomain::prompt::service {

void NormalizePromptSettings(PromptProfilePromptSettings *settings);
void NormalizeHistorySettings(PromptProfileHistorySettings *settings);
void NormalizeInlineHintPathSettings(PromptProfileInlineHintPathSettings *settings);
void NormalizeInlineHintSettings(PromptProfileInlineHintSettings *settings);
void NormalizeCompletePathSettings(PromptProfileCompletePathSettings *settings);
void NormalizeCompleteSettings(PromptProfileCompleteSettings *settings);
void NormalizeHighlightPathSettings(PromptProfileHighlightPathSettings *settings);
void NormalizeHighlightSettings(PromptProfileHighlightSettings *settings);
void NormalizePromptProfileSettings(PromptProfileSettings *settings);
void NormalizePromptProfileSet(PromptProfileSet *set);
void NormalizePromptProfileArg(PromptProfileArg *arg);

} // namespace AMDomain::prompt::service

