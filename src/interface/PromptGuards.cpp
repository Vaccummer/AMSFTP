#include "interface/Prompt.hpp"
#include "interface/ApplicationAdapters.hpp"

/**
 * @brief Silence global hooks and enable prompt-scope hook handlers.
 */
AMPromptHookGuard::AMPromptHookGuard() {
  AMInterface::ApplicationAdapters::Runtime::SilenceSignalHook("GLOBAL");
  AMInterface::ApplicationAdapters::Runtime::ResumeSignalHook("PROMPT");
}

/**
 * @brief Restore global hook state and silence prompt-scope handlers.
 */
AMPromptHookGuard::~AMPromptHookGuard() {
  AMInterface::ApplicationAdapters::Runtime::ResumeSignalHook("GLOBAL");
  AMInterface::ApplicationAdapters::Runtime::SilenceSignalHook("PROMPT");
}
