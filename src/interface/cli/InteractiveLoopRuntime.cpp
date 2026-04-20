#include "interface/cli/InteractiveLoopRuntime.hpp"

#include "interface/cli/CLIServices.hpp"
#include "interface/completion/CompletionRuntimeAdapter.hpp"
#include "interface/completion/Engine.hpp"
#include "interface/parser/CommandTree.hpp"
#include "interface/token_analyser/TokenAnalyzerRuntimeAdapter.hpp"

namespace AMInterface::cli {

InteractiveLoopRuntime::InteractiveLoopRuntime() = default;

InteractiveLoopRuntime::~InteractiveLoopRuntime() = default;

ECM InteractiveLoopRuntime::Setup(AMInterface::parser::CommandNode &command_tree,
                                  const CLIServices &managers) {
  if (bound_command_tree_ == &command_tree && completion_engine_) {
    token_type_analyzer_.SetCommandTree(&command_tree);
    managers.interfaces.prompt_profile_history_manager->SetDefaultCompleter(
        &AMInterface::completer::AMCompleteEngine::IsoclineCompleteCallback,
        completion_engine_.get());
    managers.interfaces.prompt_profile_history_manager->SetDefaultHighlighter(
        &AMInterface::parser::TokenTypeAnalyzer::PromptHighlighter_,
        &token_type_analyzer_);
    return OK;
  }

  bound_command_tree_ = &command_tree;
  if (!analyzer_runtime_) {
    analyzer_runtime_ =
        std::make_shared<AMInterface::parser::TokenAnalyzerRuntimeAdapter>(
            managers.application.client_service.Get(),
            managers.application.host_service.Get(),
            managers.application.terminal_service.Get(),
            managers.application.var_service.Get(),
            managers.interfaces.var_interface_service.Get(),
            managers.interfaces.style_service.Get(),
            managers.application.prompt_profile_manager.Get());
  }
  if (!completion_runtime_) {
    completion_runtime_ =
        std::make_shared<AMInterface::completion::CompletionRuntimeAdapter>(
            managers.application.client_service.Get(),
            managers.application.host_service.Get(),
            managers.application.terminal_service.Get(),
            managers.application.var_service.Get(),
            managers.interfaces.var_interface_service.Get(),
            managers.interfaces.style_service.Get(),
            managers.application.prompt_profile_manager.Get(),
            managers.application.transfer_service.Get());
  }

  token_type_analyzer_.SetCommandTree(&command_tree);
  token_type_analyzer_.SetRuntime(analyzer_runtime_);

  completion_engine_ =
      std::make_unique<AMInterface::completer::AMCompleteEngine>(
          &command_tree, &token_type_analyzer_, completion_runtime_,
          &managers.application.completer_config_manager.Get(),
          &managers.interfaces.style_service.Get());
  completion_engine_->LoadConfig();
  completion_engine_->Install();

  managers.interfaces.prompt_profile_history_manager->SetDefaultCompleter(
      &AMInterface::completer::AMCompleteEngine::IsoclineCompleteCallback,
      completion_engine_.get());
  managers.interfaces.prompt_profile_history_manager->SetDefaultHighlighter(
      &AMInterface::parser::TokenTypeAnalyzer::PromptHighlighter_,
      &token_type_analyzer_);
  return OK;
}

} // namespace AMInterface::cli
