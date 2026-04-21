#include "interface/cli/InteractiveLoopRuntime.hpp"

#include "interface/cli/CLIServices.hpp"
#include "interface/completion/Engine.hpp"
#include "interface/highlight/InputHighlighter.hpp"
#include "interface/input_analysis/runtime/InputSemanticRuntimeAdapter.hpp"
#include "interface/parser/CommandTree.hpp"

namespace AMInterface::cli {

InteractiveLoopRuntime::InteractiveLoopRuntime() = default;

InteractiveLoopRuntime::~InteractiveLoopRuntime() = default;

ECM InteractiveLoopRuntime::Setup(AMInterface::parser::CommandNode &command_tree,
                                  const CLIServices &managers) {
  if (bound_command_tree_ == &command_tree && completion_engine_) {
    input_analyzer_.SetCommandTree(&command_tree);
    managers.interfaces.prompt_profile_history_manager->SetDefaultCompleter(
        &AMInterface::completer::AMCompleteEngine::IsoclineCompleteCallback,
        completion_engine_.get());
    managers.interfaces.prompt_profile_history_manager->SetDefaultHighlighter(
        &AMInterface::highlight::InputHighlighter::IsoclineHighlightCallback,
        &input_highlighter_);
    return OK;
  }

  bound_command_tree_ = &command_tree;
  if (!runtime_) {
    runtime_ =
        std::make_shared<AMInterface::input::InputSemanticRuntimeAdapter>(
            managers.application.client_service.Get(),
            managers.application.host_service.Get(),
            managers.application.terminal_service.Get(),
            managers.application.var_service.Get(),
            managers.interfaces.var_interface_service.Get(),
            managers.application.prompt_profile_manager.Get(),
            managers.application.transfer_service.Get());
  }

  input_analyzer_.SetCommandTree(&command_tree);
  input_analyzer_.SetRuntime(runtime_);
  input_highlighter_.SetAnalyzer(&input_analyzer_);
  input_highlighter_.SetStyleService(&managers.interfaces.style_service.Get());

  completion_engine_ =
      std::make_unique<AMInterface::completer::AMCompleteEngine>(
          &command_tree, &input_analyzer_, runtime_,
          &managers.application.completer_config_manager.Get(),
          &managers.interfaces.style_service.Get());
  completion_engine_->LoadConfig();
  completion_engine_->Install();

  managers.interfaces.prompt_profile_history_manager->SetDefaultCompleter(
      &AMInterface::completer::AMCompleteEngine::IsoclineCompleteCallback,
      completion_engine_.get());
  managers.interfaces.prompt_profile_history_manager->SetDefaultHighlighter(
      &AMInterface::highlight::InputHighlighter::IsoclineHighlightCallback,
      &input_highlighter_);
  return OK;
}

} // namespace AMInterface::cli
