#pragma once

#include "interface/cli/ArgStruct/BaseArgStruct.hpp"
#include "interface/prompt/Prompt.hpp"
#include <string>

namespace AMInterface::cli {
namespace complete_arg_detail {

inline ECM UnsupportedCommand(AMInterface::prompt::PromptIOManager &prompt,
                              const std::string &message) {
  (void)prompt;
  const ECM rcm = Err(EC::OperationUnsupported, "", "", message);
  return rcm;
}

} // namespace complete_arg_detail

/**
 * @brief CLI argument container for complete cache clear.
 */
struct CompleteCacheClearArgs : BaseArgStruct {
  [[nodiscard]] ECM Run(const CLIServices &managers,
                        const CliRunContext &ctx) const override {
    (void)ctx;
    return complete_arg_detail::UnsupportedCommand(
        managers.interfaces.prompt_io_manager,
        "Completion cache clear is deprecated in current service mode");
  }
  void reset() override {}
};

} // namespace AMInterface::cli




