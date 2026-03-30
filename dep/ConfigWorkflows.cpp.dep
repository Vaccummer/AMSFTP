#include "application/config/ConfigWorkflows.hpp"
#include "foundation/tools/enum_related.hpp"

namespace AMApplication::ConfigWorkflow {
/**
 * @brief Persist config-related manager states from CLI context.
 */
ECM SaveAllFromCli(IHostConfigSaver &host_saver, IVarConfigSaver &var_saver,
                   IPromptConfigSaver &prompt_saver) {
  ECM rcm = host_saver.SaveHostConfig();
  if (!isok(rcm)) {
    return rcm;
  }
  rcm = var_saver.SaveVarConfig(true);
  if (!isok(rcm)) {
    return rcm;
  }
  return prompt_saver.SavePromptConfig(true);
}
} // namespace AMApplication::ConfigWorkflow
