#include "application/completion/CompletionWorkflows.hpp"
#include "foundation/tools/enum_related.hpp"

namespace AMApplication::CompletionWorkflow {
/**
 * @brief Execute completion cache clear workflow.
 */
ECM ExecuteCompleteCacheClear(const ICompletionGateway &gateway) {
  if (!gateway.HasActiveCompleter()) {
    return Err(EC::InvalidArg, "Completer is not active");
  }
  gateway.ClearActiveCompleterCache();
  return Ok();
}
} // namespace AMApplication::CompletionWorkflow
