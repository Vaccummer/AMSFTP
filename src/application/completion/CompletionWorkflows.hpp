#pragma once

#include "foundation/core/DataClass.hpp"

namespace AMApplication::CompletionWorkflow {
/**
 * @brief Application port for completion-cache commands.
 */
class ICompletionGateway {
public:
  /**
   * @brief Virtual destructor for polymorphic gateway.
   */
  virtual ~ICompletionGateway() = default;

  /**
   * @brief Return true when an active completer instance exists.
   */
  [[nodiscard]] virtual bool HasActiveCompleter() const = 0;

  /**
   * @brief Clear active completer cache.
   */
  virtual void ClearActiveCompleterCache() const = 0;
};

/**
 * @brief Execute completion cache clear workflow.
 */
ECM ExecuteCompleteCacheClear(const ICompletionGateway &gateway);
} // namespace AMApplication::CompletionWorkflow
