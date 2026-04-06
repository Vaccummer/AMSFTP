#pragma once
#include "interface/cli/CLIServices.hpp"

namespace AMInterface::cli {

/**
 * @brief Base interface for all parsed CLI argument payload structs.
 */
struct BaseArgStruct {
  virtual ~BaseArgStruct() = default;
  /**
   * @brief Execute this parsed command payload.
   */
  [[nodiscard]] virtual ECM Run(const CLIServices &managers,
                                const CliRunContext &ctx) const = 0;
  /**
   * @brief Reset this payload to parser defaults.
   */
  virtual void reset() = 0;
};

} // namespace AMInterface::cli
