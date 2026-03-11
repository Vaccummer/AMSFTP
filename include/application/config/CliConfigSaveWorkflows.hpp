#pragma once

#include "foundation/DataClass.hpp"

namespace AMApplication::ConfigWorkflow {
/**
 * @brief Port abstraction for persisting host configuration state.
 */
class IHostConfigSaver {
public:
  /**
   * @brief Virtual destructor for interface polymorphism.
   */
  virtual ~IHostConfigSaver() = default;

  /**
   * @brief Persist host-related configuration data.
   * @return ECM success or failure.
   */
  virtual ECM SaveHostConfig() = 0;
};

/**
 * @brief Port abstraction for persisting variable configuration state.
 */
class IVarConfigSaver {
public:
  /**
   * @brief Virtual destructor for interface polymorphism.
   */
  virtual ~IVarConfigSaver() = default;

  /**
   * @brief Persist variable-related configuration data.
   * @param dump_now Whether to force immediate persistence.
   * @return ECM success or failure.
   */
  virtual ECM SaveVarConfig(bool dump_now) = 0;
};

/**
 * @brief Port abstraction for persisting prompt configuration state.
 */
class IPromptConfigSaver {
public:
  /**
   * @brief Virtual destructor for interface polymorphism.
   */
  virtual ~IPromptConfigSaver() = default;

  /**
   * @brief Persist prompt-related configuration data.
   * @param dump_now Whether to force immediate persistence.
   * @return ECM success or failure.
   */
  virtual ECM SavePromptConfig(bool dump_now) = 0;
};

/**
 * @brief Persist all CLI-related configuration states in a fixed order.
 *
 * Save order:
 * 1) host
 * 2) variable
 * 3) prompt
 *
 * @param host_saver Host config saver port.
 * @param var_saver Variable config saver port.
 * @param prompt_saver Prompt config saver port.
 * @return First error encountered, otherwise success.
 */
ECM SaveAllFromCli(IHostConfigSaver &host_saver, IVarConfigSaver &var_saver,
                   IPromptConfigSaver &prompt_saver);
} // namespace AMApplication::ConfigWorkflow
