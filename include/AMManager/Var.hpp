#pragma once
#include "AMBase/Enum.hpp"
#include "AMManager/Config.hpp"
#include "AMManager/Prompt.hpp"
#include <mutex>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

class AMVarManager {
public:
  using ECM = std::pair<ErrorCode, std::string>;

  enum class VarSource { Builtin, Memory };

  /**
   * @brief Return the singleton variable manager bound to a config manager.
   */
  static AMVarManager &Instance(AMConfigManager &config_manager);

  /**
   * @brief Set or overwrite an in-memory variable, confirming overwrites.
   */
  ECM SetMemoryVar(const std::string &name, const std::string &value,
                   bool confirm_overwrite = true);

  /**
   * @brief Set or overwrite a persistent variable and mirror it in memory.
   */
  ECM SetPersistentVar(const std::string &name, const std::string &value,
                       bool confirm_overwrite = true);

  /**
   * @brief Resolve a variable value from memory or settings.
   */
  bool Resolve(const std::string &name, std::string *value,
               VarSource *source = nullptr) const;

  /**
   * @brief Query variables in memory and storage, printing results.
   */
  ECM Query(const std::vector<std::string> &names);

  /**
   * @brief Delete variables from memory and storage, confirming per key.
   */
  ECM Delete(const std::vector<std::string> &names);

  /**
   * @brief Enumerate variables, printing memory entries then storage entries.
   */
  ECM Enumerate();

  /**
   * @brief Return true if an in-memory variable exists.
   */
  bool HasMemoryVar(const std::string &name) const;

private:
  /**
   * @brief Construct a variable manager tied to the config manager.
   */
  explicit AMVarManager(AMConfigManager &config_manager);

  /**
   * @brief Ask the user to confirm overwriting an existing variable.
   */
  ECM ConfirmOverwrite(const std::string &name, VarSource source) const;

  /**
   * @brief Ask the user to confirm deleting a variable.
   */
  ECM ConfirmDelete(const std::string &name, bool has_memory,
                    bool has_storage) const;

  /**
   * @brief Format a variable key/value using the UserPaths style.
   */
  std::string FormatUserPathText(const std::string &text) const;

  /**
   * @brief Print a formatted query line.
   */
  void PrintQueryLine(const std::string &scope, const std::string &name,
                      const std::string &value) const;

  /**
   * @brief Print a formatted entry without a scope label.
   */
  void PrintEntry(const std::string &name, const std::string &value) const;

  /**
   * @brief Log a per-variable not found error.
   */
  void LogNotFound(const std::string &name) const;

  AMConfigManager &config_manager_;
  AMPromptManager &prompt_manager_;
  mutable std::mutex mutex_;
  std::unordered_map<std::string, std::string> memory_vars_;
};
