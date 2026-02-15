#pragma once
#include "AMManager/Config.hpp"
#include "AMManager/Prompt.hpp"
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

class AMVarManager : private NonCopyableNonMovable {
public:
  enum class VarSource { Public, Private, Memory };

  /**
   * @brief Return the singleton variable manager bound to a config manager.
   */
  static AMVarManager &Instance() {
    static AMVarManager instance;
    return instance;
  };

  /**
   * @brief Set or overwrite an in-memory variable, confirming overwrites.
   */
  ECM SetMemoryVar(const std::string &name, const std::string &value,
                   bool confirm_overwrite = true);

  /**
   * @brief Set or overwrite a persistent variable in storage only.
   */
  ECM SetPersistentVar(const std::string &name, const std::string &value,
                       bool confirm_overwrite = true);

  /**
   * @brief Resolve a variable value from memory or settings.
   */
  bool Resolve(const std::string &name, std::string *value = nullptr,
               VarSource *source = nullptr) const;

  /**
   * @brief Query an in-memory variable.
   */
  bool GetMemVar(const std::string &name, std::string *value) const;

  /**
   * @brief Query a persistent variable from storage.
   */
  bool GetUserVar(const std::string &name, std::string *value) const;

  /**
   * @brief List all persistent variables from storage.
   */
  [[nodiscard]] std::vector<std::pair<std::string, std::string>>
  ListUserVars() const;

  /**
   * @brief Set a persistent variable and optionally dump settings.
   */
  ECM SetUserVar(const std::string &name, const std::string &value,
                 bool dump_now = true);

  /**
   * @brief Remove a persistent variable and optionally dump settings.
   */
  ECM RemoveUserVar(const std::string &name, bool dump_now = true);

  /**
   * @brief Query variables in memory and storage, printing results.
   */
  ECM Query(const std::vector<std::string> &names);

  /**
   * @brief Execute `var` command tokens (enumerate/query/assignment).
   */
  ECM ExecuteVarTokens(const std::vector<std::string> &tokens);

  /**
   * @brief Execute `del` command tokens (parse names then delete).
   */
  ECM ExecuteDelTokens(const std::vector<std::string> &tokens);

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

  /**
   * @brief List variable names from memory and storage.
   */
  std::vector<std::string> ListNames() const;

private:
  /**
   * @brief Construct a variable manager tied to the config manager.
   */
  explicit AMVarManager() = default;

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
   * @brief Format a variable key/value using the UserVars style.
   */
  std::string FormatUserVarText(const std::string &text) const;

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

  AMConfigManager &config_manager_ = AMConfigManager::Instance();
  AMPromptManager &prompt_manager_ = AMPromptManager::Instance();
  mutable std::mutex mutex_;
  std::unordered_map<std::string, std::string> memory_vars_;
};
