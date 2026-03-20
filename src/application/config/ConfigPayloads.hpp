#pragma once

#include "application/config/StyleSettings.hpp"
#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace AMApplication::config {
/**
 * @brief Typed subtree for `Settings.Options.AutoConfigBackup`.
 */
struct AutoBackupSettings {
  bool enabled = true;
  int64_t interval_s = 60;
  int64_t max_backup_count = 3;
  int64_t last_backup_time_s = 0;
};

/**
 * @brief Typed subtree for `Settings.Options.ClientManager`.
 */
struct ClientManagerOptions {
  int heartbeat_interval_s = 60;
  int heartbeat_timeout_ms = 100;
};

/**
 * @brief Typed subtree for `Settings.Options.TransferManager`.
 */
struct TransferManagerOptions {
  int init_thread_num = 1;
  int max_thread_num = 16;
};

/**
 * @brief Typed subtree for `Settings.Options.FileSystem`.
 */
struct FileSystemOptions {
  int max_cd_history = 5;
};

/**
 * @brief Typed subtree for `Settings.Options.LogManager`.
 */
struct LogManagerOptions {
  int client_trace_level = 4;
  int program_trace_level = 4;
};

/**
 * @brief Typed subtree for `Settings.Options`.
 */
struct SettingsOptionsSnapshot {
  ClientManagerOptions client_manager{};
  TransferManagerOptions transfer_manager{};
  FileSystemOptions filesystem{};
  LogManagerOptions log_manager{};
  AutoBackupSettings auto_config_backup{};
};

/**
 * @brief Typed subtree for `Settings.UserVars`.
 */
struct UserVarsSnapshot {
  using DomainVars = std::map<std::string, std::string>;
  using DomainDict = std::map<std::string, DomainVars>;

  DomainDict domains = {};
};

/**
 * @brief Typed prompt marker settings for one prompt profile.
 */
struct PromptProfilePromptSettings {
  std::string marker = "";
  std::string continuation_marker = ">";
  bool enable_multiline = false;
};

/**
 * @brief Typed history settings for one prompt profile.
 */
struct PromptProfileHistorySettings {
  bool enable = true;
  bool enable_duplicates = true;
  int max_count = 30;
};

/**
 * @brief Typed inline-hint path settings for one prompt profile.
 */
struct PromptProfileInlineHintPathSettings {
  bool enable = true;
  bool use_async = false;
  size_t timeout_ms = 600;
};

/**
 * @brief Typed inline-hint settings for one prompt profile.
 */
struct PromptProfileInlineHintSettings {
  bool enable = true;
  int render_delay_ms = 30;
  int search_delay_ms = 0;
  PromptProfileInlineHintPathSettings path{};
};

/**
 * @brief Typed completion-path settings for one prompt profile.
 */
struct PromptProfileCompletePathSettings {
  bool use_async = false;
  size_t timeout_ms = 3000;
};

/**
 * @brief Typed completion settings for one prompt profile.
 */
struct PromptProfileCompleteSettings {
  PromptProfileCompletePathSettings path{};
};

/**
 * @brief Typed highlight-path settings for one prompt profile.
 */
struct PromptProfileHighlightPathSettings {
  bool enable = true;
  size_t timeout_ms = 1000;
};

/**
 * @brief Typed highlight settings for one prompt profile.
 */
struct PromptProfileHighlightSettings {
  int delay_ms = 0;
  PromptProfileHighlightPathSettings path{};
};

/**
 * @brief Persisted prompt-profile settings for one nickname key.
 */
struct PromptProfileSettings {
  PromptProfilePromptSettings prompt{};
  PromptProfileHistorySettings history{};
  PromptProfileInlineHintSettings inline_hint{};
  PromptProfileCompleteSettings complete{};
  PromptProfileHighlightSettings highlight{};
};

/**
 * @brief Typed subtree for `Settings.PromptProfile`.
 */
struct PromptProfileDocument {
  std::map<std::string, PromptProfileSettings> profiles = {};
};

/**
 * @brief Typed root payload for `History` document.
 */
struct PromptHistoryDocument {
  std::map<std::string, std::vector<std::string>> commands_by_profile = {};
};
} // namespace AMApplication::config
