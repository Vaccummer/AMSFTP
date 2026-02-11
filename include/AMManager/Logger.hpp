#pragma once

#include "AMBase/DataClass.hpp"
#include "AMManager/Config.hpp"
#include "AMManager/Prompt.hpp"
#include <atomic>
#include <filesystem>
#include <functional>

class AMLogManager : private NonCopyableNonMovable {
public:
  /** Return the singleton instance (requires a valid config manager). */
  static AMLogManager &Instance(AMConfigManager &cfg);

  /** Cleanup log manager resources. */
  ~AMLogManager();

  /** Enqueue a trace entry for asynchronous logging. */
  void Enqueue(const TraceInfo &info);

  /** Return a trace callback that enqueues trace entries. */
  std::function<void(const TraceInfo &)> TraceCallbackFunc();

  /**
   * Get or set the trace level.
   * When value == -99999, returns current level without modifying.
   */
  int TraceLevel(int value = -99999);

private:
  /** Construct with config manager and resolve log settings. */
  explicit AMLogManager(AMConfigManager &cfg);

  /** Write a log entry to disk using the background writer thread. */
  void WriteLogEntry_(const TraceInfo &info);

  /** Clamp trace level to the valid range [-1, 4]. */
  static int ClampTraceLevel(int value);

  /** Convert trace level enum to integer severity. */
  static int ToLevelInt(enum TraceLevel level);

  AMConfigManager &config_;
  AMPromptManager &prompt_manager_;
  std::filesystem::path log_path_;
  std::atomic<int> trace_level_{4};
};
