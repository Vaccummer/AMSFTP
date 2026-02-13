#pragma once
#include "AMBase/DataClass.hpp"
#include "AMManager/Config.hpp"
#include "AMManager/Prompt.hpp"
#include <atomic>
#include <filesystem>
#include <functional>

class AMLogManager : private NonCopyableNonMovable {
public:
  /** Initialize log manager with settings and resolve log path. */
  explicit AMLogManager() {
    int initial = config_.ResolveArg<int>(
        DocumentKind::Settings, {"InternalVars", "TraceLevel"}, 4,
        [](int v) { return v < -1 ? -1 : (v > 4 ? 4 : v); });
    trace_level_.store(initial, std::memory_order_relaxed);
    auto root = config_.ProjectRoot();
    log_path_ = root.empty() ? std::filesystem::path("AMSFTP.log")
                             : root / "AMSFTP.log";
  }

  /** Cleanup log manager resources. */
  ~AMLogManager() override = default;

  /** Return the singleton instance. */
  static AMLogManager &Instance() {
    static AMLogManager instance;
    return instance;
  }

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
  /** Write a log entry to disk using the background writer thread. */
  void WriteLogEntry_(const TraceInfo &info);

  /** Clamp trace level to the valid range [-1, 4]. */
  static int ClampTraceLevel(int value);

  /** Convert trace level enum to integer severity. */
  static int ToLevelInt(enum TraceLevel level);

  AMConfigManager &config_ = AMConfigManager::Instance();
  AMPromptManager &prompt_manager_ = AMPromptManager::Instance();
  std::filesystem::path log_path_;
  std::atomic<int> trace_level_{4};
};
