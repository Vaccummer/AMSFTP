#pragma once

#include "AMConfigManager.hpp"
#include "AMDataClass.hpp"
#include "AMPromptManager.hpp"
#include <atomic>
#include <condition_variable>
#include <deque>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <thread>

class AMLogManager {
public:
  /** Return the singleton instance (requires a valid config manager). */
  static AMLogManager &Instance(AMConfigManager &cfg);

  /** Disable copy construction. */
  AMLogManager(const AMLogManager &) = delete;
  /** Disable copy assignment. */
  AMLogManager &operator=(const AMLogManager &) = delete;
  /** Disable move construction. */
  AMLogManager(AMLogManager &&) = delete;
  /** Disable move assignment. */
  AMLogManager &operator=(AMLogManager &&) = delete;

  /** Shutdown worker thread and flush pending logs. */
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
  /** Construct with config manager and start worker thread. */
  explicit AMLogManager(AMConfigManager &cfg);

  /** Worker loop that writes queued log entries to disk. */
  void WorkerLoop();

  /** Ensure the log file is open; returns true on success. */
  bool EnsureLogFile();

  /** Clamp trace level to the valid range [-1, 4]. */
  static int ClampTraceLevel(int value);

  /** Convert trace level enum to integer severity. */
  static int ToLevelInt(enum TraceLevel level);

  AMConfigManager &config_;
  AMPromptManager &prompt_manager_;
  std::filesystem::path log_path_;
  std::ofstream log_file_;
  std::mutex queue_mtx_;
  std::condition_variable queue_cv_;
  std::deque<TraceInfo> queue_;
  std::thread worker_;
  std::atomic<bool> running_{false};
  std::atomic<int> trace_level_{4};
};
