#include "AMManager/Logger.hpp"
#include "AMBase/Enum.hpp"
#include "AMManager/Config.hpp"
#include <fstream>
#include <magic_enum/magic_enum.hpp>
#include <sstream>

/** Enqueue a log entry for the writer thread. */
void AMLogManager::Enqueue(const TraceInfo &info) {
  config_.SubmitWriteTask([this, info]() -> ECM {
    WriteLogEntry_(info);
    return {EC::Success, ""};
  });
}

/** Provide a trace callback for AMTracer that enqueues log entries. */
std::function<void(const TraceInfo &)> AMLogManager::TraceCallbackFunc() {
  static auto callback = [this](const TraceInfo &info) { Enqueue(info); };
  return callback;
}

/** Get or set trace level; value == -99999 returns the current level. */
int AMLogManager::TraceLevel(int value) {
  if (value == -99999) {
    return trace_level_.load(std::memory_order_relaxed);
  }
  int clamped = ClampTraceLevel(value);
  trace_level_.store(clamped, std::memory_order_relaxed);
  return clamped;
}

/** Write a log entry to disk using the background writer thread. */
void AMLogManager::WriteLogEntry_(const TraceInfo &info) {
  if (ToLevelInt(info.level) > trace_level_.load(std::memory_order_relaxed)) {
    return;
  }

  try {
    std::ofstream log_file(log_path_, std::ios::app);
    log_file.exceptions(std::ofstream::failbit | std::ofstream::badbit);
    std::string time_str =
        FormatTime(static_cast<size_t>(info.timestamp), "%Y/%m/%d %H:%M:%S");
    std::ostringstream line;
    line << time_str << " " << std::string(magic_enum::enum_name(info.level))
         << " " << info.nickname << " " << info.action << " " << info.target
         << " " << info.message;
    log_file << line.str() << std::endl;
  } catch (const std::exception &ex) {
    prompt_manager_.ErrorFormat("LogWriteError", ex.what());
  } catch (...) {
    prompt_manager_.ErrorFormat("LogWriteError", "Unknown Error");
  }
}

/** Clamp the trace level into the valid range [-1, 4]. */
int AMLogManager::ClampTraceLevel(int value) {
  if (value < -1) {
    return -1;
  }
  if (value > 4) {
    return 4;
  }
  return value;
}

/** Convert TraceLevel enum to integer severity. */
int AMLogManager::ToLevelInt(enum TraceLevel level) {
  return static_cast<int>(level);
}
