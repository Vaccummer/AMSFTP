#include "AMManager/Logger.hpp"
#include "AMBase/Enum.hpp"
#include <magic_enum/magic_enum.hpp>
#include <fstream>
#include <sstream>

/** Return the singleton instance initialized with the config manager. */
AMLogManager &AMLogManager::Instance(AMConfigManager &cfg) {
  static AMLogManager instance(cfg);
  return instance;
}

/** Initialize log manager with settings and resolve log path. */
AMLogManager::AMLogManager(AMConfigManager &cfg)
    : config_(cfg), prompt_manager_(AMPromptManager::Instance()) {
  int initial = config_.GetSettingInt({"InternalVars", "TraceLevel"}, 4);
  trace_level_.store(ClampTraceLevel(initial));
  auto root = config_.ProjectRoot();
  log_path_ =
      root.empty() ? std::filesystem::path("AMSFTP.log") : root / "AMSFTP.log";
}

/** Cleanup log manager resources. */
AMLogManager::~AMLogManager() {
}

/** Enqueue a log entry for the writer thread. */
void AMLogManager::Enqueue(const TraceInfo &info) {
  config_.SubmitWriteTask([this, info]() { WriteLogEntry_(info); });
}

/** Provide a trace callback for AMTracer that enqueues log entries. */
std::function<void(const TraceInfo &)> AMLogManager::TraceCallbackFunc() {
  return [this](const TraceInfo &info) { Enqueue(info); };
}

/** Get or set trace level; value == -99999 returns the current level. */
int AMLogManager::TraceLevel(int value) {
  if (value == -99999) {
    return trace_level_.load();
  }
  int clamped = ClampTraceLevel(value);
  trace_level_.store(clamped);
  return clamped;
}

/** Write a log entry to disk using the background writer thread. */
void AMLogManager::WriteLogEntry_(const TraceInfo &info) {
  if (ToLevelInt(info.level) > trace_level_.load()) {
    return;
  }

  try {
    std::ofstream log_file(log_path_, std::ios::app);
    log_file.exceptions(std::ofstream::failbit | std::ofstream::badbit);
    std::string time_str =
        FormatTime(static_cast<uint64_t>(info.timestamp),
                   "%Y/%m/%d %H:%M:%S");
    std::ostringstream line;
    line << time_str << " " << std::string(magic_enum::enum_name(info.level))
         << " " << info.nickname << " " << info.action << " " << info.target
         << " " << info.message;
    log_file << line.str() << std::endl;
  } catch (const std::exception &ex) {
    prompt_manager_.ErrorFormat("LogManager", ex.what(), false, 0, __func__);
  } catch (...) {
    prompt_manager_.ErrorFormat("LogManager", "Unknown log error", false, 0,
                                __func__);
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


