#include "AMLogManager.hpp"
#include "base/AMEnum.hpp"
#include <magic_enum/magic_enum.hpp>
#include <sstream>

/** Return the singleton instance initialized with the config manager. */
AMLogManager &AMLogManager::Instance(AMConfigManager &cfg) {
  static AMLogManager instance(cfg);
  return instance;
}

/** Initialize log manager with settings and start worker thread. */
AMLogManager::AMLogManager(AMConfigManager &cfg)
    : config_(cfg), prompt_manager_(AMPromptManager::Instance()) {
  int initial = config_.GetSettingInt({"InternalVars", "TraceLevel"}, 4);
  trace_level_.store(ClampTraceLevel(initial));
  auto root = config_.ProjectRoot();
  log_path_ =
      root.empty() ? std::filesystem::path("AMSFTP.log") : root / "AMSFTP.log";
  running_.store(true);
  worker_ = std::thread([this]() { WorkerLoop(); });
}

/** Stop worker thread and close log file if needed. */
AMLogManager::~AMLogManager() {
  running_.store(false);
  queue_cv_.notify_all();
  if (worker_.joinable()) {
    worker_.join();
  }
}

/** Enqueue a log entry for the writer thread. */
void AMLogManager::Enqueue(const TraceInfo &info) {
  {
    std::lock_guard<std::mutex> lock(queue_mtx_);
    queue_.push_back(info);
  }
  queue_cv_.notify_one();
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

/** Worker loop that writes queued entries to the log file. */
void AMLogManager::WorkerLoop() {
  while (running_.load()) {
    TraceInfo item;
    {
      std::unique_lock<std::mutex> lock(queue_mtx_);
      queue_cv_.wait(lock,
                     [this]() { return !running_.load() || !queue_.empty(); });
      if (!running_.load() && queue_.empty()) {
        break;
      }
      item = queue_.front();
      queue_.pop_front();
    }

    if (ToLevelInt(item.level) > trace_level_.load()) {
      continue;
    }

    try {
      if (!EnsureLogFile()) {
        continue;
      }
      std::string time_str = FormatTime(static_cast<uint64_t>(item.timestamp),
                                        "%Y/%m/%d %H:%M:%S");
      std::ostringstream line;
      line << time_str << " " << std::string(magic_enum::enum_name(item.level))
           << " " << item.nickname << " " << item.action << " " << item.target
           << " " << item.message;
      log_file_ << line.str() << std::endl;
    } catch (const std::exception &ex) {
      prompt_manager_.ErrorFormat("LogManager", ex.what(), false, 0, __func__);
      if (log_file_.is_open()) {
        log_file_.close();
      }
    } catch (...) {
      prompt_manager_.ErrorFormat("LogManager", "Unknown log error", false, 0,
                                  __func__);
      if (log_file_.is_open()) {
        log_file_.close();
      }
    }

    {
      std::lock_guard<std::mutex> lock(queue_mtx_);
      if (queue_.empty() && log_file_.is_open()) {
        log_file_.close();
      }
    }
  }
}

/** Ensure the log file is open and ready for writing. */
bool AMLogManager::EnsureLogFile() {
  if (log_file_.is_open()) {
    return true;
  }
  try {
    log_file_.open(log_path_, std::ios::app);
    log_file_.exceptions(std::ofstream::failbit | std::ofstream::badbit);
    return log_file_.is_open();
  } catch (const std::exception &ex) {
    prompt_manager_.ErrorFormat("LogManager", ex.what(), false, 0, __func__);
    return false;
  } catch (...) {
    prompt_manager_.ErrorFormat("LogManager", "Unknown log open error", false,
                                0, __func__);
    return false;
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
