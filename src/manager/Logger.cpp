#include "AMManager/Logger.hpp"
#include "AMBase/Enum.hpp"
#include "AMManager/Config.hpp"
#include <magic_enum/magic_enum.hpp>
#include <sstream>
#include <utility>

/** Enqueue a client trace entry for asynchronous logging. */
void AMLogManager::Enqueue(const TraceInfo &info) { ClientTrace(info); }

/** Submit a client trace entry asynchronously to `log/Client.log`. */
void AMLogManager::ClientTrace(const TraceInfo &info) {
  TraceInfo normalized = info;
  normalized.source = TraceSource::Client;
  config_.SubmitWriteTask([this, normalized]() -> ECM {
    std::lock_guard<std::mutex> lock(stream_mtx_);
    ECM open_rcm = EnsureLogStreamsOpen_();
    if (!isok(open_rcm)) {
      return open_rcm;
    }
    if (!client_log_stream_.is_open()) {
      return Err(EC::LocalFileError,
                 AMStr::amfmt("Failed to open {}", client_log_path_.string()));
    }
    WriteLogEntry_(normalized, client_log_stream_);
    return Ok();
  });
}

/** Submit a client trace entry from fields asynchronously. */
void AMLogManager::ClientTrace(enum TraceLevel level, EC error_code,
                               const std::string &nickname,
                               const std::string &target,
                               const std::string &action,
                               const std::string &msg,
                               std::optional<ConRequest> request) {
  TraceInfo trace(level, error_code, nickname, target, action, msg,
                  std::move(request), TraceSource::Client);
  ClientTrace(trace);
}

/** Provide a client-bound trace callback that submits client trace entries. */
std::function<void(const TraceInfo &)> AMLogManager::TraceCallbackFunc() {
  static auto callback = [this](const TraceInfo &info) { ClientTrace(info); };
  return callback;
}

/** Submit a structured program trace asynchronously. */
void AMLogManager::ProgramTrace(enum TraceLevel level, EC error_code,
                                const std::string &target,
                                const std::string &action,
                                const std::string &msg) {
  TraceInfo trace(level, error_code, "", target, action, msg, std::nullopt,
                  TraceSource::Programm);
  ProgramTrace(trace);
}

/** Submit a program trace entry asynchronously to `log/Program.log`. */
void AMLogManager::ProgramTrace(const TraceInfo &info) {
  TraceInfo normalized = info;
  normalized.source = TraceSource::Programm;
  normalized.request = std::nullopt;
  config_.SubmitWriteTask([this, normalized]() -> ECM {
    std::lock_guard<std::mutex> lock(stream_mtx_);
    ECM open_rcm = EnsureLogStreamsOpen_();
    if (!isok(open_rcm)) {
      return open_rcm;
    }
    if (!program_log_stream_.is_open()) {
      return Err(EC::LocalFileError,
                 AMStr::amfmt("Failed to open {}", program_log_path_.string()));
    }
    WriteLogEntry_(normalized, program_log_stream_);
    return Ok();
  });
}

/** Get or set trace levels for selected targets. */
std::variant<int, std::pair<int, int>>
AMLogManager::TraceLevel(int value, bool programm, bool client, bool print) {
  if (!programm && !client) {
    programm = true;
    client = true;
  }

  const int client_level = client_trace_level_.load(std::memory_order_relaxed);
  const int program_level =
      program_trace_level_.load(std::memory_order_relaxed);

  if (value == -99999) {
    if (print) {
      if (client && programm) {
        prompt_manager_.Print(
            AMStr::amfmt("TraceLevel: client = {}, program = {}", client_level,
                         program_level));
      } else if (client) {
        prompt_manager_.Print(
            AMStr::amfmt("TraceLevel: client = {}", client_level));
      } else if (programm) {
        prompt_manager_.Print(
            AMStr::amfmt("TraceLevel: program = {}", program_level));
      }
    }
    if (client && programm) {
      return std::pair(client_level, program_level);
    }
    if (client) {
      return client_level;
    }
    if (programm) {
      return program_level;
    }
    return client_level;
  }

  int clamped = ClampTraceLevel(value);
  if (client) {
    client_trace_level_.store(clamped, std::memory_order_relaxed);
  }
  if (programm) {
    program_trace_level_.store(clamped, std::memory_order_relaxed);
  }
  if (print) {
    if (client && programm) {
      prompt_manager_.Print(AMStr::amfmt(
          "TraceLevel set: client = {}, program = {}", clamped, clamped));
    } else if (client) {
      prompt_manager_.Print(
          AMStr::amfmt("TraceLevel set: client = {}", clamped));
    } else if (programm) {
      prompt_manager_.Print(
          AMStr::amfmt("TraceLevel set: program = {}", clamped));
    }
  }
  return clamped;
}

/** Resolve `Client.log` and `Program.log` paths from the project root. */
void AMLogManager::ResolveLogPaths_() {
  const auto root = config_.ProjectRoot();
  const auto base =
      root.empty() ? std::filesystem::path(".") : std::filesystem::path(root);
  client_log_path_ = base / "log" / "Client.log";
  program_log_path_ = base / "log" / "Program.log";
}

/** Ensure both log streams are opened in append mode. */
ECM AMLogManager::EnsureLogStreamsOpen_() {
  ResolveLogPaths_();
  std::error_code ec;
  std::filesystem::create_directories(client_log_path_.parent_path(), ec);
  if (ec) {
    return fecm(ec);
  }

  if (!client_log_stream_.is_open()) {
    client_log_stream_.clear();
    client_log_stream_.open(client_log_path_, std::ios::app);
    if (!client_log_stream_.is_open()) {
      return Err(EC::LocalFileError,
                 AMStr::amfmt("Failed to open {}", client_log_path_.string()));
    }
  }
  if (!program_log_stream_.is_open()) {
    program_log_stream_.clear();
    program_log_stream_.open(program_log_path_, std::ios::app);
    if (!program_log_stream_.is_open()) {
      return Err(EC::LocalFileError,
                 AMStr::amfmt("Failed to open {}", program_log_path_.string()));
    }
  }
  return Ok();
}

/** Close both log streams if they are currently open. */
void AMLogManager::CloseLogStreams_() {
  std::lock_guard<std::mutex> lock(stream_mtx_);
  if (client_log_stream_.is_open()) {
    client_log_stream_.flush();
    client_log_stream_.close();
  }
  if (program_log_stream_.is_open()) {
    program_log_stream_.flush();
    program_log_stream_.close();
  }
}

/** Write one formatted log entry into an already-open output stream. */
void AMLogManager::WriteLogEntry_(const TraceInfo &info,
                                  std::ofstream &stream) {
  int trace_limit = client_trace_level_.load(std::memory_order_relaxed);
  if (info.source == TraceSource::Programm) {
    trace_limit = program_trace_level_.load(std::memory_order_relaxed);
  }
  if (ToLevelInt(info.level) > trace_limit) {
    return;
  }
  if (!stream.is_open()) {
    return;
  }
  try {
    const double stamp = info.timestamp > 0 ? info.timestamp : timenow();
    const std::string time_str =
        FormatTime(static_cast<size_t>(stamp), "%Y/%m/%d %H:%M:%S");
    std::ostringstream line;
    line << time_str << " [" << std::string(magic_enum::enum_name(info.source))
         << "] [" << std::string(magic_enum::enum_name(info.level)) << "]";
    if (!info.nickname.empty()) {
      line << " [nick:" << info.nickname << "]";
    }
    if (!info.action.empty()) {
      line << " [action:" << info.action << "]";
    }
    if (!info.target.empty()) {
      line << " [target:" << info.target << "]";
    }
    if (info.request.has_value() && !info.request->hostname.empty()) {
      line << " [host:" << info.request->hostname << "]";
    }
    if (!info.message.empty()) {
      line << " " << info.message;
    }
    stream << line.str() << std::endl;
    stream.flush();
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
