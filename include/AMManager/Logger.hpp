#pragma once
#include "AMBase/DataClass.hpp"
#include <atomic>
#include <filesystem>
#include <fstream>
#include <functional>
#include <mutex>
#include <optional>
#include <variant>

class AMLogManager : private NonCopyableNonMovable {
public:
  /** Cleanup log manager resources and close log streams. */
  ~AMLogManager() override { CloseLogStreams_(); }

  /** Return the singleton instance. */
  static AMLogManager &Instance() {
    static AMLogManager instance;
    return instance;
  }

  /** Resolve paths, create the log directory, and open both log files. */
  ECM Init() override;

  /** Enqueue a client trace entry for asynchronous logging. */
  void Enqueue(const TraceInfo &info);

  /** Submit a client trace entry asynchronously to `log/Client.log`. */
  void ClientTrace(const TraceInfo &info);

  /** Submit a client trace entry from fields asynchronously. */
  void ClientTrace(TraceLevel level, EC error_code,
                   const std::string &nickname = "",
                   const std::string &target = "",
                   const std::string &action = "", const std::string &msg = "",
                   std::optional<ConRequest> request = std::nullopt);

  /** Submit a program trace entry asynchronously to `log/Program.log`. */
  void ProgramTrace(const TraceInfo &info);

  /** Submit a structured program trace asynchronously. */
  void ProgramTrace(TraceLevel level, EC error_code,
                    const std::string &target = "",
                    const std::string &action = "",
                    const std::string &msg = "");

  /** Return a client-bound trace callback that submits client traces. */
  std::function<void(const TraceInfo &)> TraceCallbackFunc();

  /**
   * Get or set trace levels with per-target selectors.
   * Selectors default to false. If both `programm` and `client` are false,
   * both are treated as true.
   * `print` controls whether this API call prints the selected level info.
   * When value == -99999, returns current level for the selected target.
   */
  std::variant<int, std::pair<int, int>> TraceLevel(int value = -99999,
                                                    bool programm = false,
                                                    bool client = false,
                                                    bool print = false);

private:
  /** Initialize log manager with settings and resolve log paths. */
  explicit AMLogManager() = default;
  /** Resolve `Client.log` and `Program.log` paths from the project root. */
  void ResolveLogPaths_();

  /** Ensure both log streams are opened in append mode. */
  ECM EnsureLogStreamsOpen_();

  /** Close both log streams if they are currently open. */
  void CloseLogStreams_();

  /** Write one formatted log entry into an already-open output stream. */
  void WriteLogEntry_(const TraceInfo &info, std::ofstream &stream);

  /** Clamp trace level to the valid range [-1, 4]. */
  static int ClampTraceLevel(int value);

  /** Convert trace level enum to integer severity. */
  static int ToLevelInt(enum TraceLevel level);

  std::filesystem::path client_log_path_;
  std::filesystem::path program_log_path_;
  std::ofstream client_log_stream_;
  std::ofstream program_log_stream_;
  std::mutex stream_mtx_;
  std::atomic<int> client_trace_level_{4};
  std::atomic<int> program_trace_level_{4};
};
