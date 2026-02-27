#pragma once
#define _WINSOCKAPI_
#include <atomic>
#include <csignal>
#ifdef _WIN32
#include <windows.h>
#else
#include <consoleapi.h>
#endif
#include <functional>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>

// programm headers
#include "AMBase/DataClass.hpp"

/**
 * @brief Global signal code observed by the CLI signal monitor.
 */
extern std::atomic<int> GlobalSignalInt;

/**
 * @brief Signal monitor that safely transfers signal events to a worker thread.
 */
class AMCliSignalMonitor : private NonCopyableNonMovable {
public:
  using SignalCallback = std::function<void(int)>;
  /**
   * @brief Hook container for a signal subscriber.
   */
  struct SignalHook {
    SignalCallback callback;
    bool is_silenced = false;
    /** Higher values run first. */
    int priority = 0;
    /** Stop propagation to lower-priority hooks when set. */
    bool consume = false;
  };

  /**
   * @brief Return the singleton instance.
   */
  static AMCliSignalMonitor &Instance();

  /**
   * @brief Stop the worker thread on destruction.
   */
  ~AMCliSignalMonitor() override;

  /**
   * @brief Install signal handlers for SIGINT/SIGTERM.
   */
  void InstallHandlers();

  /**
   * @brief Start the background worker thread.
   */
  void Start();

  ECM Init() override;

  /**
   * @brief Stop the background worker thread.
   */
  void Stop();

  /**
   * @brief Get the last signal observed by the worker loop.
   */
  int LastSignal() const;

  /**
   * @brief Register a signal hook (name must be unique).
   */
  bool RegisterHook(const std::string &name, const SignalHook &hook);

  /**
   * @brief Unregister a signal hook (GLOBAL cannot be unregistered).
   */
  bool UnregisterHook(const std::string &name);

  /**
   * @brief Silence a hook by name (GLOBAL can be silenced).
   */
  bool SilenceHook(const std::string &name);

  /**
   * @brief Resume a silenced hook by name.
   */
  bool ResumeHook(const std::string &name);

  /**
   * @brief Update a hook priority (GLOBAL not supported).
   */
  bool SetHookPriority(const std::string &name, int priority);

  /**
   * @brief Signal handler to record the signal number.
   */
  static void SignalHandler(int signum);

private:
#ifdef _WIN32
  /**
   * @brief Console control handler for CTRL+C/CTRL+BREAK.
   */
  static BOOL WINAPI ConsoleCtrlHandler_(DWORD type);
#endif
  AMCliSignalMonitor();

  /**
   * @brief Ensure GLOBAL hook exists and keeps canonical defaults.
   */
  void EnsureGlobalHook_();

  /**
   * @brief Worker loop that consumes recorded signals.
   */
  void Run_();

  std::atomic<bool> running_{false};
  std::atomic<int> last_handled_signal_{0};
  std::thread worker_;
  mutable std::mutex hooks_mtx_;
  std::unordered_map<std::string, SignalHook> hooks_;
};
