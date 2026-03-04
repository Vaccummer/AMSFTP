#pragma once
#define _WINSOCKAPI_
#include <atomic>
#ifdef _WIN32
#include <windows.h>
#else
#include <csignal>
#include <signal.h>
#endif
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>

// programm headers
#include "foundation/DataClass.hpp"

/**
 * @brief Signal monitor that safely transfers signal events to a worker thread.
 */
class AMInfraCliSignalMonitor : private NonCopyableNonMovable {
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
   * @brief Stop the worker thread on destruction.
   */
  ~AMInfraCliSignalMonitor() override;

  /**
   * @brief Construct signal monitor with explicit external token binding.
   */
  AMInfraCliSignalMonitor();

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
   * @brief Bind a task-control token used for Ctrl+C/Ctrl+Break propagation.
   * @param token Shared task-control token pointer.
   */
  void BindTaskControlToken(const std::shared_ptr<TaskControlToken> &token);

  /**
   * @brief Clear the currently bound task-control token.
   */
  void ClearTaskControlToken();

  /**
   * @brief Get a strong pointer to the currently bound task-control token.
   * @return Shared task-control token pointer or nullptr.
   */
  [[nodiscard]] std::shared_ptr<TaskControlToken> BoundTaskControlToken() const;

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
private:
  /**
   * @brief Ensure GLOBAL hook exists and keeps canonical defaults.
   */
  void EnsureGlobalHook_();

  /**
   * @brief Worker loop that consumes recorded signals.
   */
  void Run_();

  /**
   * @brief Resolve the bound task-control token to a strong pointer.
   * @return Shared task-control token pointer or nullptr.
   */
  [[nodiscard]] std::shared_ptr<TaskControlToken> ResolveTaskControlToken_() const;

  std::atomic<bool> running_{false};
  std::atomic<int> last_handled_signal_{0};
  std::thread worker_;
  mutable std::mutex hooks_mtx_;
  mutable std::mutex token_mtx_;
  std::weak_ptr<TaskControlToken> task_control_token_;
  std::unordered_map<std::string, SignalHook> hooks_;
};
