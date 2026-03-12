#pragma once
#define _WINSOCKAPI_
#include <atomic>
#ifdef _WIN32
#include <windows.h>
#else
#include <csignal>
#include <signal.h>
#endif
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>

// program headers
#include "domain/signal/SignalMonitorPort.hpp"

/**
 * @brief Signal monitor that safely transfers signal events to a worker thread.
 */
class AMInfraCliSignalMonitor : public AMSignalMonitorPort {
public:
  /**
   * @brief Stop the worker thread on destruction.
   */
  ~AMInfraCliSignalMonitor();

  /**
   * @brief Construct signal monitor.
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
  void Stop() override;

  /**
   * @brief Get the last signal observed by the worker loop.
   */
  int LastSignal() const override;

  /**
   * @brief Register a signal hook (name must be unique).
   */
  bool RegisterHook(const std::string &name,
                    const AMDomain::signal::SignalHook &hook) override;

  /**
   * @brief Unregister a signal hook by name.
   */
  bool UnregisterHook(const std::string &name) override;

  /**
   * @brief Silence a hook by name.
   */
  bool SilenceHook(const std::string &name) override;

  /**
   * @brief Resume a silenced hook by name.
   */
  bool ResumeHook(const std::string &name) override;

  /**
   * @brief Update a hook priority by name.
   */
  bool SetHookPriority(const std::string &name, int priority) override;

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
   * @brief Worker loop that consumes recorded signals.
   */
  void Run_();

  std::atomic<bool> running_{false};
  std::atomic<int> last_handled_signal_{0};
  std::thread worker_;
  mutable std::mutex hooks_mtx_;
  std::unordered_map<std::string, AMDomain::signal::SignalHook> hooks_;
};
