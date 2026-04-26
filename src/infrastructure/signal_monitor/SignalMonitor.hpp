#pragma once

#include <atomic>
#include <csignal>
#include <signal.h>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>

// program headers
#include "domain/signal/SignalMonitorPort.hpp"

namespace AMInfra::signal {

/**
 * @brief Signal monitor that safely transfers signal events to a worker thread.
 */
class SignalMonitorImpl final : public AMDomain::signal::SignalMonitor {
public:
  ~SignalMonitorImpl() override;

  SignalMonitorImpl();

  void InstallHandlers();

  void Start();

  ECM Init() override;

  void Stop() override;

  int LastSignal() const override;

  bool RegisterHook(const std::string &name,
                    const AMDomain::signal::SignalHook &hook) override;

  bool UnregisterHook(const std::string &name) override;

  bool SilenceHook(const std::string &name) override;

  bool ResumeHook(const std::string &name) override;

  bool SetHookPriority(const std::string &name, int priority) override;

private:
  static void SignalHandler(int signal_num);

  void Run_();
  std::atomic<bool> running_{false};
  std::atomic<bool> stop_requested_{false};
  std::atomic<int> last_handled_signal_{0};
  std::thread worker_;
  mutable std::mutex hooks_mtx_;
  std::unordered_map<std::string, AMDomain::signal::SignalHook> hooks_;
};

} // namespace AMInfra::signal
