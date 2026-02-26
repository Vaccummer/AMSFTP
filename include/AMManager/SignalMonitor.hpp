#pragma once
#define _WINSOCKAPI_
#include <algorithm>
#include <atomic>
#include <chrono>
#include <csignal>
#include <iostream>
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
#include <vector>

// programm headers
#include "AMBase/DataClass.hpp"

/**
 * @brief Global signal code observed by the CLI signal monitor.
 */
inline std::atomic<int> GlobalSignalInt = 0;

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
    amf interrupt_flag;
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
  static AMCliSignalMonitor &Instance() {
    static AMCliSignalMonitor instance;
    return instance;
  }

  /**
   * @brief Stop the worker thread on destruction.
   */
  ~AMCliSignalMonitor() override { Stop(); }

  /**
   * @brief Install signal handlers for SIGINT/SIGTERM.
   */
  void InstallHandlers() {
#ifdef _WIN32
    SetConsoleCtrlHandler(AMCliSignalMonitor::ConsoleCtrlHandler_, TRUE);
#else
    struct sigaction sa{};
    sa.sa_handler = AMCliSignalMonitor::SignalHandler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    sigaction(SIGINT, &sa, nullptr);
#ifdef SIGTERM
    sigaction(SIGTERM, &sa, nullptr);
#endif
#endif
  }

  /**
   * @brief Start the background worker thread.
   */
  void Start() {
    if (running_.exchange(true, std::memory_order_acq_rel)) {
      return;
    }
    worker_ = std::thread([this]() { Run_(); });
  }

  ECM Init() override {
    EnsureGlobalHook_();
    InstallHandlers();
    Start();
    return Ok();
  }

  /**
   * @brief Stop the background worker thread.
   */
  void Stop() {
    running_.store(false, std::memory_order_release);
    if (worker_.joinable()) {
      worker_.join();
    }
  }

  /**
   * @brief Get the last signal observed by the worker loop.
   */
  int LastSignal() const {
    return last_handled_signal_.load(std::memory_order_relaxed);
  }

  /**
   * @brief Register a signal hook (name must be unique).
   */
  bool RegisterHook(const std::string &name, const SignalHook &hook) {
    if (name.empty()) {
      return false;
    }
    std::lock_guard<std::mutex> lock(hooks_mtx_);
    if (hooks_.find(name) != hooks_.end()) {
      return false;
    }
    hooks_[name] = hook;
    if (name == "GLOBAL") {
      hooks_[name].interrupt_flag = amgif;
      hooks_[name].priority = 0;
      hooks_[name].consume = false;
    }
    return true;
  }

  /**
   * @brief Unregister a signal hook (GLOBAL cannot be unregistered).
   */
  bool UnregisterHook(const std::string &name) {
    if (name.empty() || name == "GLOBAL") {
      return false;
    }
    std::lock_guard<std::mutex> lock(hooks_mtx_);
    return hooks_.erase(name) > 0;
  }

  /**
   * @brief Silence a hook by name (GLOBAL can be silenced).
   */
  bool SilenceHook(const std::string &name) {
    if (name.empty()) {
      return false;
    }
    std::lock_guard<std::mutex> lock(hooks_mtx_);
    auto it = hooks_.find(name);
    if (it == hooks_.end()) {
      return false;
    }
    it->second.is_silenced = true;
    return true;
  }

  /**
   * @brief Resume a silenced hook by name.
   */
  bool ResumeHook(const std::string &name) {
    if (name.empty()) {
      return false;
    }
    std::lock_guard<std::mutex> lock(hooks_mtx_);
    auto it = hooks_.find(name);
    if (it == hooks_.end()) {
      return false;
    }
    it->second.is_silenced = false;
    return true;
  }

  /**
   * @brief Update a hook priority (GLOBAL not supported).
   */
  bool SetHookPriority(const std::string &name, int priority) {
    if (name.empty() || name == "GLOBAL") {
      return false;
    }
    std::lock_guard<std::mutex> lock(hooks_mtx_);
    auto it = hooks_.find(name);
    if (it == hooks_.end()) {
      return false;
    }
    it->second.priority = priority;
    return true;
  }

  /**
   * @brief Signal handler to record the signal number.
   */
  static void SignalHandler(int signum) { GlobalSignalInt.store(signum); }

private:
#ifdef _WIN32
  /**
   * @brief Console control handler for CTRL+C/CTRL+BREAK.
   */
  static BOOL WINAPI ConsoleCtrlHandler_(DWORD type) {
    switch (type) {
    case CTRL_C_EVENT: // ctrl-c trigger
      GlobalSignalInt.store(SIGINT);
      return TRUE;
    case CTRL_BREAK_EVENT: // ctrl-break trigger
      GlobalSignalInt.store(SIGTERM);
      return TRUE;
    case CTRL_CLOSE_EVENT: // window close trigger
      GlobalSignalInt.store(SIGTERM);
      return TRUE;
    default:
      return FALSE;
    }
  }
#endif
  AMCliSignalMonitor() = default;

  /**
   * @brief Ensure GLOBAL hook exists and keeps canonical defaults.
   */
  void EnsureGlobalHook_() {
    std::lock_guard<std::mutex> lock(hooks_mtx_);
    auto it = hooks_.find("GLOBAL");
    if (it == hooks_.end()) {
      SignalHook global;
      global.interrupt_flag = amgif;
      global.callback = {};
      global.is_silenced = false;
      global.priority = 0;
      global.consume = false;
      hooks_["GLOBAL"] = std::move(global);
      return;
    }
    it->second.interrupt_flag = amgif;
    it->second.priority = 0;
    it->second.consume = false;
  }

  /**
   * @brief Worker loop that consumes recorded signals.
   */
  void Run_() {
    while (running_.load(std::memory_order_acquire)) {
      int signum = GlobalSignalInt.exchange(0);
      if (signum != 0) {
        last_handled_signal_.store(signum, std::memory_order_relaxed);
        std::cout << "Signal " << last_handled_signal_
                  << " received, processing hooks..." << std::endl;
        std::vector<SignalHook> hooks;
        {
          std::lock_guard<std::mutex> lock(hooks_mtx_);
          hooks.reserve(hooks_.size());
          for (const auto &entry : hooks_) {
            hooks.push_back(entry.second);
          }
        }
        std::sort(hooks.begin(), hooks.end(),
                  [](const SignalHook &a, const SignalHook &b) {
                    return a.priority > b.priority;
                  });
        for (const auto &hook : hooks) {
          if (hook.is_silenced) {
            continue;
          }
          if (hook.callback) {
            hook.callback(signum);
          }
          if (hook.interrupt_flag) {
            hook.interrupt_flag->set(true);
            std::cout << "Signal " << signum
                      << " received, interrupt flag set by hook callback."
                      << std::endl;
          }
          if (hook.consume) {
            break;
          }
        }
        if ((signum == SIGINT || signum == SIGTERM) && amgif) {
          amgif->set(true);
        }
      }
      std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
  }

  std::atomic<bool> running_{false};
  std::atomic<int> last_handled_signal_{0};
  std::thread worker_;
  mutable std::mutex hooks_mtx_;
  std::unordered_map<std::string, SignalHook> hooks_;
};
