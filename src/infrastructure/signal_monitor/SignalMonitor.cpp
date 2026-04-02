#include "infrastructure/signal_monitor/SignalMonitor.hpp"
#include <algorithm>
#include <chrono>
#include <foundation/tools/enum_related.hpp>
#include <memory>
#include <utility>
#include <vector>

namespace {
std::atomic<int> GlobalSignalInt{0};
} // namespace

namespace AMInfra::signal {

/** Stop worker resources during teardown. */
SignalMonitorImpl::~SignalMonitorImpl() { Stop(); }

void SignalMonitorImpl::InstallHandlers() {
#ifdef _WIN32
  SetConsoleCtrlHandler(SignalMonitorImpl::ConsoleCtrlHandler_, TRUE);
#else
  struct sigaction sa{};
  sa.sa_handler = SignalMonitorImpl::SignalHandler;
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = SA_RESTART;
  sigaction(SIGINT, &sa, nullptr);
#ifdef SIGTERM
  sigaction(SIGTERM, &sa, nullptr);
#endif
#endif
}

void SignalMonitorImpl::Start() {
  if (running_.exchange(true, std::memory_order_acq_rel)) {
    return;
  }
  worker_ = std::thread([this]() { Run_(); });
}

ECM SignalMonitorImpl::Init() {
  InstallHandlers();
  Start();
  return OK;
}

void SignalMonitorImpl::Stop() {
  running_.store(false, std::memory_order_release);
  if (worker_.joinable()) {
    worker_.join();
  }
}

int SignalMonitorImpl::LastSignal() const {
  return last_handled_signal_.load(std::memory_order_relaxed);
}

bool SignalMonitorImpl::RegisterHook(const std::string &name,
                                     const AMDomain::signal::SignalHook &hook) {
  if (name.empty()) {
    return false;
  }
  std::lock_guard<std::mutex> lock(hooks_mtx_);
  if (hooks_.find(name) != hooks_.end()) {
    return false;
  }
  hooks_[name] = hook;
  return true;
}

bool SignalMonitorImpl::UnregisterHook(const std::string &name) {
  if (name.empty()) {
    return false;
  }
  std::lock_guard<std::mutex> lock(hooks_mtx_);
  return hooks_.erase(name) > 0;
}

bool SignalMonitorImpl::SilenceHook(const std::string &name) {
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

bool SignalMonitorImpl::ResumeHook(const std::string &name) {
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

bool SignalMonitorImpl::SetHookPriority(const std::string &name, int priority) {
  if (name.empty()) {
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

#ifdef _WIN32
BOOL WINAPI SignalMonitorImpl::ConsoleCtrlHandler_(DWORD type) {
  switch (type) {
  case CTRL_C_EVENT:
    GlobalSignalInt.store(SIGINT);
    return TRUE;
  case CTRL_BREAK_EVENT:
    GlobalSignalInt.store(SIGTERM);
    return TRUE;
  case CTRL_CLOSE_EVENT:
    GlobalSignalInt.store(SIGTERM);
    return TRUE;
  default:
    return FALSE;
  }
}
#else
void SignalMonitorImpl::SignalHandler(int signal_num) {
  if (signal_num == SIGINT || signal_num == SIGTERM) {
    GlobalSignalInt.store(signal_num);
  }
}
#endif

SignalMonitorImpl::SignalMonitorImpl() = default;

void SignalMonitorImpl::Run_() {
  while (running_.load(std::memory_order_acquire)) {
    const int signum = GlobalSignalInt.exchange(0);
    if (signum != 0) {
      last_handled_signal_.store(signum, std::memory_order_relaxed);
      std::vector<AMDomain::signal::SignalHook> hooks;
      {
        std::lock_guard<std::mutex> lock(hooks_mtx_);
        hooks.reserve(hooks_.size());
        for (const auto &entry : hooks_) {
          hooks.push_back(entry.second);
        }
      }
      std::sort(hooks.begin(), hooks.end(),
                [](const AMDomain::signal::SignalHook &a,
                   const AMDomain::signal::SignalHook &b) {
                  return a.priority > b.priority;
                });
      for (const auto &hook : hooks) {
        if (hook.is_silenced) {
          continue;
        }
        if (hook.callback) {
          hook.callback(signum);
        }
        if (hook.consume) {
          break;
        }
      }
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }
}

} // namespace AMInfra::signal

namespace AMDomain::signal {

std::unique_ptr<SignalMonitor> BuildSignalMonitorPort() {
  return std::make_unique<AMInfra::signal::SignalMonitorImpl>();
}

} // namespace AMDomain::signal
