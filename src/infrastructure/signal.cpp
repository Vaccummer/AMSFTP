#include "foundation/tools/enum_related.hpp"
#include "infrastructure/SignalMonitor.hpp"
#include <algorithm>
#include <chrono>
#include <utility>
#include <vector>

std::atomic<int> GlobalSignalInt{0};

/** Stop worker resources during teardown. */
AMInfraCliSignalMonitor::~AMInfraCliSignalMonitor() { Stop(); }

void AMInfraCliSignalMonitor::InstallHandlers() {
#ifdef _WIN32
  SetConsoleCtrlHandler(AMInfraCliSignalMonitor::ConsoleCtrlHandler_, TRUE);
#else
  struct sigaction sa{};
  sa.sa_handler = AMInfraCliSignalMonitor::SignalHandler;
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = SA_RESTART;
  sigaction(SIGINT, &sa, nullptr);
#ifdef SIGTERM
  sigaction(SIGTERM, &sa, nullptr);
#endif
#endif
}

void AMInfraCliSignalMonitor::Start() {
  if (running_.exchange(true, std::memory_order_acq_rel)) {
    return;
  }
  worker_ = std::thread([this]() { Run_(); });
}

ECM AMInfraCliSignalMonitor::Init() {
  EnsureGlobalHook_();
  InstallHandlers();
  Start();
  return Ok();
}

void AMInfraCliSignalMonitor::Stop() {
  running_.store(false, std::memory_order_release);
  if (worker_.joinable()) {
    worker_.join();
  }
}

int AMInfraCliSignalMonitor::LastSignal() const {
  return last_handled_signal_.load(std::memory_order_relaxed);
}

bool AMInfraCliSignalMonitor::RegisterHook(const std::string &name,
                                           const SignalHook &hook) {
  if (name.empty()) {
    return false;
  }
  std::lock_guard<std::mutex> lock(hooks_mtx_);
  if (hooks_.find(name) != hooks_.end()) {
    return false;
  }
  hooks_[name] = hook;
  if (name == "GLOBAL") {
    hooks_[name].priority = 0;
    hooks_[name].consume = false;
  }
  return true;
}

bool AMInfraCliSignalMonitor::UnregisterHook(const std::string &name) {
  if (name.empty() || name == "GLOBAL") {
    return false;
  }
  std::lock_guard<std::mutex> lock(hooks_mtx_);
  return hooks_.erase(name) > 0;
}

bool AMInfraCliSignalMonitor::SilenceHook(const std::string &name) {
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

bool AMInfraCliSignalMonitor::ResumeHook(const std::string &name) {
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

bool AMInfraCliSignalMonitor::SetHookPriority(const std::string &name,
                                              int priority) {
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

/** Bind a task-control token for signal propagation. */
void AMInfraCliSignalMonitor::BindTaskControlToken(
    const std::shared_ptr<TaskControlToken> &token) {
  std::lock_guard<std::mutex> lock(token_mtx_);
  task_control_token_ = token;
}

/** Clear the currently bound task-control token. */
void AMInfraCliSignalMonitor::ClearTaskControlToken() {
  std::lock_guard<std::mutex> lock(token_mtx_);
  task_control_token_.reset();
}

/** Return the currently bound task-control token. */
std::shared_ptr<TaskControlToken> AMInfraCliSignalMonitor::BoundTaskControlToken()
    const {
  return ResolveTaskControlToken_();
}

void AMInfraCliSignalMonitor::SignalHandler(int signum) {
  GlobalSignalInt.store(signum);
}

#ifdef _WIN32
BOOL WINAPI AMInfraCliSignalMonitor::ConsoleCtrlHandler_(DWORD type) {
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
#endif

AMInfraCliSignalMonitor::AMInfraCliSignalMonitor() = default;

void AMInfraCliSignalMonitor::EnsureGlobalHook_() {
  std::lock_guard<std::mutex> lock(hooks_mtx_);
  auto it = hooks_.find("GLOBAL");
  if (it == hooks_.end()) {
    SignalHook global;
    global.callback = {};
    global.is_silenced = false;
    global.priority = 0;
    global.consume = false;
    hooks_["GLOBAL"] = std::move(global);
    return;
  }
  it->second.priority = 0;
  it->second.consume = false;
}

/** Resolve the weak task-control token binding to a strong pointer. */
std::shared_ptr<TaskControlToken>
AMInfraCliSignalMonitor::ResolveTaskControlToken_() const {
  std::lock_guard<std::mutex> lock(token_mtx_);
  return task_control_token_.lock();
}

void AMInfraCliSignalMonitor::Run_() {
  while (running_.load(std::memory_order_acquire)) {
    const int signum = GlobalSignalInt.exchange(0);
    if (signum != 0) {
      last_handled_signal_.store(signum, std::memory_order_relaxed);
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
        if (hook.consume) {
          break;
        }
      }
      auto token = ResolveTaskControlToken_();
      if ((signum == SIGINT || signum == SIGTERM) && token) {
        (void)token->SetStatus(signum == SIGINT ? ControlSignal::Interrupt
                                                : ControlSignal::Kill);
      }
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }
}
