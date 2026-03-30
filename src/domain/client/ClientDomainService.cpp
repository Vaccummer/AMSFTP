#include "domain/client/ClientDomainService.hpp"
#include "domain/client/ClientPort.hpp"
#include "foundation/tools/time.hpp"

#include <utility>

namespace AMDomain::client {
float ResolveTimeoutBudgetMs(int timeout_ms, int64_t start_time) {
  if (timeout_ms <= 0) {
    return static_cast<float>(timeout_ms);
  }
  if (start_time < 0) {
    return static_cast<float>(timeout_ms);
  }
  const float remain = static_cast<float>(timeout_ms) -
                       static_cast<float>(AMTime::miliseconds() - start_time);
  return remain > 0.0f ? remain : 0.0f;
}

ClientControlComponent MakeClientControlComponent(amf interrupt_flag,
                                                  int timeout_ms,
                                                  int64_t start_time) {
  timeoutf timeout_port = CreateClientTimeoutPort();
  if (timeout_port) {
    timeout_port->SetTimeout(ResolveTimeoutBudgetMs(timeout_ms, start_time));
  }
  return ClientControlComponent(std::move(interrupt_flag),
                                std::move(timeout_port));
}

ClientControlComponent MakeClientIOControlArgs(amf interrupt_flag, int timeout_ms,
                                               int64_t start_time) {
  return MakeClientControlComponent(std::move(interrupt_flag), timeout_ms,
                                    start_time);
}
} // namespace AMDomain::client
