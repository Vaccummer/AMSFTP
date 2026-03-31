#include "domain/client/ClientDomainService.hpp"
#include "domain/client/ClientPort.hpp"
#include "infrastructure/client/common/Base.hpp"

namespace AMDomain::client {
amf CreateClientControlToken() {
  return std::make_shared<AMInfra::client::ClientControlToken>();
}

timeoutf CreateClientTimeoutPort() {
  auto timeout_port = std::make_shared<AMInfra::client::ClientTimeoutPort>();
  timeout_port->SetTimeout(AMDomain::client::ClientService::AMDefaultTimeoutMs);
  return timeout_port;
}
} // namespace AMDomain::client
