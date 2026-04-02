#include "domain/config/ConfigStorePort.hpp"
#include "foundation/tools/enum_related.hpp"
#include "infrastructure/config/TomlConfigStore.hpp"
#include <memory>

namespace AMDomain::config {
ECMData<std::unique_ptr<IConfigStorePort>>
CreateConfigStorePort(const ConfigStoreInitArg &arg) {
  auto store = std::make_unique<AMInfra::config::AMTomlConfigStore>();
  ECM rcm = store->Configure(arg);
  if (!(rcm)) {
    return {nullptr, rcm};
  }
  std::unique_ptr<IConfigStorePort> port(std::move(store));
  return {std::move(port), OK};
}
} // namespace AMDomain::config
