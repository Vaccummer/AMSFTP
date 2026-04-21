#include "infrastructure/config/ConfigStoreFactory.hpp"

#include "infrastructure/config/TomlConfigStore.hpp"
#include <memory>

namespace AMDomain::config {

ConfigStoreInitArg
BuildDefaultConfigStoreInitArg(const std::filesystem::path &root_dir) {
  ConfigStoreInitArg arg = {};
  arg.root_dir = root_dir;
  arg.layout = {
      {DocumentKind::Config,
       {DocumentKind::Config, root_dir / "config" / "config.toml"}},
      {DocumentKind::Settings,
       {DocumentKind::Settings, root_dir / "config" / "settings.toml"}},
      {DocumentKind::KnownHosts,
       {DocumentKind::KnownHosts, root_dir / "config" / "known_hosts.toml"}},
      {DocumentKind::History,
       {DocumentKind::History, root_dir / "config" / "history.toml"}}};
  return arg;
}

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
