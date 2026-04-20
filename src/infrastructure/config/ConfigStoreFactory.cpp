#include "infrastructure/config/ConfigStoreFactory.hpp"

#include "domain/config/ConfigStorePort.hpp"
#include "domain/config/ConfigSchema.hpp"
#include "infrastructure/config/TomlConfigStore.hpp"
#include <memory>

namespace AMInfra::config {

AMDomain::config::ConfigStoreInitArg
BuildDefaultConfigStoreInitArg(const std::filesystem::path &root_dir) {
  using AMDomain::config::DocumentKind;

  AMDomain::config::ConfigStoreInitArg arg = {};
  arg.root_dir = root_dir;
  arg.layout = {
      {DocumentKind::Config,
       {DocumentKind::Config, root_dir / "config" / "config.toml",
        AMDomain::config::schema::GetSchemaJson(DocumentKind::Config)}},
      {DocumentKind::Settings,
       {DocumentKind::Settings, root_dir / "config" / "settings.toml",
        AMDomain::config::schema::GetSchemaJson(DocumentKind::Settings)}},
      {DocumentKind::KnownHosts,
       {DocumentKind::KnownHosts, root_dir / "config" / "known_hosts.toml",
        AMDomain::config::schema::GetSchemaJson(DocumentKind::KnownHosts)}},
      {DocumentKind::History,
       {DocumentKind::History, root_dir / "config" / "history.toml",
        AMDomain::config::schema::GetSchemaJson(DocumentKind::History)}}};
  return arg;
}

} // namespace AMInfra::config

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
