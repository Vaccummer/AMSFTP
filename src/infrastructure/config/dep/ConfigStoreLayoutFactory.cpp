#include "infrastructure/config/ConfigStoreLayoutFactory.hpp"

#include "foundation/tools/json.hpp"

namespace {
/** @brief JSON schema used to validate config/internal/history.toml. */
inline constexpr char kHistorySchemaJson[250] = R"json(
{
  "type": "object",
  "additionalProperties": {
    "type": "object",
    "properties": {
      "commands": {
        "type": "array",
        "items": {
          "type": "string"
        }
      }
    },
    "additionalProperties": false
  }
}
)json";

/**
 * @brief Resolve schema file contents into final schema JSON.
 */
std::string ReadSchemaJson_(const std::filesystem::path &schema_path) {
  std::string schema_json = AMJson::ReadSchemaData(schema_path, nullptr);
  if (schema_json.empty()) {
    schema_json = "{}";
  }
  return schema_json;
}
} // namespace

namespace AMInfra::config {
/**
 * @brief Build default config-store init arg rooted at one project directory.
 */
AMDomain::config::ConfigStoreInitArg
BuildDefaultConfigStoreInitArg(const std::filesystem::path &root_dir) {
  AMDomain::config::ConfigStoreInitArg out = {};
  out.root_dir = root_dir;
  out.layout[AMDomain::config::DocumentKind::Config] = {
      AMDomain::config::DocumentKind::Config,
      root_dir / "config" / "config.toml",
      ReadSchemaJson_(root_dir / "config" / "schema" / "config.schema.json")};
  out.layout[AMDomain::config::DocumentKind::Settings] = {
      AMDomain::config::DocumentKind::Settings,
      root_dir / "config" / "settings.toml",
      ReadSchemaJson_(root_dir / "config" / "schema" / "settings.schema.json")};
  out.layout[AMDomain::config::DocumentKind::KnownHosts] = {
      AMDomain::config::DocumentKind::KnownHosts,
      root_dir / "config" / "internal" / "known_hosts.toml",
      ReadSchemaJson_(root_dir / "config" / "schema" /
                      "known_hosts.schema.json")};
  out.layout[AMDomain::config::DocumentKind::History] = {
      AMDomain::config::DocumentKind::History,
      root_dir / "config" / "internal" / "history.toml",
      kHistorySchemaJson};
  return out;
}
} // namespace AMInfra::config
