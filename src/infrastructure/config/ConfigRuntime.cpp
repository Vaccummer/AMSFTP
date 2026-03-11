#include "infrastructure/config/ConfigRuntime.hpp"

#include "foundation/tools/enum_related.hpp"
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
AMConfigRuntime::AMConfigRuntime() : app_service_(&store_, &backup_use_case_) {}

AMConfigRuntime::~AMConfigRuntime() { Close(); }

ECM AMConfigRuntime::Init(const std::filesystem::path &root_dir) {
  ConfigStoreLayout layout;

  layout[AMDomain::config::DocumentKind::Config] = {
      AMDomain::config::DocumentKind::Config,
      root_dir / "config" / "config.toml",
      ReadSchemaJson_(root_dir / "config" / "schema" / "config.schema.json")};
  layout[AMDomain::config::DocumentKind::Settings] = {
      AMDomain::config::DocumentKind::Settings,
      root_dir / "config" / "settings.toml",
      ReadSchemaJson_(root_dir / "config" / "schema" / "settings.schema.json")};
  layout[AMDomain::config::DocumentKind::KnownHosts] = {
      AMDomain::config::DocumentKind::KnownHosts,
      root_dir / "config" / "internal" / "known_hosts.toml",
      ReadSchemaJson_(root_dir / "config" / "schema" / "known_hosts.schema.json")};
  layout[AMDomain::config::DocumentKind::History] = {
      AMDomain::config::DocumentKind::History,
      root_dir / "config" / "internal" / "history.toml",
      kHistorySchemaJson};

  return Init(root_dir, layout);
}

ECM AMConfigRuntime::Init(const std::filesystem::path &root_dir,
                          const ConfigStoreLayout &layout) {
  Close();
  root_dir_ = root_dir;
  app_service_.SetDumpErrorCallback(
      [this](const ECM &err) { NotifyDumpError_(err); });
  ECM rcm = store_.Configure(root_dir, layout);
  if (!isok(rcm)) {
    initialized_ = false;
    return rcm;
  }
  rcm = app_service_.Load(std::nullopt, true);
  initialized_ = isok(rcm);
  return rcm;
}

void AMConfigRuntime::Close() {
  app_service_.CloseHandles();
  initialized_ = false;
}

void AMConfigRuntime::SetDumpErrorCallback(DumpErrorCallback cb) {
  dump_error_cb_ = std::move(cb);
  app_service_.SetDumpErrorCallback(
      [this](const ECM &err) { NotifyDumpError_(err); });
}

AMApplication::config::AMConfigAppService &AMConfigRuntime::AppService() {
  return app_service_;
}

const AMApplication::config::AMConfigAppService &
AMConfigRuntime::AppService() const {
  return app_service_;
}

void AMConfigRuntime::NotifyDumpError_(const ECM &err) const {
  if (dump_error_cb_) {
    dump_error_cb_(err);
  }
}
} // namespace AMInfra::config
