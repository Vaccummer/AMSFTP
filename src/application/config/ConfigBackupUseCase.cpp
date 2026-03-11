#include "application/config/ConfigBackupUseCase.hpp"

#include "application/config/ConfigAppService.hpp"
#include "domain/config/ConfigRules.hpp"
#include "foundation/tools/enum_related.hpp"
#include "foundation/tools/string.hpp"
#include "foundation/tools/time.hpp"
#include <limits>
#include <optional>

namespace {
using Json = nlohmann::ordered_json;

/**
 * @brief Read one int field from object when available.
 */
std::optional<int64_t> GetIntField_(const Json &obj, const std::string &key) {
  if (!obj.is_object()) {
    return std::nullopt;
  }
  auto it = obj.find(key);
  if (it == obj.end()) {
    return std::nullopt;
  }
  if (it->is_number_integer()) {
    return it->get<int64_t>();
  }
  if (it->is_number_unsigned()) {
    const auto value = it->get<uint64_t>();
    if (value <= static_cast<uint64_t>(std::numeric_limits<int64_t>::max())) {
      return static_cast<int64_t>(value);
    }
    return std::nullopt;
  }
  if (it->is_string()) {
    try {
      return std::stoll(it->get<std::string>());
    } catch (...) {
      return std::nullopt;
    }
  }
  return std::nullopt;
}

/**
 * @brief Read one bool field from object when available.
 */
std::optional<bool> GetBoolField_(const Json &obj, const std::string &key) {
  if (!obj.is_object()) {
    return std::nullopt;
  }
  auto it = obj.find(key);
  if (it == obj.end()) {
    return std::nullopt;
  }
  if (it->is_boolean()) {
    return it->get<bool>();
  }
  if (it->is_number_integer()) {
    return it->get<int64_t>() != 0;
  }
  if (it->is_number_unsigned()) {
    return it->get<uint64_t>() != 0;
  }
  if (it->is_string()) {
    const std::string token = AMStr::lowercase(it->get<std::string>());
    if (token == "true") {
      return true;
    }
    if (token == "false") {
      return false;
    }
  }
  return std::nullopt;
}
} // namespace

namespace AMApplication::config {
ECM AMConfigBackupUseCase::Execute(AMConfigAppService *service) {
  if (!service) {
    return Err(EC::InvalidArg, "null config app service");
  }

  constexpr bool kDefaultEnabled = true;
  constexpr int64_t kDefaultMaxBackupCount = 3;
  constexpr int64_t kDefaultLastBackupS = 0;

  Json settings_json = Json::object();
  if (!service->GetJson(AMDomain::config::DocumentKind::Settings,
                        &settings_json)) {
    return Err(EC::ConfigLoadFailed, "failed to load settings json");
  }
  if (!settings_json.is_object()) {
    settings_json = Json::object();
  }

  bool changed = false;
  Json &options_cfg = settings_json["Options"];
  if (!options_cfg.is_object()) {
    options_cfg = Json::object();
    changed = true;
  }
  Json &backup_cfg = options_cfg["AutoConfigBackup"];
  if (!backup_cfg.is_object()) {
    backup_cfg = Json::object();
    changed = true;
  }

  bool enabled = kDefaultEnabled;
  if (auto v = GetBoolField_(backup_cfg, "enabled")) {
    enabled = *v;
  } else {
    backup_cfg["enabled"] = kDefaultEnabled;
    changed = true;
  }

  int64_t interval_s = AMDomain::config::AMConfigRules::ClampBackupIntervalSeconds(
      GetIntField_(backup_cfg, "interval_s").value_or(60));
  if (!GetIntField_(backup_cfg, "interval_s").has_value() ||
      GetIntField_(backup_cfg, "interval_s").value() != interval_s) {
    changed = true;
  }
  backup_cfg["interval_s"] = interval_s;

  int64_t max_backup_count =
      AMDomain::config::AMConfigRules::ClampBackupCount(
          GetIntField_(backup_cfg, "max_backup_count")
              .value_or(kDefaultMaxBackupCount));
  if (!GetIntField_(backup_cfg, "max_backup_count").has_value() ||
      GetIntField_(backup_cfg, "max_backup_count").value() != max_backup_count) {
    changed = true;
  }
  backup_cfg["max_backup_count"] = max_backup_count;

  const auto now_s = static_cast<int64_t>(AMTime::seconds());
  int64_t last_backup_time_s =
      AMDomain::config::AMConfigRules::ClampLastBackupTimestamp(
          GetIntField_(backup_cfg, "last_backup_time_s")
              .value_or(kDefaultLastBackupS),
          now_s);
  if (!GetIntField_(backup_cfg, "last_backup_time_s").has_value() ||
      GetIntField_(backup_cfg, "last_backup_time_s").value() !=
          last_backup_time_s) {
    changed = true;
  }
  backup_cfg["last_backup_time_s"] = last_backup_time_s;

  if (changed &&
      !service->SetArg(AMDomain::config::DocumentKind::Settings, {},
                       settings_json)) {
    return Err(EC::ConfigDumpFailed, "failed to update backup policy settings");
  }

  const auto root_dir = service->ProjectRoot();
  if (!root_dir.empty()) {
    const std::filesystem::path backup_dir = root_dir / "config" / "bak";
    service->PruneBackupFiles(backup_dir, "config-", ".toml.bak",
                              max_backup_count);
    service->PruneBackupFiles(backup_dir, "settings-", ".toml.bak",
                              max_backup_count);
    service->PruneBackupFiles(backup_dir, "known_hosts-", ".toml.bak",
                              max_backup_count);
  }

  if (!enabled || (interval_s > 0 && (now_s - last_backup_time_s) < interval_s)) {
    if (changed) {
      return service->Dump(AMDomain::config::DocumentKind::Settings, "", true);
    }
    return Ok();
  }

  backup_cfg["last_backup_time_s"] = now_s;
  if (!service->SetArg(AMDomain::config::DocumentKind::Settings, {},
                       settings_json)) {
    return Err(EC::ConfigDumpFailed, "failed to update backup timestamp");
  }

  if (root_dir.empty()) {
    return service->Dump(AMDomain::config::DocumentKind::Settings, "", true);
  }

  const std::filesystem::path backup_dir = root_dir / "config" / "bak";
  ECM mkdir_rcm = service->EnsureDirectory(backup_dir);
  if (!isok(mkdir_rcm)) {
    return mkdir_rcm;
  }

  const std::string stamp =
      FormatTime(static_cast<size_t>(now_s), "%Y-%m-%d-%H-%M");
  const std::filesystem::path config_backup =
      backup_dir / ("config-" + stamp + ".toml.bak");
  const std::filesystem::path settings_backup =
      backup_dir / ("settings-" + stamp + ".toml.bak");
  const std::filesystem::path known_hosts_backup =
      backup_dir / ("known_hosts-" + stamp + ".toml.bak");

  service->SubmitWriteTask([service, config_backup, settings_backup,
                            known_hosts_backup]() -> ECM {
    ECM rcm =
        service->Dump(AMDomain::config::DocumentKind::Config,
                      config_backup.string(), false);
    if (!isok(rcm)) {
      return rcm;
    }
    rcm = service->Dump(AMDomain::config::DocumentKind::Settings,
                        settings_backup.string(), false);
    if (!isok(rcm)) {
      return rcm;
    }
    return service->Dump(AMDomain::config::DocumentKind::KnownHosts,
                         known_hosts_backup.string(), false);
  });

  return service->Dump(AMDomain::config::DocumentKind::Settings, "", true);
}
} // namespace AMApplication::config
