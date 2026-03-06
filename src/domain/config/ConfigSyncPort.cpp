#include "domain/config/ConfigSyncPort.hpp"

#include <utility>

namespace AMDomain::config {
/**
 * @brief Construct one sync port for one document/path key.
 */
AMConfigSyncPort::AMConfigSyncPort(DocumentKind kind, Path path, Json init_json)
    : kind_(kind), path_(std::move(path)), json_(std::move(init_json)) {}

/**
 * @brief Return bound document kind.
 */
DocumentKind AMConfigSyncPort::Kind() const { return kind_; }

/**
 * @brief Return bound path key.
 */
const AMConfigSyncPort::Path &AMConfigSyncPort::GetPath() const { return path_; }

/**
 * @brief Overwrite current in-port JSON payload.
 */
void AMConfigSyncPort::SetJson(const Json &json) {
  std::lock_guard<std::mutex> lock(mtx_);
  json_ = json;
}

/**
 * @brief Return a snapshot of in-port JSON payload.
 */
bool AMConfigSyncPort::GetJson(Json *out) const {
  if (!out) {
    return false;
  }
  std::lock_guard<std::mutex> lock(mtx_);
  *out = json_;
  return true;
}

/**
 * @brief Register callback used before dump to refresh payload JSON.
 */
void AMConfigSyncPort::RegisterDumpCallback(DumpCallback cb) {
  std::lock_guard<std::mutex> lock(mtx_);
  dump_cb_ = std::move(cb);
}

/**
 * @brief Trigger callback and refresh payload JSON in place.
 */
bool AMConfigSyncPort::TriggerDumpCallback() {
  std::lock_guard<std::mutex> lock(mtx_);
  if (!dump_cb_) {
    return true;
  }
  try {
    dump_cb_(json_);
    return true;
  } catch (...) {
    return false;
  }
}
} // namespace AMDomain::config
