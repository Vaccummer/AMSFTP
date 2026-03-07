#pragma once

#include "domain/config/DocumentKind.hpp"
#include "foundation/DataClass.hpp"
#include "foundation/tools/json.hpp"
#include <functional>
#include <mutex>
#include <vector>

namespace AMDomain::config {
/**
 * @brief Shared sync port bound to one `(DocumentKind, Path)` key.
 *
 * Business classes may keep this port and register one dump callback that
 * serializes their runtime state into the owned JSON payload.
 */
class AMConfigSyncPort : NonCopyableNonMovable {
public:
  using Path = std::vector<std::string>;
  using DumpCallback = std::function<void(Json &)>;

  /**
   * @brief Construct one sync port for one document/path key.
   */
  AMConfigSyncPort(DocumentKind kind, Path path, Json init_json = Json::object());

  /**
   * @brief Return bound document kind.
   */
  [[nodiscard]] DocumentKind Kind() const;

  /**
   * @brief Return bound path key.
   */
  [[nodiscard]] const Path &GetPath() const;

  /**
   * @brief Overwrite current in-port JSON payload.
   */
  void SetJson(const Json &json);

  /**
   * @brief Return a snapshot of in-port JSON payload.
   */
  [[nodiscard]] bool GetJson(Json *out) const;

  /**
   * @brief Register callback used before dump to refresh payload JSON.
   */
  void RegisterDumpCallback(DumpCallback cb);

  /**
   * @brief Trigger callback and refresh payload JSON in place.
   *
   * @return true when callback succeeded or not set; false on exception.
   */
  [[nodiscard]] bool TriggerDumpCallback();

private:
  DocumentKind kind_;
  Path path_;
  mutable std::mutex mtx_;
  Json json_ = Json::object();
  DumpCallback dump_cb_;
};
} // namespace AMDomain::config
