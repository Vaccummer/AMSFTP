#pragma once
#include "foundation/RustTomlRead.h"
#include "domain/config/ConfigHandlePort.hpp"

/**
 * @brief Concrete cfgffi-backed TOML handle with in-memory Json cache.
 */
class AMInfraSuperTomlHandle final
    : public AMDomain::config::AMInfraConfigHandlePort {
public:
  AMInfraSuperTomlHandle() = default;
  ~AMInfraSuperTomlHandle() override { Close(); }

  ECM Init(const std::filesystem::path &path,
           const std::string &schema_json) override;
  bool GetJson(Json *out) const override;
  bool ReadValue(domain::arg::TypeTag type, void *out) const override;
  bool WriteValue(domain::arg::TypeTag type, const void *in) override;
  ECM DumpInplace() override;
  ECM DumpTo(const std::filesystem::path &dst_path) override;
  bool GetSchemaJson(std::string *out) const override;
  bool GetSchemaJson(Json *out) const override;
  void Close() override;
  [[nodiscard]] bool IsDirty() const override;
  [[nodiscard]] std::chrono::system_clock::time_point
  LastModified() const override;

  /**
   * @brief Return original TOML path for this handle.
   */
  [[nodiscard]] std::filesystem::path Path() const;

private:
  std::filesystem::path ori_path_;
  std::string schema_json_ = "{}";
  ConfigHandle *cfgffi_handle_ = nullptr;
  Json json_ = Json::object();
  bool is_dirty_ = false;
  std::chrono::system_clock::time_point last_modified_{};
};
