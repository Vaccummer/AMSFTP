// #include "AMBase/CommonTools.hpp"
// #include "AMManager/Config.hpp"
// #include "AMManager/Host.hpp"

// AMConfigManager &AMConfigManager::Instance() {
//   static AMConfigManager instance;
//   return instance;
// }

// AMConfigManager::AMConfigManager() :
// host_manager_(std::make_unique<AMHostManager>(*this)) {}

// /** @brief Stop the background writer and release config handles. */
// AMConfigManager::~AMConfigManager() { CloseHandles(); }

// ECM AMConfigManager::Init() {
//   std::string root_env;
//   if (!GetEnv("AMSFTP_ROOT", &root_env)) {
//     prompt.ErrorFormat("ConfigInit",
//                        "$AMSFTP_ROOT environment variable is not set");
//     return Err(EC::ConfigInvalid,
//                "AMSFTP_ROOT environment variable is not set");
//   }

//   std::filesystem::path root_dir(root_env);
//   std::error_code ec;
//   std::filesystem::create_directories(root_dir, ec);
//   if (ec) {
//     prompt.ErrorFormat("ConfigInit",
//                        "failed to create root directory " + root_dir.string()
//                        +
//                            ": " + ec.message(),
//                        true, 2);
//     return Err(EC::ConfigLoadFailed, "failed to create root directory " +
//                                          root_dir.string() + ": " +
//                                          ec.message());
//   }

//   auto init_status = AMConfigStorage::Init(root_dir);
//   if (init_status.first != EC::Success) {
//     prompt.ErrorFormat("ConfigInit", init_status.second, true, 2);
//     return init_status;
//   }

//   auto load_status = LoadAll();
//   if (load_status.first != EC::Success) {
//     prompt.ErrorFormat("ConfigInit", load_status.second, true, 2);
//     return load_status;
//   }

//   return Ok();
// }

// std::string AMConfigManager::GetSettingString(
//     const Path &path, const std::string &default_value) const {
//   Value value;
//   if (!ReadTomlValue(DocumentKind::Settings, path, &value)) {
//     return default_value;
//   }
//   if (std::holds_alternative<std::string>(value)) {
//     return std::get<std::string>(value);
//   }
//   if (std::holds_alternative<int64_t>(value)) {
//     return std::to_string(std::get<int64_t>(value));
//   }
//   if (std::holds_alternative<bool>(value)) {
//     return std::get<bool>(value) ? "true" : "false";
//   }
//   return default_value;
// }

// int AMConfigManager::ResolveTimeoutMs(int default_timeout_ms) const {
//   Value value;
//   if (!ReadTomlValue(DocumentKind::Settings,
//                      {"InternalVars", "TimeoutMs"}, &value)) {
//     return default_timeout_ms;
//   }
//   if (std::holds_alternative<int64_t>(value)) {
//     const int64_t raw = std::get<int64_t>(value);
//     return raw > 0 ? static_cast<int>(raw) : default_timeout_ms;
//   }
//   if (std::holds_alternative<std::string>(value)) {
//     try {
//       const int parsed = std::stoi(std::get<std::string>(value));
//       return parsed > 0 ? parsed : default_timeout_ms;
//     } catch (...) {
//       return default_timeout_ms;
//     }
//   }
//   return default_timeout_ms;
// }

// AMHostManager &AMConfigManager::Host() { return *host_manager_; }

// const AMHostManager &AMConfigManager::Host() const { return *host_manager_; }
