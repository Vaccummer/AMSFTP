#pragma once

#include "foundation/tools/auth.hpp"
#include "foundation/tools/string.hpp"
#include "interface/adapters/client/ClientInterfaceService.hpp"
#include "interface/cli/ArgStruct/BaseArgStruct.hpp"
#include <cstring>
#include <string>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#endif

namespace AMInterface::cli {

namespace config_arg_detail {

inline bool NormalizeEncryptedPassword(const std::string &input,
                                       std::string *out) {
  if (!out) {
    return false;
  }
  out->clear();

  const std::string raw = AMStr::Strip(input);
  if (raw.empty()) {
    return false;
  }

  std::string payload = raw;
  if (AMAuth::IsEncrypted(raw)) {
    payload = raw.substr(std::string(AMAuth::kEncryptedPrefix).size());
  }
  if (payload.empty()) {
    return false;
  }

  const std::string decoded = AMAuth::HexDecode(payload);
  if (decoded.empty() && !payload.empty()) {
    return false;
  }
  *out = std::string(AMAuth::kEncryptedPrefix) + payload;
  return true;
}

inline bool CopyTextToClipboard(const std::string &text) {
#ifdef _WIN32
  const int wide_len = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
                                           text.c_str(), -1, nullptr, 0);
  if (wide_len <= 0) {
    return false;
  }
  std::wstring wide(static_cast<size_t>(wide_len), L'\0');
  if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.c_str(), -1,
                          wide.data(), wide_len) <= 0) {
    return false;
  }

  const size_t bytes = wide.size() * sizeof(wchar_t);
  HGLOBAL handle = GlobalAlloc(GMEM_MOVEABLE, bytes);
  if (!handle) {
    return false;
  }
  void *buffer = GlobalLock(handle);
  if (!buffer) {
    GlobalFree(handle);
    return false;
  }
  std::memcpy(buffer, wide.data(), bytes);
  GlobalUnlock(handle);

  if (!OpenClipboard(nullptr)) {
    GlobalFree(handle);
    return false;
  }
  EmptyClipboard();
  if (SetClipboardData(CF_UNICODETEXT, handle) == nullptr) {
    CloseClipboard();
    GlobalFree(handle);
    return false;
  }
  CloseClipboard();
  return true;
#else
  (void)text;
  return false;
#endif
}

} // namespace config_arg_detail

/**
 * @brief CLI argument container for config ls.
 */
struct ConfigLsArgs : BaseArgStruct {
  bool detail = false;
  [[nodiscard]] ECM Run(const CLIServices &managers,
                        const CliRunContext &ctx) const override {
    (void)ctx;
    (void)detail;
    return managers.interfaces.config_interface_service->PrintPaths();
  }
  void reset() override { detail = false; }
};

/**
 * @brief CLI argument container for config get.
 */
struct ConfigGetArgs : BaseArgStruct {
  AMInterface::client::ListClientsRequest request = {};
  [[nodiscard]] ECM Run(const CLIServices &managers,
                        const CliRunContext &ctx) const override {
    (void)ctx;
    return managers.interfaces.client_interface_service->ListHosts(request.nicknames, true);
  }
  void reset() override { request = {}; }
};

/**
 * @brief CLI argument container for config add.
 */
struct ConfigAddArgs : BaseArgStruct {
  std::string nickname = {};
  [[nodiscard]] ECM Run(const CLIServices &managers,
                        const CliRunContext &ctx) const override {
    (void)ctx;
    return managers.interfaces.client_interface_service->AddHost(nickname);
  }
  void reset() override { nickname.clear(); }
};

/**
 * @brief CLI argument container for config edit.
 */
struct ConfigEditArgs : BaseArgStruct {
  std::string nickname = {};
  [[nodiscard]] ECM Run(const CLIServices &managers,
                        const CliRunContext &ctx) const override {
    (void)ctx;
    return managers.interfaces.client_interface_service->ModifyHost(nickname);
  }
  void reset() override { nickname.clear(); }
};

/**
 * @brief CLI argument container for config rename.
 */
struct ConfigRenameArgs : BaseArgStruct {
  std::string old_name = {};
  std::string new_name = {};
  [[nodiscard]] ECM Run(const CLIServices &managers,
                        const CliRunContext &ctx) const override {
    (void)ctx;
    return managers.interfaces.client_interface_service->RenameHost(old_name, new_name);
  }
  void reset() override {
    old_name.clear();
    new_name.clear();
  }
};

/**
 * @brief CLI argument container for config remove.
 */
struct ConfigRemoveArgs : BaseArgStruct {
  std::vector<std::string> names = {};
  [[nodiscard]] ECM Run(const CLIServices &managers,
                        const CliRunContext &ctx) const override {
    (void)ctx;
    return managers.interfaces.client_interface_service->RemoveHosts(names);
  }
  void reset() override { names.clear(); }
};

/**
 * @brief CLI argument container for config set.
 */
struct ConfigSetArgs : BaseArgStruct {
  AMInterface::client::SetHostValueRequest request = {};
  [[nodiscard]] ECM Run(const CLIServices &managers,
                        const CliRunContext &ctx) const override {
    (void)ctx;
    return managers.interfaces.client_interface_service->SetHostValue(request);
  }
  void reset() override { request = {}; }
};

/**
 * @brief CLI argument container for config save.
 */
struct ConfigSaveArgs : BaseArgStruct {
  [[nodiscard]] ECM Run(const CLIServices &managers,
                        const CliRunContext &ctx) const override {
    (void)ctx;
    return managers.interfaces.config_interface_service->SaveAll();
  }
  void reset() override {}
};

/**
 * @brief CLI argument container for config backup.
 */
struct ConfigBackupArgs : BaseArgStruct {
  [[nodiscard]] ECM Run(const CLIServices &managers,
                        const CliRunContext &ctx) const override {
    (void)ctx;
    return managers.interfaces.config_interface_service->BackupAll();
  }
  void reset() override {}
};

/**
 * @brief CLI argument container for config export.
 */
struct ConfigExportArgs : BaseArgStruct {
  std::string path = {};
  [[nodiscard]] ECM Run(const CLIServices &managers,
                        const CliRunContext &ctx) const override {
    (void)ctx;
    return managers.interfaces.config_interface_service->Export(path);
  }
  void reset() override { path.clear(); }
};

/**
 * @brief CLI argument container for config profile set.
 */
struct ConfigProfileSetArgs : BaseArgStruct {
  std::string nickname = {};
  [[nodiscard]] ECM Run(const CLIServices &managers,
                        const CliRunContext &ctx) const override {
    (void)ctx;
    AMInterface::client::ChangeClientRequest request = {};
    request.nickname = AMStr::Strip(nickname).empty() ? "local" : nickname;
    request.quiet = false;
    return managers.interfaces.client_interface_service->ChangeClient(request);
  }
  void reset() override { nickname.clear(); }
};

/**
 * @brief CLI argument container for decrypt utility.
 */
struct ConfigDecryptArgs : BaseArgStruct {
  std::string password = {};
  [[nodiscard]] ECM Run(const CLIServices &managers,
                        const CliRunContext &ctx) const override {
    (void)ctx;
    const auto report_error = [&managers](const ECM &rcm) -> ECM {
      managers.interfaces.prompt_io_manager->ErrorFormat(rcm);
      return rcm;
    };

    std::string encrypted_input = {};
    if (!config_arg_detail::NormalizeEncryptedPassword(password,
                                                       &encrypted_input)) {
      return report_error(Err(
          EC::InvalidArg, __func__, "",
          "decrypt requires encrypted password input: enc:<HEX> or <HEX>"));
    }

    std::string plain = AMAuth::DecryptPassword(encrypted_input);
    if (plain.empty()) {
      return report_error(
          Err(EC::InvalidArg, __func__, "", "invalid encrypted password"));
    }
    if (!config_arg_detail::CopyTextToClipboard(plain)) {
      AMAuth::SecureZero(plain);
      return report_error(Err(EC::OperationUnsupported, __func__, "",
                              "failed to copy password to clipboard"));
    }
    AMAuth::SecureZero(plain);
    managers.interfaces.prompt_io_manager->Print(
        "✅ Password copied to clipboard!");
    return OK;
  }
  void reset() override { password.clear(); }
};

} // namespace AMInterface::cli



