#pragma once
#include "AMClientManager.hpp"
#include "AMConfigManager.hpp"
#include "AMPromptManager.hpp"
#include "base/AMEnum.hpp"
#include <string>
#include <utility>
#include <vector>

class AMFileSystem {
public:
  using ECM = std::pair<ErrorCode, std::string>;
  /** Global interrupt flag used when no flag is provided. */
  inline static amf global_interrupt_flag = std::make_shared<InterruptFlag>();

  /** Disable copy construction. */
  AMFileSystem(const AMFileSystem &) = delete;
  /** Disable copy assignment. */
  AMFileSystem &operator=(const AMFileSystem &) = delete;
  /** Disable move construction. */
  AMFileSystem(AMFileSystem &&) = delete;
  /** Disable move assignment. */
  AMFileSystem &operator=(AMFileSystem &&) = delete;

  /** Return the singleton instance. */
  static AMFileSystem &Instance(AMClientManager &client_manager,
                                AMConfigManager &config_manager);

  /** Check whether a client exists and print status. */
  ECM check(const std::string &nickname, amf interrupt_flag = nullptr);
  /** Create/connect a client by nickname. */
  ECM connect(const std::string &nickname, amf interrupt_flag = nullptr);
  /** Switch current client, optionally creating it. */
  ECM change_client(const std::string &nickname, amf interrupt_flag = nullptr);
  /** Remove a client from the manager with confirmation. */
  ECM remove_client(const std::string &nickname);
  /** Change working directory with history support. */
  ECM cd(const std::string &path, amf interrupt_flag = nullptr);
  /** Print all clients with real-time status. */
  ECM print_clients(amf interrupt_flag = nullptr);
  /** Print stat info for a path. */
  ECM stat(const std::string &path, amf interrupt_flag = nullptr);
  /** List directory entries; list_like enables long format, show_all shows dot
   * entries. */
  ECM ls(const std::string &path, bool list_like = false, bool show_all = false,
         amf interrupt_flag = nullptr);
  /** Print total size of a path. */
  ECM getsize(const std::string &path, amf interrupt_flag = nullptr);
  /** Find paths matching the pattern. */
  ECM find(const std::string &path, amf interrupt_flag = nullptr);
  /** Create directory (recursive). */
  ECM mkdir(const std::string &path, amf interrupt_flag = nullptr);
  /** Remove a path using safe removal. */
  ECM rm(const std::string &path, amf interrupt_flag = nullptr);

private:
  /** Construct with required managers. */
  AMFileSystem(AMClientManager &client_manager,
               AMConfigManager &config_manager);

  /** Resolved client reference helper. */
  struct ClientRef {
    std::string nickname;
    std::shared_ptr<BaseClient> client;
    AMClientManager::PoolKind pool = AMClientManager::PoolKind::Operation;
    /** Return true if client is valid. */
    [[nodiscard]] bool is_valid() const { return static_cast<bool>(client); }
  };

  /** Resolve client by nickname and pool (case-insensitive). */
  ClientRef ResolveClientByName(const std::string &nickname,
                                AMClientManager::PoolKind pool) const;
  /** Resolve client and raw path from input. */
  ClientRef ResolveClientForPath(const std::string &input,
                                 std::string *out_path,
                                 bool allow_config_probe = false,
                                 amf interrupt_flag = nullptr);
  /** Resolve client or prompt to create it. */
  ClientRef ResolveOrCreateClient(const std::string &nickname,
                                  amf interrupt_flag = nullptr);
  /** Normalize nickname to lowercase for comparisons. */
  std::string NormalizeNickname(const std::string &nickname) const;
  /** Build absolute path using AMFS::abspath and workdir. */
  std::string BuildPath(const ClientRef &client, const std::string &path) const;
  /** Get client workdir from public map or fallback to home dir. */
  std::string GetClientWorkdir(const std::shared_ptr<BaseClient> &client) const;
  /** Set client workdir in public map. */
  void SetClientWorkdir(const std::shared_ptr<BaseClient> &client,
                        const std::string &path);
  /** Ensure workdir exists in public map. */
  void EnsureClientWorkdir(const std::shared_ptr<BaseClient> &client);
  /** Get workdir and initialize if missing. */
  std::string GetOrInitWorkdir(const std::shared_ptr<BaseClient> &client) const;
  /** Update cd history. */
  void UpdateHistory(const std::string &nickname, const std::string &path);
  /** Print a client status line. */
  ECM PrintClientStatus(const ClientRef &client, bool update = true,
                        amf interrupt_flag = nullptr);
  /** Format size to human-readable string. */
  std::string FormatSize(uint64_t size) const;
  /** Format unix timestamp to printable time. */
  std::string FormatTimestamp(double value) const;
  /** Format path type to string. */
  std::string FormatPathType(PathType type) const;
  /** Format stat output block. */
  std::string FormatStatOutput(const PathInfo &info) const;
  /** Apply styling for a path based on type. */
  std::string StylePath(const PathInfo &info, const std::string &path) const;
  /** Prompt for yes/no. */
  bool PromptYesNo(const std::string &prompt, bool default_no = true) const;
  /** Return true when path is absolute. */
  bool IsAbsolutePath(const std::string &path) const;

  AMClientManager &client_manager_;
  AMConfigManager &config_manager_;
  AMPromptManager &prompt_manager_;
  std::string last_cd_;
};
