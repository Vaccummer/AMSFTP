#pragma once
#include "AMBase/Enum.hpp"
#include "AMManager/Client.hpp"
#include "AMManager/Config.hpp"
#include "AMManager/Prompt.hpp"
#include <cstdint>
#include <list>
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

  /** Check whether clients exist and print status. */
  ECM check(const std::string &nickname, bool detail = false,
            amf interrupt_flag = nullptr);
  /** Check whether clients exist from nickname list. */
  ECM check(const std::vector<std::string> &nicknames, bool detail = false,
            amf interrupt_flag = nullptr);
  /** Create/connect a client by nickname, optionally rebuilding it. */
  ECM connect(const std::string &nickname, bool force = false,
              amf interrupt_flag = nullptr, bool switch_client = true);
  /** Create/connect an SFTP client by connection info. */
  ECM sftp(const std::string &nickname, const std::string &hostname,
           const std::string &username, int64_t port,
           const std::string &password, const std::string &keyfile,
           amf interrupt_flag = nullptr);
  /** Create/connect an SFTP client by user@host string. */
  ECM sftp(const std::string &nickname, const std::string &user_at_host,
           int64_t port, const std::string &password,
           const std::string &keyfile, amf interrupt_flag = nullptr);
  /** Create/connect an FTP client by connection info. */
  ECM ftp(const std::string &nickname, const std::string &hostname,
          const std::string &username, int64_t port,
          const std::string &password, const std::string &keyfile,
          amf interrupt_flag = nullptr);
  /** Create/connect an FTP client by user@host string. */
  ECM ftp(const std::string &nickname, const std::string &user_at_host,
          int64_t port, const std::string &password, const std::string &keyfile,
          amf interrupt_flag = nullptr);
  /** Switch current client, optionally creating it. */
  ECM change_client(const std::string &nickname, amf interrupt_flag = nullptr);
  /** Remove a client from the manager with confirmation. */
  ECM remove_client(const std::string &nickname);
  /** Change working directory with history support. */
  ECM cd(const std::string &path, amf interrupt_flag = nullptr,
         bool from_history = false);
  /** Print all clients with optional detailed status. */
  ECM print_clients(bool detail = false, amf interrupt_flag = nullptr);
  /** Print stat info for a path. */
  ECM stat(const std::string &path, amf interrupt_flag = nullptr,
           int timeout_ms = -1);
  /** Print stat info for multiple paths. */
  ECM stat(const std::vector<std::string> &paths, amf interrupt_flag = nullptr,
           int timeout_ms = -1);
  /** List directory entries; list_like enables long format, show_all shows dot
   * entries. */
  ECM ls(const std::string &path, bool list_like = false, bool show_all = false,
         amf interrupt_flag = nullptr, int timeout_ms = -1);
  /** Print total size of a path. */
  ECM getsize(const std::string &path, amf interrupt_flag = nullptr,
              int timeout_ms = -1);
  /** Print total size for multiple paths. */
  ECM getsize(const std::vector<std::string> &paths,
              amf interrupt_flag = nullptr, int timeout_ms = -1);
  /** Find paths matching the pattern. */
  ECM find(const std::string &path, SearchType type = SearchType::All,
           amf interrupt_flag = nullptr, int timeout_ms = -1);
  /** Create directory (recursive). */
  ECM mkdir(const std::string &path, amf interrupt_flag = nullptr,
            int timeout_ms = -1);
  /** Create directories (recursive) for multiple paths. */
  ECM mkdir(const std::vector<std::string> &paths, amf interrupt_flag = nullptr,
            int timeout_ms = -1);
  /** Remove a path using safe removal. */
  ECM rm(const std::string &path, bool quiet = false,
         amf interrupt_flag = nullptr, int timeout_ms = -1);
  /** Remove paths using safe removal. */
  ECM rm(const std::vector<std::string> &paths, bool quiet = false,
         amf interrupt_flag = nullptr, int timeout_ms = -1);
  /** Remove paths using safe or permanent removal with optional force. */
  ECM rm(const std::vector<std::string> &paths, bool permanent, bool force,
         bool quiet = false, amf interrupt_flag = nullptr,
         int timeout_ms = -1);
  /** Move multiple sources into destination without cross-client moves. */
  ECM move(const std::vector<std::string> &srcs, const std::string &dst,
           bool mkdir = false, bool overwrite = false,
           amf interrupt_flag = nullptr, int timeout_ms = -1);
  /** Rename a single source to destination without cross-client moves. */
  ECM rename(const std::string &src, const std::string &dst, bool mkdir = false,
             bool overwrite = false, amf interrupt_flag = nullptr,
             int timeout_ms = -1);
  /** Walk a path and print entries; only_file/only_dir controls filtering. */
  ECM walk(const std::string &path, bool only_file = false,
           bool only_dir = false, bool show_all = false,
           bool ignore_special_file = true, bool quiet = false,
           amf interrupt_flag = nullptr, int timeout_ms = -1);
  /** Print a directory tree like unix tree using walk output and filters. */
  ECM tree(const std::string &path, int max_depth = -1, bool only_dir = false,
           bool show_all = false, bool ignore_special_file = true,
           bool quiet = false, amf interrupt_flag = nullptr,
           int timeout_ms = -1);
  /** Measure current client RTT and print the result. */
  ECM TestRTT(int times = 1, amf interrupt_flag = nullptr);
  /** Print the absolute path resolved by client home/workdir. */
  ECM realpath(const std::string &path, amf interrupt_flag = nullptr,
               int timeout_ms = -1);
  /** Print the protocol name for a client (defaults to current). */
  ECM GetProtocol(const std::string &nickname = "",
                  amf interrupt_flag = nullptr);
  /** Print the trash directory for a client (defaults to current). */
  ECM TrashDir(const std::string &nickname = "", amf interrupt_flag = nullptr,
               int timeout_ms = -1);
  /** Print the home directory for a client (defaults to current). */
  ECM HomeDir(const std::string &nickname = "", amf interrupt_flag = nullptr,
              int timeout_ms = -1);
  /** Update the trash directory and persist it in config. */
  ECM SetTrashDir(const std::string &trash_dir,
                  const std::string &nickname = "",
                  amf interrupt_flag = nullptr, int timeout_ms = -1);
  /** Update transfer buffer size and persist it in config. */
  ECM SetBufferSize(int64_t buffer_size, const std::string &nickname = "",
                    amf interrupt_flag = nullptr);
  /** Apply styling for a path based on type. */
  std::string StylePath(const PathInfo &info, const std::string &path) const;

private:
  /** Construct with required managers. */
  AMFileSystem(AMClientManager &client_manager,
               AMConfigManager &config_manager);

  /** Resolved client reference helper. */
  struct ClientRef {
    std::string nickname;
    std::shared_ptr<BaseClient> client;
    /** Return true if client is valid. */
    [[nodiscard]] bool is_valid() const { return static_cast<bool>(client); }
  };

  /** Split a whitespace separated target list. */
  [[nodiscard]] std::vector<std::string>
  SplitTargets(const std::string &input) const;
  /** Build absolute path using AMFS::abspath and workdir. */
  [[nodiscard]] std::string BuildPath(const ClientRef &client,
                                      const std::string &path) const;
  /** Update cd history. */
  void UpdateHistory(const std::string &nickname, const std::string &path);
  /** Print a client status line. */
  ECM PrintClientStatus(const ClientRef &client, bool update = true,
                        amf interrupt_flag = nullptr);
  /** Format unix timestamp to printable time. */
  std::string FormatTimestamp(double value) const;
  /** Format stat output block. */
  std::string FormatStatOutput(const PathInfo &info) const;
  /**
   * @brief Create a walk error callback that prints formatted errors.
   * @param func_name Function label for error messages.
   * @param quiet When true, suppress callback creation.
   * @return WalkErrorCallback instance or nullptr when quiet.
   */
  [[nodiscard]] AMFS::WalkErrorCallback
  MakeWalkErrorCallback(const std::string &func_name, bool quiet) const;

  AMClientManager &client_manager_;
  AMConfigManager &config_manager_;
  AMPromptManager &prompt_manager_;
  std::list<std::string> cd_history_;
};
