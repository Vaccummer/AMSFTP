#pragma once

#pragma message("AMSFTP deprecated header: include/interface/adapters/FileCommandGateway.dep.hpp; prefer interface/adapters/FileSystemAdapter.hpp")
#ifdef __GNUC__
#warning "AMSFTP deprecated header: include/interface/adapters/FileCommandGateway.dep.hpp; prefer interface/adapters/FileSystemAdapter.hpp"
#endif

#include "application/client/FileCommandWorkflows.hpp"
#include "application/client/ClientAppService.hpp"
#include "foundation/DataClass.hpp"
#include <string>
#include <utility>
#include <vector>

namespace AMInterface::ApplicationAdapters {
using EC = ErrorCode;

/**
 * @brief Deprecated compatibility gateway over filesystem app service.
 *
 * Use `FileSystemCliAdapter` instead for active interface-path calls.
 */
class [[deprecated("Use FileSystemCliAdapter from FileSystemAdapter.hpp")]]
    FileCommandGateway final
    : public AMApplication::FileCommandWorkflow::IFileCommandGateway {
public:
  /**
   * @brief Construct deprecated gateway from client app service.
   */
  explicit FileCommandGateway(
      AMApplication::client::ClientAppService &client_service);

  ECM CheckClients(const std::vector<std::string> &nicknames, bool detail,
                   amf interrupt_flag = nullptr) override;
  ECM ListClients(bool detail, amf interrupt_flag = nullptr);
  ECM DisconnectClients(const std::vector<std::string> &nicknames);
  ECM StatPaths(const std::vector<std::string> &paths,
                amf interrupt_flag = nullptr, int timeout_ms = -1);
  ECM ListPath(const std::string &path, bool list_like, bool show_all,
               amf interrupt_flag = nullptr, int timeout_ms = -1);
  ECM GetSize(const std::vector<std::string> &paths,
              amf interrupt_flag = nullptr, int timeout_ms = -1) override;
  ECM Find(const std::string &path, SearchType type = SearchType::All,
           amf interrupt_flag = nullptr, int timeout_ms = -1) override;
  ECM Mkdir(const std::vector<std::string> &paths,
            amf interrupt_flag = nullptr, int timeout_ms = -1) override;
  ECM Remove(const std::vector<std::string> &paths, bool permanent, bool force,
             bool quiet = false, amf interrupt_flag = nullptr,
             int timeout_ms = -1) override;
  ECM Walk(const std::string &path, bool only_file = false,
           bool only_dir = false, bool show_all = false,
           bool ignore_special_file = true, bool quiet = false,
           amf interrupt_flag = nullptr, int timeout_ms = -1) override;
  ECM Tree(const std::string &path, int max_depth = -1, bool only_dir = false,
           bool show_all = false, bool ignore_special_file = true,
           bool quiet = false, amf interrupt_flag = nullptr,
           int timeout_ms = -1) override;
  ECM Realpath(const std::string &path, amf interrupt_flag = nullptr,
               int timeout_ms = -1) override;
  ECM TestRtt(int times = 1, amf interrupt_flag = nullptr) override;
  ECM Cd(const std::string &path, amf interrupt_flag = nullptr,
         bool from_history = false) override;
  std::pair<ECM, std::pair<std::string, int>>
  ShellRun(const std::string &cmd, int max_time_ms = -1,
           amf interrupt_flag = nullptr) override;

private:
  AMApplication::client::ClientAppService &client_service_;
};
} // namespace AMInterface::ApplicationAdapters
