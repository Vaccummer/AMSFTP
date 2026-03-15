#pragma once

#include "application/filesystem/FileSystemAppService.hpp"
#include "foundation/DataClass.hpp"
#include <string>
#include <utility>
#include <vector>

class AMPromptManager;

namespace AMInterface::ApplicationAdapters {
/**
 * @brief Direct interface-layer filesystem adapter used by CLI bind calls.
 *
 * This adapter owns user interaction policy (confirmation/prompt) and delegates
 * execution to application filesystem service.
 */
class FileSystemCliAdapter final {
public:
  /**
   * @brief Construct direct CLI adapter from app service and prompt manager.
   */
  FileSystemCliAdapter(
      AMApplication::filesystem::FileSystemAppService &filesystem_service,
      AMPromptManager &prompt_manager);

  /**
   * @brief Check clients by nickname list.
   */
  ECM CheckClients(const std::vector<std::string> &nicknames, bool detail,
                   amf interrupt_flag = nullptr) const;

  /**
   * @brief List clients.
   */
  ECM ListClients(bool detail, amf interrupt_flag = nullptr) const;

  /**
   * @brief Disconnect clients by nickname list.
   */
  ECM DisconnectClients(const std::vector<std::string> &nicknames) const;

  /**
   * @brief Query stat results for one or more paths.
   */
  ECM StatPaths(const std::vector<std::string> &paths,
                amf interrupt_flag = nullptr, int timeout_ms = -1) const;

  /**
   * @brief Query list results for one path.
   */
  ECM ListPath(const std::string &path, bool list_like, bool show_all,
               amf interrupt_flag = nullptr, int timeout_ms = -1) const;

  /**
   * @brief Query size results for one or more paths.
   */
  ECM GetSize(const std::vector<std::string> &paths,
              amf interrupt_flag = nullptr, int timeout_ms = -1) const;

  /**
   * @brief Query find results for one path.
   */
  ECM Find(const std::string &path, SearchType type = SearchType::All,
           amf interrupt_flag = nullptr, int timeout_ms = -1) const;

  /**
   * @brief Create directories for one or more paths.
   */
  ECM Mkdir(const std::vector<std::string> &paths, amf interrupt_flag = nullptr,
            int timeout_ms = -1) const;

  /**
   * @brief Remove paths with interface-owned confirmation behavior.
   */
  ECM Remove(const std::vector<std::string> &paths, bool permanent,
             bool quiet = false, amf interrupt_flag = nullptr,
             int timeout_ms = -1) const;

  /**
   * @brief Query walk results.
   */
  ECM Walk(const std::string &path, bool only_file = false,
           bool only_dir = false, bool show_all = false,
           bool ignore_special_file = true, bool quiet = false,
           amf interrupt_flag = nullptr, int timeout_ms = -1) const;

  /**
   * @brief Query tree results.
   */
  ECM Tree(const std::string &path, int max_depth = -1, bool only_dir = false,
           bool show_all = false, bool ignore_special_file = true,
           bool quiet = false, amf interrupt_flag = nullptr,
           int timeout_ms = -1) const;

  /**
   * @brief Query realpath result.
   */
  ECM Realpath(const std::string &path, amf interrupt_flag = nullptr,
               int timeout_ms = -1) const;

  /**
   * @brief Measure RTT for current client.
   */
  ECM TestRtt(int times = 1, amf interrupt_flag = nullptr) const;

  /**
   * @brief Change current workdir.
   */
  ECM Cd(const std::string &path, amf interrupt_flag = nullptr,
         bool from_history = false) const;

  /**
   * @brief Execute one shell command and return output + code.
   */
  std::pair<ECM, std::pair<std::string, int>>
  ShellRun(const std::string &cmd, int max_time_ms = -1,
           amf interrupt_flag = nullptr) const;

private:
  AMApplication::filesystem::FileSystemAppService &filesystem_service_;
  AMPromptManager &prompt_manager_;
};
} // namespace AMInterface::ApplicationAdapters
