#pragma once

#include "domain/filesystem/FileSystemModel.hpp"
#include "domain/transfer/TransferDomainModel.hpp"

#include <optional>
#include <string>
#include <vector>

namespace AMInterface::transfer {

enum class TransferConfirmPolicy {
  RequireConfirm,
  AutoApprove,
  DenyIfConfirmNeeded
};

struct TransferRunArg {
  std::vector<AMDomain::transfer::UserTransferSet> transfer_sets = {};
  bool quiet = false;
  bool run_async = false;
  int timeout_ms = 0;
  TransferConfirmPolicy confirm_policy = TransferConfirmPolicy::RequireConfirm;
};

struct HttpGetArg {
  std::string src_url = {};
  std::optional<AMDomain::filesystem::PathTarget> dst_target = std::nullopt;
  std::string username = {};
  std::string password = {};
  std::string proxy = {};
  std::string https_proxy = {};
  std::string bear_token = {};
  int redirect_times = -1;
  bool resume = false;
  bool overwrite = false;
  bool quiet = false;
  bool run_async = false;
  int timeout_ms = 0;
  TransferConfirmPolicy confirm_policy = TransferConfirmPolicy::RequireConfirm;
};

struct TransferTaskListArg {
  bool pending = false;
  bool suspend = false;
  bool finished = false;
  bool conducting = false;
};

struct TransferTaskShowArg {
  std::vector<AMDomain::transfer::TaskID> ids = {};
};

struct TransferTaskControlArg {
  std::vector<AMDomain::transfer::TaskID> ids = {};
  int timeout_ms = 5000;
  int grace_period_ms = 1500;
};

struct TransferTaskInspectArg {
  AMDomain::transfer::TaskID id = 0;
  bool show_sets = true;
  bool show_entries = true;
};

struct TransferTaskResultArg {
  std::vector<AMDomain::transfer::TaskID> ids = {};
  bool remove = false;
};

struct TransferTaskRemoveArg {
  std::vector<AMDomain::transfer::TaskID> ids = {};
};

} // namespace AMInterface::transfer
