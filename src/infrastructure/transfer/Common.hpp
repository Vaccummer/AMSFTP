#pragma once

#include "domain/client/ClientPort.hpp"
#include "domain/transfer/TransferDomainModel.hpp"
#include "domain/transfer/TransferPort.hpp"
#include "foundation/core/DataClass.hpp"
#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <deque>
#include <functional>
#include <future>
#include <list>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <stop_token>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

namespace AMInfra::transfer {
using AMDomain::transfer::TaskAssignType;
using AMDomain::transfer::TaskID;
using ClientHandle = std::shared_ptr<AMDomain::client::IClientPort>;
using EC = ErrorCode;
using ErrorCBInfo = AMDomain::transfer::ErrorCBInfo;
using ProgressCBInfo = AMDomain::transfer::ProgressCBInfo;
using TaskHandle = std::shared_ptr<AMDomain::transfer::TaskInfo>;
using TaskInfo = AMDomain::transfer::TaskInfo;
using TaskRegistry = AMAtomic<std::unordered_map<TaskID, TaskHandle>>;
using TaskStatus = AMDomain::transfer::TaskStatus;
using TransferClientContainer = AMDomain::transfer::TransferClientContainer;
using TransferTask = AMDomain::transfer::TransferTask;

struct TransferBufferPolicy {
  size_t default_buffer_size =
      AMDomain::client::ClientService::AMDefaultBufferSize;
  size_t min_buffer_size = AMDomain::client::ClientService::AMMinBufferSize;
  size_t max_buffer_size = AMDomain::client::ClientService::AMMaxBufferSize;
};
} // namespace AMInfra::transfer
