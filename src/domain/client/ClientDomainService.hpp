#pragma once
#include "domain/client/ClientPort.hpp"
#include <cstdint>

namespace AMDomain::client::ClientService {
constexpr int64_t AMDefaultLocalBufferSize = 1024 * 1024 * 16;
constexpr int64_t AMDefaultRemoteBufferSize = 1024 * 1024 * 8;
constexpr int64_t AMMinBufferSize = 1024 * 4;
constexpr int64_t AMMaxBufferSize = 1024 * 1024 * 1024;
constexpr float AMDefaultTimeoutMs = -1.0f;

inline int64_t ClampBufferSize(int64_t size, bool is_local) {
  if (size <= 0) {
    return is_local ? AMDefaultLocalBufferSize : AMDefaultRemoteBufferSize;
  }
  if (size <= AMMinBufferSize) {
    return AMMinBufferSize;
  }
  if (size > AMMaxBufferSize) {
    return AMMaxBufferSize;
  }
  return size;
};

inline ClientID GenerateID(ClientProtocol protocol) {
  static std::atomic<uint64_t> counter{0};
  const uint64_t id = counter.fetch_add(1, std::memory_order_relaxed);
  switch (protocol) {
  case ClientProtocol::SFTP:
    return AMStr::fmt("SFTP-{}", id);
  case ClientProtocol::FTP:
    return AMStr::fmt("FTP-{}", id);
  case ClientProtocol::LOCAL:
    return AMStr::fmt("LOCAL-{}", id);
  default:
    return "";
  }
}

} // namespace AMDomain::client::ClientService

namespace AMDomain::client::MaintainerService {
static constexpr int HeartbeatTimeoutMinMs = 10;
static constexpr int HeartbeatTimeoutMaxMs = 10000;
static constexpr int HeartbeatIntervalMinS = 1;
static constexpr int HeartbeatIntervalMaxS = 3600;

[[nodiscard]] inline unsigned int ClampHeartbeatTimeoutMs(int timeout_ms) {
  return timeout_ms < HeartbeatTimeoutMinMs
             ? HeartbeatTimeoutMinMs
             : (timeout_ms > HeartbeatTimeoutMaxMs ? HeartbeatTimeoutMaxMs
                                                   : timeout_ms);
};

[[nodiscard]] inline unsigned int ClampHeartbeatIntervalS(int interval_s) {
  return interval_s < HeartbeatIntervalMinS
             ? HeartbeatIntervalMinS
             : (interval_s > HeartbeatIntervalMaxS ? HeartbeatIntervalMaxS
                                                   : interval_s);
};

} // namespace AMDomain::client::MaintainerService
