#pragma once

#include "infrastructure/client/runtime/IOCore.hpp"
#include <memory>
#include <utility>
#include <vector>

namespace AMBootstrap {
/**
 * @brief Bootstrap forwarding helper for runtime client factory.
 *
 * Prefer calling AMInfra::ClientRuntime::CreateClient directly from concrete
 * runtime/adapter paths. This wrapper is kept for migration compatibility.
 */
inline std::shared_ptr<BaseClient>
CreateClient(const ConRequest &request, ssize_t trace_num = 10,
             TraceCallback trace_cb = {}, std::vector<std::string> keys = {},
             AuthCallback auth_cb = {}) {
  return AMInfra::ClientRuntime::CreateClient(
      request, trace_num, std::move(trace_cb), std::move(keys),
      std::move(auth_cb));
}
} // namespace AMBootstrap
