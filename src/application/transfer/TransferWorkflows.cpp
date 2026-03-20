#include "application/transfer/TransferWorkflows.hpp"
#include "foundation/tools/enum_related.hpp"
#include "foundation/tools/string.hpp"

namespace AMApplication::TransferWorkflow {
namespace {
using ClientPath = AMDomain::filesystem::ClientPath;

/**
 * @brief Validate one explicit transfer endpoint payload.
 */
ECM ValidateEndpoint_(const ClientPath &endpoint,
                      const std::string &label) {
  const std::string name = label.empty() ? std::string("endpoint") : label;
  if (endpoint.nickname.empty()) {
    return Err(EC::InvalidArg, AMStr::fmt("{} nickname is empty", name));
  }
  if (endpoint.path.empty()) {
    return Err(EC::InvalidArg, AMStr::fmt("{} path is empty", name));
  }
  return Ok();
}
} // namespace

/**
 * @brief Validate optional trailing async suffix.
 */
ECM ValidateAsyncSuffix(const std::string &async_suffix,
                        bool *out_suffix_async) {
  if (!out_suffix_async) {
    return Err(EC::InvalidArg, "null async suffix output");
  }
  *out_suffix_async = false;
  if (async_suffix.empty()) {
    return Ok();
  }
  if (async_suffix != "&") {
    return Err(EC::InvalidArg, "job submit: trailing arg must be &");
  }
  *out_suffix_async = true;
  return Ok();
}

/**
 * @brief Build one normalized user transfer set from explicit endpoints.
 */
ECM BuildTransferSet(const TransferBuildArgs &args, UserTransferSet *out_set) {
  if (!out_set) {
    return Err(EC::InvalidArg, "null transfer output");
  }

  if (args.srcs.empty()) {
    return Err(EC::InvalidArg, "cp requires at least one source");
  }

  std::vector<ClientPath> transfer_srcs = {};
  ClientPath transfer_dst = {};
  if (args.output.path.empty()) {
    if (args.srcs.size() != 2) {
      return Err(EC::InvalidArg,
                 "cp requires exactly 2 paths when --output is omitted");
    }
    transfer_srcs = {args.srcs.front()};
    transfer_dst = args.srcs.back();
  } else {
    transfer_srcs = args.srcs;
    transfer_dst = args.output;
  }

  ECM dst_rcm = ValidateEndpoint_(transfer_dst, "dst");
  if (!isok(dst_rcm)) {
    return dst_rcm;
  }
  for (size_t i = 0; i < transfer_srcs.size(); ++i) {
    ECM src_rcm = ValidateEndpoint_(
        transfer_srcs[i], AMStr::fmt("src[{}]", std::to_string(i)));
    if (!isok(src_rcm)) {
      return src_rcm;
    }
  }

  std::vector<AMDomain::client::ScopedPath> normalized_srcs = {};
  normalized_srcs.reserve(transfer_srcs.size());
  for (const auto &src : transfer_srcs) {
    AMDomain::client::ScopedPath scoped = {};
    scoped.explicit_client = true;
    scoped.nickname = src.nickname;
    scoped.path = src.path;
    normalized_srcs.push_back(std::move(scoped));
  }
  out_set->srcs = std::move(normalized_srcs);
  out_set->dst = AMDomain::client::ScopedPath{
      true, transfer_dst.nickname, transfer_dst.path};
  out_set->mkdir = !args.no_mkdir;
  out_set->overwrite = args.overwrite;
  out_set->clone = args.clone;
  out_set->ignore_special_file = !args.include_special;
  out_set->resume = args.resume;
  return Ok();
}

/**
 * @brief Execute transfer workflow using domain transfer executor port.
 */
TransferExecutionResult ExecuteTransfer(
    const TransferBuildArgs &args, const TransferExecutionOptions &options,
    AMDomain::transfer::ITransferExecutorPort &executor) {
  (void)options.confirm_policy;
  TransferExecutionResult out = {};
  out.rcm = BuildTransferSet(args, &out.transfer_set);
  if (!isok(out.rcm)) {
    return out;
  }

  out.run_async = options.run_async_from_context;
  if (out.run_async) {
    out.rcm = executor.TransferAsync({out.transfer_set}, options.quiet);
    return out;
  }

  out.rcm = executor.Transfer({out.transfer_set}, options.quiet);
  return out;
}
} // namespace AMApplication::TransferWorkflow
