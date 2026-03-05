#include "application/transfer/TransferWorkflows.hpp"
#include "foundation/tools/enum_related.hpp"

namespace AMApplication::TransferWorkflow {
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
 * @brief Build one normalized user transfer set from input arguments.
 */
ECM BuildTransferSet(const TransferBuildArgs &args,
                     const IPathSubstitutionPort &substitutor,
                     bool accept_ampersand_suffix, UserTransferSet *out_set,
                     bool *out_suffix_async) {
  if (!out_set) {
    return Err(EC::InvalidArg, "null transfer output");
  }

  bool suffix_async = false;
  std::vector<std::string> raw_srcs = args.srcs;
  if (accept_ampersand_suffix && !raw_srcs.empty() && raw_srcs.back() == "&") {
    suffix_async = true;
    raw_srcs.pop_back();
  }

  if (raw_srcs.empty()) {
    return Err(EC::InvalidArg, "cp requires at least one source");
  }

  const std::vector<std::string> resolved_srcs =
      substitutor.SubstitutePathLike(raw_srcs);
  const std::string resolved_output =
      substitutor.SubstitutePathLike(args.output);

  std::vector<std::string> transfer_srcs;
  std::string transfer_dst;
  if (resolved_output.empty()) {
    if (resolved_srcs.size() != 2) {
      return Err(EC::InvalidArg,
                 "cp requires exactly 2 paths when --output is omitted");
    }
    transfer_srcs = {resolved_srcs.front()};
    transfer_dst = resolved_srcs.back();
  } else {
    transfer_srcs = resolved_srcs;
    transfer_dst = resolved_output;
  }

  out_set->srcs = std::move(transfer_srcs);
  out_set->dst = std::move(transfer_dst);
  out_set->mkdir = !args.no_mkdir;
  out_set->overwrite = args.overwrite;
  out_set->clone = args.clone;
  out_set->ignore_special_file = !args.include_special;
  out_set->resume = args.resume;
  if (out_suffix_async) {
    *out_suffix_async = suffix_async;
  }
  return Ok();
}

/**
 * @brief Execute transfer workflow using domain transfer executor port.
 */
TransferExecutionResult ExecuteTransfer(
    const TransferBuildArgs &args, const TransferExecutionOptions &options,
    const IPathSubstitutionPort &substitutor,
    AMDomain::transfer::ITransferExecutorPort &executor, amf interrupt_flag) {
  TransferExecutionResult out = {};
  bool suffix_async = false;
  out.rcm = BuildTransferSet(args, substitutor, options.accept_ampersand_suffix,
                             &out.transfer_set, &suffix_async);
  if (!isok(out.rcm)) {
    return out;
  }

  out.run_async = options.run_async_from_context || suffix_async;
  if (out.run_async) {
    out.rcm = executor.TransferAsync({out.transfer_set}, options.quiet,
                                     interrupt_flag);
    return out;
  }

  out.rcm =
      executor.Transfer({out.transfer_set}, options.quiet, interrupt_flag);
  return out;
}
} // namespace AMApplication::TransferWorkflow
