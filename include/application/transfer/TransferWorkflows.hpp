#pragma once

#include "domain/filesystem/FileSystemModel.hpp"
#include "domain/transfer/TransferPorts.hpp"
#include <string>
#include <vector>

namespace AMApplication::TransferWorkflow {
/**
 * @brief Explicit confirmation policy for transfer operations.
 */
enum class TransferConfirmPolicy {
  RequireConfirm,
  AutoApprove,
  DenyIfConfirmNeeded
};

/**
 * @brief Application-facing transfer input payload.
 */
struct TransferBuildArgs {
  /**
   * @brief Explicit source endpoints from interface normalization.
   */
  std::vector<AMDomain::filesystem::ClientPath> srcs;

  /**
   * @brief Optional explicit destination endpoint.
   */
  AMDomain::filesystem::ClientPath output;

  /**
   * @brief Enable overwrite behavior.
   */
  bool overwrite = false;

  /**
   * @brief Disable destination mkdir behavior.
   */
  bool no_mkdir = false;

  /**
   * @brief Enable clone mode.
   */
  bool clone = false;

  /**
   * @brief Include special files.
   */
  bool include_special = false;

  /**
   * @brief Enable resume behavior.
   */
  bool resume = false;
};

/**
 * @brief Input policy flags for execution workflow.
 */
struct TransferExecutionOptions {
  /**
   * @brief Whether current run context requests async.
   */
  bool run_async_from_context = false;

  /**
   * @brief Whether execution should be quiet.
   */
  bool quiet = false;

  /**
   * @brief Confirmation policy passed from interface to application.
   */
  TransferConfirmPolicy confirm_policy = TransferConfirmPolicy::RequireConfirm;
};

/**
 * @brief Result of transfer execution orchestration.
 */
struct TransferExecutionResult {
  /**
   * @brief Execution status code and message.
   */
  ECM rcm = {EC::Success, ""};

  /**
   * @brief Effective async mode selected by workflow.
   */
  bool run_async = false;

  /**
   * @brief Normalized transfer set passed to executor.
   */
  UserTransferSet transfer_set;
};

/**
 * @brief Validate optional trailing async suffix.
 *
 * @param async_suffix Optional suffix token.
 * @param out_suffix_async Output async flag.
 * @return Validation status.
 */
ECM ValidateAsyncSuffix(const std::string &async_suffix,
                        bool *out_suffix_async);

/**
 * @brief Build one normalized user transfer set from explicit endpoints.
 *
 * @param args Explicit transfer input.
 * @param out_set Built transfer set.
 * @return Validation/build result.
 */
ECM BuildTransferSet(const TransferBuildArgs &args, UserTransferSet *out_set);

/**
 * @brief Execute transfer workflow using domain transfer executor port.
 *
 * @param args Explicit transfer input.
 * @param options Execution policy flags.
 * @param executor Domain transfer executor.
 * @return Execution status plus normalized payload.
 */
TransferExecutionResult
ExecuteTransfer(const TransferBuildArgs &args,
                const TransferExecutionOptions &options,
                AMDomain::transfer::ITransferExecutorPort &executor);
} // namespace AMApplication::TransferWorkflow
