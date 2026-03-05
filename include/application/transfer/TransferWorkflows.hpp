#pragma once

#include "domain/transfer/TransferPorts.hpp"
#include "foundation/DataClass.hpp"
#include <string>
#include <vector>

namespace AMApplication::TransferWorkflow {
/**
 * @brief Application-facing transfer input payload.
 */
struct TransferBuildArgs {
  /**
   * @brief Source path arguments from command/input.
   */
  std::vector<std::string> srcs;

  /**
   * @brief Optional destination argument.
   */
  std::string output;

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
   * @brief Whether trailing `&` should be interpreted as async marker.
   */
  bool accept_ampersand_suffix = false;
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
 * @brief Port for path-like substitution.
 */
class IPathSubstitutionPort {
public:
  /**
   * @brief Virtual destructor for polymorphic substitution port.
   */
  virtual ~IPathSubstitutionPort() = default;

  /**
   * @brief Substitute one path-like token.
   */
  [[nodiscard]] virtual std::string
  SubstitutePathLike(const std::string &raw) const = 0;

  /**
   * @brief Substitute multiple path-like tokens.
   */
  [[nodiscard]] virtual std::vector<std::string>
  SubstitutePathLike(const std::vector<std::string> &raw) const = 0;
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
 * @brief Build one normalized user transfer set from input arguments.
 *
 * @param args Raw transfer input.
 * @param substitutor Path substitution port.
 * @param accept_ampersand_suffix Whether `&` suffix is consumed from sources.
 * @param out_set Built transfer set.
 * @param out_suffix_async Whether async suffix was detected.
 * @return Validation/build result.
 */
ECM BuildTransferSet(const TransferBuildArgs &args,
                     const IPathSubstitutionPort &substitutor,
                     bool accept_ampersand_suffix, UserTransferSet *out_set,
                     bool *out_suffix_async = nullptr);

/**
 * @brief Execute transfer workflow using domain transfer executor port.
 *
 * @param args Raw transfer input.
 * @param options Execution policy flags.
 * @param substitutor Path substitution port.
 * @param executor Domain transfer executor.
 * @param interrupt_flag Optional task-control token.
 * @return Execution status plus normalized payload.
 */
TransferExecutionResult
ExecuteTransfer(const TransferBuildArgs &args,
                const TransferExecutionOptions &options,
                const IPathSubstitutionPort &substitutor,
                AMDomain::transfer::ITransferExecutorPort &executor,
                amf interrupt_flag = nullptr);
} // namespace AMApplication::TransferWorkflow
