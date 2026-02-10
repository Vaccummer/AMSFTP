#pragma once
#include <atomic>
#include <condition_variable>
#include <cstddef>
#include <memory>
#include <mutex>
#include <string>
#include <thread>

struct ic_completion_env_s;
using ic_completion_env_t = ic_completion_env_s;

class AMClientManager;
class AMConfigManager;
class AMFileSystem;
class AMTransferManager;

/**
 * @brief Completion coordinator for interactive input.
 */
class AMCompleter {
public:
  /**
   * @brief Construct the completer with required managers.
   *
   * @param config_manager Settings/config manager reference.
   * @param client_manager Client manager reference.
   * @param filesystem Filesystem manager reference.
   * @param transfer_manager Transfer manager reference.
   */
  AMCompleter(AMConfigManager &config_manager, AMClientManager &client_manager,
              AMFileSystem &filesystem, AMTransferManager &transfer_manager);

  /**
   * @brief Stop the async worker and release resources.
   */
  ~AMCompleter();

  /**
   * @brief Install the completer into the isocline environment.
   */
  void Install();

  /**
   * @brief Clear any cached completion results.
   */
  void ClearCache();

  /**
   * @brief Return the currently active completer instance.
   */
  static AMCompleter *Active();

  /**
   * @brief Set the active completer instance.
   *
   * @param instance Completer instance or nullptr to clear.
   */
  static void SetActive(AMCompleter *instance);

private:
  /**
   * @brief Isocline callback entrypoint for completion.
   *
   * @param cenv Completion environment provided by isocline.
   * @param prefix Raw input prefix before the cursor.
   */
  static void IsoclineCompleter(ic_completion_env_t *cenv, const char *prefix);

  AMCompleter(const AMCompleter &) = delete;
  AMCompleter &operator=(const AMCompleter &) = delete;
  AMCompleter(AMCompleter &&) = delete;
  AMCompleter &operator=(AMCompleter &&) = delete;

  /**
   * @brief Opaque implementation container.
   */
  struct Impl;

  std::unique_ptr<Impl> impl_;
};
