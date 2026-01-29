@src\AMConfigManager.cpp

@include\AMConfigManager.hpp

- Replace `AMConfigManager::Status` with the `ECM` type.

  - If no corresponding code exists in `EC`, create a new one.
- Remove redundant checks in `AMConfigManager::EnsureInitialized`.
- Move generic prompt-related functions from `AMConfigManager` to `PromptManager` (excluding format-customized functions like `PromptModifyFields`).
- Remove the redundant function `AMConfigManager::StyledValue`.
- Replace `AMConfigManager::MaybeStyle` with direct usage of `Format`.
- Add a new field `login_dir` to `ClientConfig`.
- `AMConfigManager::GetClientConfig` must read **all** fields from `ClientConfig`.

  - If a field is missing, assign its default value.
  - Persist these default values back to the config file.
- Provide two utility functions:

  ```cpp
  bool QueryKey(Settings/config, AMConfigProcessor::Path, &value) {
      // Match and retrieve the value at the specified path.
      // Return false if the path does not exist or the value type mismatches.
  }
  ```
  ```cpp
  template<typename T>
  bool SetKey(Settings/config, AMConfigProcessor::Path, T value) {
      // Set/modify the value at the specified path.
      // Create the path if it does not exist (template function).
  }
  ```
- Enhance `AMConfigManager::Delete` to accept **multiple targets** (space-separated).
- Enhance `AMConfigManager::Query` to accept **multiple targets** (space-separated).
