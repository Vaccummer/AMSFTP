# Improve ClientManager

@include\AMClientManager.hpp

- Treat `LocalClient` the same as other regular clients: initialize it by reading the config entry with nickname `"local"`.
- Change `AMClientManager::client_maintainer` to be held by a **shared pointer** (`std::shared_ptr`).
- Remove the `ClientMaintainerRef& ResolveMaintainer_()` function.Replace its usage sites with a ternary operator (`condition ? a : b`).
- When a `Client` is created:

  1. Read the `login_dir` field from the client's config.
  2. If the value is missing **or** the path does not exist:
     - Fall back to `home_dir`
     - Persist this fallback value back to the config file
  3. Store the resolved directory path in `client->public_kv["workdir"]`.
- Remove the `CreClient()` function.
