improve local_client

The `AMConfigManager`'s `local_client` is initialized by reading the `[LocalClient]` section from `setting.toml`, and it binds the trace callback function, among other setup steps.

When initializing a `ClientMaintainer`, it may optionally receive a pointer to a `LocalClient`. If none is provided, it creates its own instance.

Check whether the `local_client` has any thread-safety issues. If it is confirmed to be thread-safe, then the `local_client` owned by `AMConfigManager` can be shared as a common client across the system. However, **do not** design `LocalClient` as a singleton class.
