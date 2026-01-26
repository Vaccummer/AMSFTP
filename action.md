# Adjust the function calls in **`AMConfigManager` according to the updated `AMConfigProcessor`.

@include/`AMConfigManager`.hpp

@src/`AMConfigManager`.cpp

`AMConfigManager` will no longer use `FlatMap` as the storage object for configuration data. Instead, `FlatMap` will only be used during initial loading for filtering out invalid keys. After this filtering step, the data must be converted into the standard TOML data format.

**Consequently, all operations that read configuration data also need to be updated accordingly.**

**You may add helper functions to **`AMConfigProcessor` as needed to facilitate these operations in the config manager.
