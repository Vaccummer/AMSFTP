# New Config format and manage method

@include/AMCommonTools.hpp

@include/AMConfigManager.hpp

@D:\Compiler\vcpkg\installed\x64-windows\include\toml++

**I need to switch the configuration file format to TOML and use the **`toml++` library to handle the source files. The library has already been installed via vcpkg.

**The **`AMConfigProcessor` class should retain its current function interface, but its supported format will change from YAML to TOML.

**Additionally, **`AMConfigProcessor` needs to implement two new features:

* **A function to convert its internal data type **`FlatMap` back into a TOML node.
* **A function to directly write a TOML node to a file.**
