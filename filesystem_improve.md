Improve AMFileSystem

@include\AMClient\AMBaseClient.hpp

@D:\CodeLib\CPP\AMSFTP\include\AMFileSystem.hpp

* **Add a thread-safe map of type **`<std::string, std::string>` to `AMTracer`. Remove all variables and operations related to `public_var`, and directly expose this new map to external code.
* **When a client is created, write its home directory as the initial working directory (**`workdir`) into the map.
* **Upon successful **`cd` operations, update the `workdir` entry for the corresponding client in the map.
* **When resolving paths, first use **`ResolveClientForPath` to extract the client and raw path. Then, pass the raw path along with the client’s current working directory (from the map) to `AMFS::abspath`, and enforce the use of Unix-style path separators (`/`).
