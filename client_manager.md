**The objects to be managed are **`SFTPClient`, `FTPClient`, and `LocalClient`.

**The primary purpose of the manager is to centrally manage these clients and provide a unified interface for use by other functions.**

**The manager is closely related to **`HostMaintainer`. You must read its implementation in `@.\include\AMClient\AMCore.hpp`.

**The manager must read configuration data through **`ConfigManager`.

**There is already an immature Python version of **`ClientManager` in `@managers.py`. Note that some function names in this version are not well chosen, and certain interfaces have already been deprecated. However, you can refer to it to understand which functionalities need to be implemented.  **Important** **: this Python code is ***not* a template for your implementation—it only serves as a functional reference. If you can design a better solution, please implement improvements accordingly.

**Some functions in the Python **`ClientManager` are merely placeholders without actual implementations. You may follow the same approach for now—these functions will be implemented later.

**Specific requirements:**

1. **The manager must maintain ****two** `HostMaintainer` instances for storing clients:
   1. **One **`HostMaintainer` stores clients used for  **file transfer operations** **.**
   2. **The other stores clients used for ****non-file-transfer operations** (e.g., `ls`, `mkdir`, `remove`, executing commands, etc.).
   3. **The **`DisconnectCallback` bound to each `HostMaintainer` must distinguish between the two maintainers.
2. **The manager must set a **`PasswordCallback` function.
3. **The manager must provide a series of operations for managing clients.**
