
# Config Manager

**A utility class for managing configuration files. There are two configuration files:**

* `config.yaml`: stores connection-related information for hosts.
* `settings.yaml`: stores application-specific settings.

**In **`AMCommonTools.hpp`, there is a utility class `AMConfigProcessor` for reading YAML files. However, its current `Query` function is insufficient. I would like to enhance it so that when querying a key, a default value can be provided:

* **If the key exists, return a pointer to the queried value.**
* **If the key does not exist, set the key to the given default value in the configuration and then return a pointer to it.**

**The variable and function names I provided are only for reference—you may introduce new, clearer names as needed.**

## Functions of the `config_manager` Class

**The **`config_manager` class is a **singleton** and  **non-copyable** **. Its initialization requires no parameters.**

**All public functions must return an **`int`-style status code represented as `std::pair<std::string, int>` (i.e., `<error_message, error_code>`), where a successful operation returns `< "", 0 >`.

### `Init()` Function

*(Note: This is not the class constructor—just named “Init”)*

1. **Read the environment variable **`$AMSFTP_ROOT` to obtain the project root directory. Configuration files are expected at `{root}/config/config.yaml` and `{root}/config/settings.yaml`.
2. **If the files exist, process them using **`AMConfigProcessor` (from `AMCommonTools.hpp`) and apply user-provided key filters.
3. **If a file does not exist, initialize the corresponding internal **`result_map` as empty.
4. **Store the loaded configurations as class member attributes.**

### `Dump()` Function

*(Automatically called on program exit)*

1. **Create the **`{root}/config` directory. If creation fails (except for "already exists"), throw an error and terminate the program immediately (to avoid recursive dump attempts).
2. **Write the internal **`result_map` back to the YAML files using `AMConfigProcessor::DumpToFile`.

### `Format()` Function

 **Purpose** **: Custom string formatting based on styles defined in settings.**

std::string format(const std::string& ori_str, const std::string& style_name);

* `style_name` corresponds to an entry under the `style` section in `settings.yaml`.
* **First, look up the style key in **`result_map`. If the key is missing, return `ori_str` unchanged.
* **If the key exists, parse its value (e.g., **`"[#033415 bold]"`), which specifies:
  * **A hexadecimal color code (**`#033415`)
  * **Optional text attributes (**`bold`)
* **Convert this into an ANSI escape sequence. If the format is invalid, return the original string.**
* **If parsing succeeds and yields a non-empty ANSI code, return the formatted string (with ANSI codes wrapped around **`ori_str`). Otherwise, return an empty string.

### `List()` Function

 **Purpose** **: Print all host entries in a formatted layout:**

[nickname]
username :   xx
port            :   xx
...

* **Left-align all field names (e.g., **`username`, `port`).
* **Apply the corresponding **`style` (from `settings.yaml`) to each value via the `Format()` function.

### `Src()` Function

 **Purpose** **: Print the absolute paths of the config and settings files:**

[Config]  = /absolute/path/to/config.yaml
[Setting] = /absolute/path/to/settings.yaml

* **Left-align the labels (**`[Config]`, `[Setting]`).
* **Style the right-hand path values using **`Format()`.

### `Delete()` Function

 **Purpose** **: Delete a specified host by nickname and print the operation result (success or failure).**

### `Query()` Function

 **Purpose** **: Retrieve and display host information for a given nickname.**

* **If the host exists, print it in the same format as **`List()`.
* **If not, print an error message.**

### `Add()` Function

 **Purpose** **: Interactively create a new host entry using the **`replxx` library (use `context7` for input prompts).

* **Pressing **`Ctrl+C` cancels the operation and prints a cancellation message.

**Required fields** (with validation):

1. **Nickname** **: Only alphanumeric characters and underscores allowed. Must not duplicate an existing nickname.**
2. **Username** **: Any non-empty string.**
3. **Hostname** **: Any non-empty string.**
4. **Port** **: Optional; must be a positive integer if provided. Default is **`22` (show a hint when using default).
5. **Keyfile** **: Optional (can be empty).**
6. **Password** **: Optional (can be empty string).**
7. **Trash_dir** **: Optional (can be empty string).**
8. **Protocol** **: Must be either **`sftp` or `ftp` (case-insensitive input; store in lowercase).
9. **Buffer_size** **: Must be a positive integer.**

**After collecting all fields, prompt the user for final confirmation before saving.**

### `Modify()` Function

 **Purpose** **: Modify an existing host (similar to **`Add`).

* **Takes a **`nickname` as argument. If it doesn’t exist, print an error and exit.
* **During interactive input, pre-fill each field with its current value as a placeholder.**
* **After editing, prompt for confirmation before applying changes.**
