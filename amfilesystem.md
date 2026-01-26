# AMFileSystem

`AMFileSystem` (amfsm) is one of the core modules of the entire project. It primarily wraps client operations further and serves as the interface for user interaction.

Therefore, these functions must include extensive validation and informative output operations.

---

### Input Format

1. **Path format**: `{client_name}@{path}`
   1. Some paths may inherently contain `@`. To disambiguate, check whether the extracted nickname exists in the client registry.
   2. Local paths can be written as `@{path}`—this is syntactic sugar.
   3. `local@{path}` also denotes a local path.
   4. A bare `{path}` (without `@`) refers to the current client’s path.
   5. Nickname matching is **case-insensitive**.

---

### Output Format

1. **Client status printing**:

   - ✅ `{client_name}@{work_dir}` (normal case)
   - ❌ `{client_name}@{work_dir}  {EC_name} : {EC_msg}` (error case)
2. **Size information**: Must be converted into human-readable units (KB, MB, GB, etc.).
3. **Path info (`stat`) template**:

```
[path]

type     : {pathtype_name}
owner    : am
mode     : rwxrwx---
size     : 12KB

create_time : 2025/01/26 15:46:32
modify_time : 2025/01/26 15:46:32
access_time : 2025/01/26 15:46:32
```

> **Note**: Left-align the keywords (`type`, `owner`, `mode`, `size`) in the first block. The timestamp lines form a separate aligned block below.

4. **`ls -l` style listing** (each field must be properly aligned):

```
drwxrwx---  am   0B   2025/01/26 15:46:32   item_name
```

---

### Functions (return `ECM`)

1. **`check`**: Accepts only a nickname; verifies client existence/status.
2. **`connect`**: Equivalent to adding a client.
3. **`change_client`**: Switches the current client; creates it if it doesn’t exist.
4. **`remove_client`**: Removes a client from the `ClientManager` (does **not** modify config). Requires user confirmation before deletion.
5. **`cd`**:
   1. Supports `cd {path}` (relative to current client).
   2. Also supports `cd {hostname}@{path}`.
   3. If the target client doesn’t exist, prompt the user whether to create it.
   4. Maintains a single history entry as a string `{nickname}@{path}` for `cd -`.
   5. After `cd -` is executed, clear the history until the next `cd` to a different location.
   6. `cd` with no argument does nothing. However, `cd {nickname}@` is equivalent to `change_client`.
6. **`print_clients`**: Lists all clients with real-time status (calls underlying method with `update=true`), formatted as defined above.
7. **`stat`**: Accepts `{nickname}@{path}`; outputs path info using the template above.
8. **`getsize`**: Accepts `{nickname}@{path}`; prints size in human-readable format (e.g., `"12KB"`).
9. **`find`**: Accepts `{nickname}@{path}`; prints one matching path per line, with styled formatting.
10. **`mkdir`**: Accepts `{nickname}@{path}`; supports recursive directory creation.
11. **`rm`**: Accepts `{nickname}@{path}`.
    - Does **not** provide a "permanent delete" option.
    - Use `saferm` for safe removal (e.g., move to trash or confirm).
    - Use `remove` for direct deletion (if explicitly provided).
