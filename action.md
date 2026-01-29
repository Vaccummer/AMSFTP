
## Improve AMFilesystem

- `AMFileSystem::check` should accept multiple clients as input.
- Add a new function `AMFileSystem::sftp`, corresponding to `ClientManager::Connect` but with the protocol fixed to SFTP. Upon successful connection, automatically switch to the newly created client.
- Add a new function `AMFileSystem::ftp`, with the same behavior as above but with the protocol fixed to FTP.
- `remove_client` should accept multiple target clients, but prompt for confirmation only once collectively.
- `AMFileSystem::stat` should accept multiple targets and print their status information one by one.
- `AMFileSystem::getsize` should accept multiple targets and print each target's size on a separate line.
- General-purpose functions related to `treeNode` creation and printing in `AMFileSystem::tree` should be moved to `CommonTools` for reuse.
- `mkdir` and `rm` should support multiple target paths for batch operations.
- Remove `AMFileSystem::NormalizeNickname`; replace all usages with `AMStr::lowercase()`.
- Remove `AMFileSystem::PromptYesNo`; use the confirmation prompt functionality provided by `PromptManager` instead.
- Replace `AMFileSystem::IsAbsolutePath` with `AMPathStr::IsAbs`.
