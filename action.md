## AMWorkManager

- Change `conducting_tasks_` to `std::unordered_set<TaskId>`
- Rename `get_conducting_id` to `get_conducting_ids`, returning a **copy** of `conducting_tasks_`
- Implement new `get_thread_ids()` method

## AMTransferManager (TM)

`TransferManager` handles file transfers and serves as a user-facing wrapper around `AMWorkManager`.

### New Member

- Add `std::unordered_map<ID, std::list<std::shared_ptr<BaseClient>>> idle_pool_` as an idle client pool

### Result Callback Flow

- Results must pass through TM's wrapper layer:
  1. Execute TM's default callback first
  2. Then invoke user-defined custom callback
- Store execution results in TM's history log (use `std::list`, prepend new entries to front)

### Overall Workflow

1. **User submits one or more `UserTransferSet` objects to TM**

   - Each `UserTransferSet` represents a single user command
   - Multiple commands may be accumulated and submitted together for batch processing
2. **Client preparation**

   - Analyze required clients from paths (format: `{nickname}@{path}`)
   - Fetch clients from `idle_pool_` first; create new ones if needed
   - If any client fails validation:
     - Return all successfully validated clients to `idle_pool_`
     - Abort the operation
   - If all clients are ready: create a `HostMaintainer` via `std::map`
3. **Path preprocessing**

   - Source paths may contain wildcards requiring pattern matching via `find()` function
   - In non-quiet mode:
     - Print matched results when wildcards are used
     - Prompt user for confirmation before proceeding
4. **Task generation via `worker.load_tasks()`**

   - Generates `std::vector<TASK>` where `TASK` is the minimal execution unit
   - On error: report via `PromptManager::error_format()` (non-fatal)
5. **Task submission to WM**

   - Submit each `TASK` to WM to generate individual `TaskInfo` objects
   - **Do not merge into a single batch submission** – TM must retain ownership of `TaskInfo` objects to avoid later result lookup from WM's result cache
6. **Post-execution**

   - Return all clients to `idle_pool_` after task completion

### Core Blocking `transfer()` Function

**Parameters:**

- `std::vector<UserTransferSet>`
- `bool quiet`
- `std::atomic<bool>* interrupt_flag = nullptr`

**Return:** `ECM` (Error Code Message)

**Key Behaviors:**

1. Propagate `interrupt_flag` to all network I/O operations and blocking calls for user-triggered termination
   - Termination messages should vary based on execution phase
2. After task submission:
   - Create progress bar (using the newly implemented `ProgressBar`)
   - Poll `TaskInfo` periodically to update progress
   - Check `interrupt_flag` during each refresh cycle
     - If triggered: call `WM::terminate()` to cancel tasks
   - `refresh_interval_ms`:
     - Read from settings
     - Default: 200 ms
     - Minimum: 10 ms
3. Block via condition variable awaiting execution completion
4. Set result callback in `TaskInfo` that:
   - Notifies the condition variable upon completion
   - Triggers `PromptManager`'s result printing

### Non-Blocking `transfer_async()` Function

**Parameters:** Same as blocking version
**Return:** `ECM` (success returned immediately upon task submission)

**Behavior:**

- Submits tasks and returns immediately without waiting for completion
- Execution proceeds in background threads
- Results handled via callback mechanism
