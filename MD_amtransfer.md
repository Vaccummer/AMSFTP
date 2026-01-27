## New UserTransferSet Class (for storing users' original transfer settings)

- `vector<pair<src, dst>>`
- `mkdir` flag
- `overwrite` flag
- `ignore_special_file` flag

## TaskInfo Improvements

Make `TaskInfo` thread-safe:

- Convert numeric and enum properties to `std::atomic`
- Include an internal mutex for non-atomic modifications

Add new properties to `TaskInfo`:

- `vector<UserTransferSet>` to store transfer configurations
- `bool quiet` (no locking required since it's immutable after construction)
- Result callback function with signature: `void(std::shared_ptr<TaskInfo>)`
- `thread_id` to specify execution affinity to a particular thread

## PS

+ Replace raw `char[]` in `StreamRingBuffer` with `std::array` for idiomatic C++ style

## PromptManager Improvements

Implement a thread-safe function to receive `TaskInfo` and print result information in a standardized format. Suppress output in quiet mode.

## AMWorkManager (WM) Improvements

- Use smart pointers (`std::shared_ptr<TaskInfo>`) consistently for all `TaskInfo`-related operations to reduce memory overhead
- Rename `transfer()` to `submit()` which accepts a `TaskInfo` object for submission
- Add a new overload with the original `transfer()` signature that returns `std::shared_ptr<TaskInfo>`
- Create `ProgressData` before `ExecuteTask()` and destroy it upon exit

### New Result Handling Mechanism

After task completion, check for a result callback function in `TaskInfo`:

- If present: invoke the callback directly (`void(std::shared_ptr<TaskInfo>)`)
- If absent: add the result to the worker's result cache

### Multi-threaded Task Scheduling Design

1. **Thread Model**: Each thread maintains its own task queue (`std::list<TaskId>`), with logical IDs numbered from 0 (ID 0 is the base/default thread)
2. **Task Registry**: Maintain a global `unordered_map<TaskId, TaskRecord>`
3. **TaskRecord Structure**:

   - `TaskInfo` pointer
   - `AssignType` (either `affinity` for thread-bound tasks or `public` for unbound/invalid ID tasks)
   - `AffinityID` (target thread ID)
   - `std::list<TaskId>::iterator it` pointing to the task's position in its queue
4. **Task Submission**:

   - Validate the requested thread ID during submission
   - Register the task in `taskRegistry` and enqueue it in the appropriate thread-local or public queue
5. **Task Execution**:

   - Threads first consume tasks from their affinity queue, then fall back to the public queue
   - Upon selecting a task ID:
     - Lock and update the task's state in `taskRegistry`
     - Retrieve task data and remove the ID from the pending queue
   - After execution, remove the task from `taskRegistry` and handle results via callback or cache
6. **Lifecycle Management**:

   - Update operations like `terminate()` to track currently executing tasks via a `vector<TaskId>`
   - Add function to retrieve all active thread IDs
   - Add function to dynamically adjust thread count (range: 1–64):
     - Increasing threads takes effect immediately
     - Decreasing threads requires waiting until target threads become idle (no pending affinity tasks and no active execution)
