## AMTracer

Replace `std::vector<TraceInfo>` with `std::list<TraceInfo>`.

## TaskInfo

- Introduce a new field `OnWhichThread`:
  - Set to the executing thread's ID during task execution
  - Set to `-1` in all other states (pending, completed, etc.)
- Eliminate `TaskRecord`; migrate its remaining properties into `TaskInfo`
- Rename `affinity_id` to `affinity_thread` and replace `thread_id` with this field
- Convert memory-intensive members (e.g., `TASKS` and other large variables) to `std::shared_ptr` to reduce memory footprint

## ClientMaintainer

- Support initialization via `std::unordered_map<std::string, std::shared_ptr<BaseClient>>`
- Allow `heartbeat_interval_s` to accept negative values, indicating heartbeat is disabled

## ClientManager

- Remove `trace_num` as a function parameter; instead:
  - Read from settings as a class member attribute
  - Default value: `10`
  - Minimum allowed value: `5`
- Introduce a basic `CreClient()` function:
  - **Parameters**: `nickname`, `interrupt_flag`
  - **Returns**: `std::pair<ECM, std::shared_ptr<BaseClient>>`
  - Binds Python tracer to the client's logger
  - Binds authentication callback to `ClientManager`'s global `authcb`

## PromptManager (PM)

1. **`resultprint()`**:

   - Accepts `std::shared_ptr<TaskInfo>`
   - Prints task execution results (placeholder implementation; format TBD for future refinement)
2. **`taskprint()`**:

   - Accepts `std::shared_ptr<TaskInfo>`
   - Prints submitted task metadata (placeholder implementation; format TBD for future refinement)
