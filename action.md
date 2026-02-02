
@src\manager\Transfer.cpp

Encapsulate a function `CollectClients` that:

- Accepts a `vector<nicknames>`
- Returns `pair<ecm, maintainer_ptr>` to create a maintainer for required clients
- Logic should mirror the relevant operations in `PrepareTasks_`

Modify `PrepareTasks_` return type to `pair<ECM, TaskInfo_ptr>`, and add two parameters:

- `quiet`
- `interrupt_flag`
  Perform `TaskInfo` generation inside `PrepareTasks_` (while result callbacks remain in the two transfer types)

Change `ReturnClientsToIdle_` to directly accept `ClientMaintainer`, read `ClientMaintainer.hosts`, and return all non-local clients to the shared pool.

Add overloads for `transfer_async` and `transfer` that directly accept `TaskInfo`.

Fix the progress bar bug in `transfer`: since `transfer` submits only a single task, it doesn't need a progress bar group.

`TaskInfo` should hold a shared pointer to its maintainer.

Add a new attribute to `TaskInfo`: `vector<string> nicknames`.

In `AMTransferManager::ResultCallback`, after returning the maintainer's clients to the pool, set the maintainer pointer to `nullptr` to release it.

Remove maintainer-invoking query functions from `TransferManager`.

# Resume

Introduce a new `resume` feature for resubmitting/resuming already failed tasks.

`resume` accepts the following parameters:

- `string id` (positional): ID of an existing task whose location is known and status is *completed*. Non-completed tasks should trigger an error immediately.
- `bool is_async = false`
- `bool quiet = false`
- `vector<int> index`: variadic integer arguments representing indices of specific tasks within `TaskInfo::TASKS`

Implementation steps:

1. Validate whether the task ID is legal
2. Filter out invalid indices (out-of-bounds/negative values) with user warnings about filtered indices
3. Reconstruct `TASKS` based on transmission status—tasks already marked `IsSuccess` should not be retransmitted
4. Analyze required clients and invoke `CollectClients` to create a maintainer; abort with error on failure
5. Call `workermanager::cre_taskinfo` to create `TaskInfo`
6. Invoke the appropriate transfer function based on `is_async`
