
Used to print task information. You can create a dedicated class `TaskInfoPrint`.

## TaskSubmitPrint

Used to report when submitting in `transfer_async`.

Format:

* `Submit ID: [{taskid}] FileNum: {num} TotalSize: {size} Clients: {nicknames}`
* Get `nicknames` via `client_maintainer.get_nicknames()`.

## TaskResultPrint

Used to print after a task finishes executing.

Do not print if `taskinfo.quiet` is set.

Format:

* `✅/❌ [{taskid}] {transferred_size}/{total_size} ThreadID: {} {rcm}`
* Choose ✅/❌ based on `rcm`.
  * If ✅, you don’t need to print `rcm` afterward.

## Show

A function for quick task status queries. It prints in different formats depending on the task state.

### 1. Show `pending_task`

`[{taskid}] Status: {} TotalSize: {} AffinityThread: {} SubmitTime: {}`

* Time format: `16:02`.

### 2. Show `finished_task`

`[{taskid}] Status: {} {transferred_size}/{total_size} ThreadID: {} ElapsedTime: {}`

* `ElapsedTime` format: `1m30s`.

### 3. Show `conducting_task`

Use a progress bar.

* Set `prefix` as: `{src_hostname}@{src_filename} -> {dst_hostname}@{dst_filename}`
* Continuously read `taskinfo` and refresh.
* Add an `interrupt_flag` in `show()` to terminate the progress bar.

## List

Used to print task information in batch.

### History / Pending

Call `show()` for each task.

### Conducting

Create multiple progress bars to output progress information.

## Inspect

Used to print detailed task information.

Include:
`id, status, submit_time, start_time, finished_time, rcm, total_transferred_size, total_size, files_num, quiet, affinity_thread, on_which_thread, buffer_size, client_names`

* Print one attribute per line.
* Attribute names can be slightly adjusted for readability.
* Align attribute names.

### `task` subcommand

Used to print all task entries inside `taskinfo`.

Format:

```
[order]

src: {nickname}@{path}

dst: {nickname}@{path}

size: {}

transferred: {}

rcm: (print only when IsFinished is true)
```

### `set` subcommand

Used to print the original command settings of the task (`UserTransferSet`).

Format:

```
[order]

- If there is only one UserTransferSet, omit the index.

{src1}
{src2}
{src3}
...

 ->  {dst}

clone =
mkdir =
overwrite =
no special =

[order]

...
```
