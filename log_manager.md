## log_manager

The core is a dedicated thread that continuously writes to a log file, enabling thread-safe logging.

- Maintain a queue to store `TraceInfo` entries.
- Read `project_root` from the `config_manager`, open the log file at `{project_root}/AMSFTP.log`, and continuously dequeue entries from the queue and write them to the log file.
  - Properly handle any exceptions that occur during this process and report them to the `prompt_manager` (without terminating the program).

Provide a public **trace callback function** that simply enqueues a `TraceInfo` entry into the queue—this function will be bound by `AMTracer`.

Provide a `trace_level` interface:

- Default value is `-99999`.
- If the input value is `-99999`, return the current trace level without modifying it.
- Otherwise, set the trace level to the given value, clamped within the valid range of **-1 to 4**.
- During initialization, read the initial trace level from the settings; if not specified, default to **4**.

This trace level is used to filter log entries during writing:

- Convert the `TraceLevel` enum value to an integer.
- Only write a log entry if its level is **less than or equal to** the configured trace level; otherwise, discard it.
