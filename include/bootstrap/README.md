# bootstrap

Composition root interfaces and wiring entry points for app and session
lifetime dependencies.

- `AppHandle.hpp`: process-lifetime wiring and runtime adapter binding.
- `SessionHandle.hpp`: per-run mutable session context and task-control token.
- `WF6_STATUS.md`, `WF7_STATUS.md`: workflow completion trackers.
