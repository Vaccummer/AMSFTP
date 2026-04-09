# Interactive SSH Terminal Duty

Goal: implement a real interactive SSH terminal over `libssh2` that can carry raw terminal byte streams and support full-screen apps, password prompts, and resize handling.

## Workflows

### W1. Capability Contract
- Scope: define the terminal capability surface in domain/application DTOs and `IClientIOPort`.
- Deliverables: terminal request/response types, open/read/write/resize/close APIs, error mapping rules, unsupported-protocol behavior.
- Dependencies: none.
- Handoff contract: downstream workflows consume stable DTO names and error codes; do not rename once published.
- Risk points: breaking existing `ConductCmd` semantics, mixing UI concerns into application layer.
- Done criteria: contract compiles conceptually across SFTP/local/FTP/HTTP without protocol-specific leaks.

### W2. SSH Channel Core
- Scope: implement the libssh2 PTY + shell lifecycle for SFTP clients.
- Deliverables: channel open, PTY request, shell start, non-blocking read/write loop, EOF/exit-status handling.
- Dependencies: W1.
- Handoff contract: expose a protocol-agnostic terminal backend that satisfies the contract from W1.
- Risk points: `LIBSSH2_ERROR_EAGAIN` loops, double-close, channel/session lifetime bugs.
- Done criteria: backend can create a live shell session and exchange bytes reliably.

### W3. Session and Concurrency Policy
- Scope: define how terminal mode coexists with file transfer operations and reconnect logic.
- Deliverables: exclusivity rules, lock strategy, terminal-active state, cancel/interrupt policy.
- Dependencies: W1, W2.
- Handoff contract: all other workflows must follow the chosen concurrency policy and not bypass locks.
- Risk points: shared-session races, deadlocks, blocking `Connect`/`Check` paths, stale terminal state after reconnect.
- Done criteria: policy is explicit and testable, with no ambiguous ownership of session/socket state.

### W4. Interface Terminal Loop
- Scope: build the raw local TTY bridge that feeds stdin to SSH and renders SSH output to stdout.
- Deliverables: raw-mode guard, key handling, local echo policy, `Ctrl+C` forwarding vs local abort, cursor restore.
- Dependencies: W1, W2, W3.
- Handoff contract: consumes backend read/write/resizes and emits user input as raw byte streams.
- Risk points: terminal not restored on crash, prompt renderer corruption, platform-specific console behavior.
- Done criteria: interactive sessions can run curses-like programs and return cleanly to the prompt.

### W5. Resize and Signal Handling
- Scope: propagate terminal size changes and handle interruptions correctly across platforms.
- Deliverables: window-size detection, resize event forwarding, SIGINT/SIGWINCH strategy, Windows console fallback.
- Dependencies: W2, W4.
- Handoff contract: resize events are delivered as a terminal-side signal, not as a generic command call.
- Risk points: missed resize events, signal handler side effects, platform divergence.
- Done criteria: resizing the local terminal updates remote PTY dimensions without breaking the session.

### W6. CLI Command Surface
- Scope: add a user-facing command for interactive terminal mode and wire it to the current client selection.
- Deliverables: CLI command, parsing, mode entry/exit, error messages, help text.
- Dependencies: W1, W4, W5.
- Handoff contract: CLI invokes the interface terminal loop only after the client is connected and supported.
- Risk points: conflating one-shot `cmd` with persistent terminal mode, prompt state not restored after exit.
- Done criteria: users can enter and leave interactive SSH mode predictably from the CLI.

### W7. Observability and Recovery
- Scope: add logs, traces, and recovery paths for terminal start/stop failures.
- Deliverables: trace points, state snapshots, error mapping, reconnect/cleanup behavior.
- Dependencies: W2, W3, W4, W6.
- Handoff contract: all failure paths return actionable error context and leave the client usable when possible.
- Risk points: noisy logs, hiding root cause, incomplete cleanup after partial init.
- Done criteria: terminal failures are diagnosable and do not poison later operations.

### W8. Verification Matrix
- Scope: define and execute focused tests and manual checks for the terminal path.
- Deliverables: unit coverage for state transitions, integration checklist, manual scenarios for `vim`, `htop`, password prompts, resize, Ctrl+C.
- Dependencies: all workflows.
- Handoff contract: test cases must map back to specific workflow behavior and regressions.
- Risk points: testing only happy path, missing platform coverage, lack of negative cases.
- Done criteria: each workflow has at least one validating test or manual scenario and a known failure report path.

## Cooperation Protocol

- Sync cadence: short daily coordination plus an integration checkpoint before any shared API or session-policy change lands.
- Conflict rules:
  - W1 owns signatures and DTO names.
  - W2 owns libssh2 shell mechanics.
  - W3 owns lock/state rules.
  - W4 owns local terminal I/O.
  - W5 owns resize/signal delivery.
  - W6 owns CLI entry points.
  - W7 owns logging/recovery.
  - W8 owns validation coverage.
- File ownership:
  - Subagents should edit only their assigned files unless an integration checkpoint explicitly expands scope.
  - Shared headers are edited only after W1 publishes stable contract text.
- Integration checkpoints:
  - Checkpoint 1: W1 + W3 agree on terminal API and concurrency policy.
  - Checkpoint 2: W2 + W4 verify byte-stream compatibility.
  - Checkpoint 3: W5 + W6 confirm resize and exit flow from the user’s point of view.
  - Checkpoint 4: W7 + W8 sign off on cleanup, traces, and regression cases.
- Handoff rule: each workflow ends with a short status note listing files touched, assumptions made, and what the next workflow may rely on.

## Execution Notes

- Keep `ConductCmd` as the non-interactive command path unless the new terminal API explicitly replaces it in a separate slice.
- Prefer vertical slices over a big rewrite.
- Do not merge prompt rendering, shell execution, and raw terminal transport into one layer.
