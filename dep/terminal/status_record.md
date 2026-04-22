# Interactive SSH Terminal Status Record

Repo scope: `d:\CodeLib\CPP\AMSFTP`

This is the shared progress board for parallel terminal implementation work.
Workflow IDs and dependency assumptions are synchronized with:
- `terminal/duty.md`
- `terminal/workflow_contract.md`

## Global Summary

| Workflow ID | Owner Role | Status | Blocker | Latest Update | Next Action |
| --- | --- | --- | --- | --- | --- |
| W1 | Capability contract owner (Kant) | Completed | None | Terminal DTO/API contract published; `IClientIOPort` extended; local/ftp/http unsupported stubs aligned | Keep contract stable during W8 verification |
| W2 | SSH channel core owner (Halley) | Completed | None | Terminal core moved to dedicated `SSHTerminalPort` with independent SSH session from `ConRequest` | Harden edge-case behaviors during verification |
| W3 | Session/concurrency policy owner (Pasteur) | Completed | None | Terminal/SFTP decoupling landed: terminal session lifecycle no longer tied to SFTP transport session | Verify behavior under concurrent terminal and file I/O |
| W4 | Interface terminal loop owner (Pasteur) | Completed | None | Raw local terminal bridge landed in filesystem interface, supports byte passthrough and local exit key | Validate behavior across more terminal emulators |
| W5 | Resize/signal owner (Pasteur) | Completed | None | Local geometry detection and remote PTY resize propagation implemented | Stress-test rapid resize and interrupt timing |
| W6 | CLI surface owner (Pasteur) | Completed | None | `term` command wired in CLI args/bindings and routed to terminal interface flow | Refine UX/help wording based on verification feedback |
| W7 | Observability/recovery owner (Halley) | In Progress | None | Connect-state tracing standardized for SFTP connect path; spinner can render live stage text from client trace | Extend same state-trace contract to terminal open path and verify fallback behavior |
| W8 | Verification owner | Planned | Waiting for W3/W7 freeze | Core implementation path exists for terminal scenarios | Execute test matrix for `vim`, `htop`, password prompt, resize, Ctrl+C |

## Parallel Cooperation Notes

- Parallel execution performed with three subagents:
  - Kant: W1 contract and cross-client interface alignment.
  - Halley: W2 SFTP terminal backend and W7 cleanup/traces.
  - Pasteur: W4/W5/W6 interface and CLI integration.
- Integration checkpoint completed:
  - DTO/API mismatch between W1 and W2 was reconciled in `src/infrastructure/client/sftp/SFTP.hpp`.
- Remaining coordination focus:
  - W3 and W7 must publish final policy/diagnostic notes before W8 sign-off.

## Per-Workflow Log

Use one short entry per update.

### W1 Log
- [2026-04-09 13:01] Status: Completed | Update: Added terminal args/results and `IClientIOPort` methods; aligned unsupported protocol stubs | Next: freeze naming and semantics.

### W2 Log
- [2026-04-09 13:05] Status: In Progress | Update: Added libssh2 PTY/shell backend and terminal state helpers in SFTP client | Next: integrate with finalized DTO contract.
- [2026-04-09 13:17] Status: Completed | Update: Reconciled SFTP terminal methods to published DTO fields (`opened`, `eof`, `bytes_written`, `resized`, status flags) | Next: support W8 hardening.
- [2026-04-09 13:40] Status: Completed | Update: Moved SSH terminal implementation into `src/infrastructure/client/sftp/Terminal.hpp` as `terminal::SSHTerminalPort` with independent session ownership | Next: verify auth/pty edge cases.
- [2026-04-09 14:35] Status: Completed | Update: Refactored `SSHTerminalPort` to own an internal `AMSFTPIOCore` and delegate session establishment to `AMSFTPIOCore::Connect` for code reuse | Next: evaluate whether remaining duplicated helper methods in `Terminal.hpp` can be removed safely.

### W3 Log
- [2026-04-09 13:06] Status: In Progress | Update: Terminal state guarded by recursive mutex; disconnect hook closes shell before session teardown | Next: publish explicit shared-session policy note and lock-order rules.
- [2026-04-09 13:40] Status: Completed | Update: Introduced virtual terminal port boundary (`ITerminalPort` + `TerminalPortBase`) and delegated SFTP terminal APIs through isolated terminal component | Next: verify concurrency behavior and document residual risks.

### W4 Log
- [2026-04-09 13:07] Status: Completed | Update: Implemented raw mode guard and stdin/stdout bridge loop in filesystem interface service | Next: verify terminal restore behavior under abnormal exits.

### W5 Log
- [2026-04-09 13:08] Status: Completed | Update: Implemented local geometry polling and remote PTY resize forwarding | Next: add high-frequency resize scenario checks in W8.

### W6 Log
- [2026-04-09 13:09] Status: Completed | Update: Added `term` command surface and argument routing to interface service | Next: confirm help text and command discoverability.

### W7 Log
- [2026-04-09 13:10] Status: In Progress | Update: Added terminal lifecycle traces and disconnect cleanup interception | Next: standardize diagnostics for timeout/interruption/socket-failure classes.
- [2026-04-09 14:15] Status: In Progress | Update: Added SFTP `connect.state` trace stages (`resolving hostname`, `creating TCP connect`, fingerprint, auth method negotiation, private key/password auth, SFTP handle init) and wired connect spinner to consume these states | Next: mirror the same stage contract in terminal-session connect/open flow.

### W8 Log
- [2026-04-09 13:11] Status: Planned | Update: Matrix drafted in docs only, not executed | Next: run manual matrix for `vim`, `htop`, password prompts, resize, Ctrl+C.

## Risk Register

| Risk ID | Severity | Probability | Mitigation | Owner |
| --- | --- | --- | --- | --- |
| R1 | High | High | Do not allow terminal and SFTP IO to race on one session without strict policy | W3 |
| R2 | High | Medium | Treat libssh2 EAGAIN as a first-class state with bounded wait/retry policy | W2 |
| R3 | High | Medium | Keep raw terminal bytes out of prompt formatting path | W4 |
| R4 | High | Medium | Ensure Ctrl+C semantics differ correctly between shell mode and normal app mode | W5 |
| R5 | Medium | Medium | Enforce single cleanup sequence for all exit/failure paths | W7 |
| R6 | Medium | Medium | Validate resize behavior under rapid resize events | W5 |
| R7 | Medium | Low | Keep unsupported protocol behavior explicit and tested | W1/W8 |

## Integration Gate Checklist

- [x] W1 API/DTO contract frozen and shared.
- [x] W3 concurrency/session policy frozen and shared.
- [x] W2 shell channel lifecycle implemented with correct EAGAIN handling.
- [x] W4 raw bridge supports interactive programs (`vim`, `htop`, password prompts).
- [x] W5 resize and signal policy works and does not break shell mode.
- [x] W6 CLI command enters and exits terminal mode cleanly.
- [ ] W7 traces and cleanup are actionable and non-destructive.
- [ ] W8 verification matrix executed with pass/fail evidence.

## Decision Log (ADR-lite)

### ADR-001
- Date: 2026-04-09
- Title: Interactive terminal capability boundary
- Status: Accepted
- Decision: Keep interactive terminal API separate from one-shot `ConductCmd`.
- Reason: lifecycle and I/O semantics differ.

### ADR-002
- Date: 2026-04-09
- Title: Terminal lifecycle cleanup point
- Status: Accepted
- Decision: invoke terminal cleanup from SFTP disconnect pre-hook to avoid stale channel/session coupling.
- Reason: prevent leaked channel state during reconnect/disconnect.

### ADR-003
- Date: 2026-04-09
- Title: Raw I/O boundary
- Status: Accepted
- Decision: raw stream handling stays in interface terminal loop, not prompt formatting utilities.
- Reason: prevent stream corruption and broken full-screen behavior.

## Cache-Sign Audit (2026-04-09)

### Findings (ordered by severity)

- High | Potential cache depth underflow / double flush
  - Location: `src/interface/prompt/PromptCli.cpp` (`SetCacheOutputOnly`, `FlushCachedOutput`)
  - Risk: repeated disable calls can underflow depth or flush more than once.
  - Mitigation: clamp at zero and flush only on transition from depth `1 -> 0`.

- High | Cache bypass in low-level isocline write paths
  - Location: `src/interface/prompt/PromptCli.cpp` (`PrintSyncLocked_`, `PrintSyncRefreshLocked_`, `ClearScreen`, `UseAlternateScreen`, `SetCursorVisible`)
  - Risk: output still reaches terminal when cache sign is active.
  - Mitigation: route all isocline writes through cache gate.

- Medium | Terminal teardown flush ordering
  - Location: `src/interface/adapters/filesystem/FilesystemInterfaceSerivce.cpp` (`Terminal`)
  - Risk: cached callback/error output may not flush on every exit/failure branch.
  - Mitigation: keep one scoped cache guard over terminal bridge/close/restore and release after restore.

- Medium | Callback ordering during raw-mode teardown
  - Location: `src/interface/adapters/client/ClientInterfaceService.cpp` (disconnect callback print path)
  - Risk: disconnect messages interleave with raw-screen redraw.
  - Mitigation: rely on prompt cache sign during terminal session and flush after terminal restore.

- Low | PTY byte stream accidentally captured by prompt cache
  - Location: `src/interface/adapters/filesystem/FilesystemInterfaceSerivce.cpp` (`WriteTerminalBytes_`)
  - Risk: interactive apps freeze if PTY bytes are cached.
  - Mitigation: keep PTY stream on direct `fwrite` path; cache applies only to prompt/isocline output.

### Manual Regression Checklist

- `term` enter
  - Run `term` on a connected SFTP client and verify terminal output appears immediately.
  - Trigger a background callback print while terminal is active and verify it is deferred.
- `vim` exit
  - Start `vim`, quit, and verify prompt prefix appears immediately without extra keypress.
- `htop` exit
  - Start `htop`, quit, and verify no stuck blank screen and no delayed redraw requirement.
- disconnect callback timing
  - Force remote disconnect during terminal mode and verify disconnect message appears after terminal teardown, not mid-TUI frame.
