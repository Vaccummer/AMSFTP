# Isocline Structure in AMSFTP

Updated: 2026-03-25

## 1. Build and Source Composition

- `amsftp` builds Isocline from a single compilation unit:
  - `src/third_party/Isocline/isocline.c`
- That file includes all internal C modules directly when `IC_SEPARATE_OBJS` is not set:
  - `attr.c`, `bbcode.c`, `editline.c`, `highlight.c`, `undo.c`, `history.c`, `completers.c`, `completions.c`, `term.c`, `tty_esc.c`, `tty.c`, `stringbuf.c`, `common.c`.
- Include roots expose Isocline headers via:
  - `src/third_party/Isocline/isocline.h`

## 2. Isocline Runtime Model (Fork)

### 2.1 Profile-centric environment

- Isocline runtime state is profile-based:
  - `ic_profile_t` owns one `ic_env_t`.
- Global runtime pointers in `isocline.c`:
  - profile list (`ic_profiles`)
  - current profile (`ic_current_profile`)
  - default profile (`ic_default_profile`)

### 2.2 `ic_env_t` major subsystems

Defined in `src/third_party/Isocline/env.h`:

- terminal output: `term_t* term`
- tty/input: `tty_t* tty`
- completion state: `completions_t* completions`
- history state: `history_t* history`
- bbcode/style engine: `bbcode_t* bbcode`
- active editline state flags:
  - `edit_active`
  - `refresh_request`
- async message queue state:
  - `async_lock`
  - `async_print_head`
  - `async_print_tail`

## 3. AMSFTP Prompt Integration (Current Active Path)

Active files (non-`dep`):

- `src/interface/prompt/Prompt.hpp`
- `src/interface/prompt/PromptProfile.cpp`
- `src/interface/prompt/PromptCli.cpp`
- `src/interface/prompt/PromptApi.cpp`

### 3.1 Two-manager split

1. `IsoclineProfileManager`
- owns prompt profile switch + history sync logic.
- keeps:
  - `PromptProfileManager&`
  - `PromptHistoryManager&`
  - `AMStyleConfigManager&`
  - runtime state (`profile`, `current_nickname`, loaded flag)
  - profile cache (`std::map<std::string, ic_profile_t*>`)

2. `AMPromptIOManager`
- owns print/prompt APIs:
  - `Print`, `PrintRaw`, `FmtPrint`, `ErrorFormat`
  - `Prompt`, `LiteralPrompt`, `PromptCore`, `SecurePrompt`, `PromptYesNo`
  - cache-output controls (`SetCacheOutputOnly`, `FlushCachedOutput`)

## 4. Startup and Runtime Wiring

### 4.1 Construction

In `main.cpp`:

- construct app-level managers:
  - `PromptProfileManager`
  - `PromptHistoryManager`
  - `AMStyleConfigManager`
- construct interface managers:
  - `IsoclineProfileManager`
  - `AMPromptIOManager`

### 4.2 Bootstrap binding

In `src/bootstrap/runtime/AppHandle.cpp` and `RuntimeBindings.cpp`:

- runtime binding stores pointers to:
  - `prompt_profile_history_manager`
  - `prompt_io_manager`
- `CliManagers::Init()` calls:
  1. `prompt_profile_history_manager.Init()`
  2. `prompt_io_manager.Init()`

### 4.3 Interactive loop usage

In `src/interface/cli/InteractiveLoop.cpp`:

Per loop iteration:

1. reload settings if changed
2. `ChangeClient(current_nickname)`
3. build prompt text
4. read input with `PromptCore(...)`
5. on submit: `AddHistoryEntry(line)`
6. on exit: `FlushHistory()`

## 5. Style Flow

### 5.1 Config source

`config/settings.toml` style sections consumed by Isocline path include:

- `[Style.CLIPrompt]`
- `[Style.ValueQueryHighlight]`
- `[Style.InternalStyle]`

### 5.2 Mapping path

1. config snapshot decode (`AMStyleSnapshot`)
2. conversion in `ConfigAssembly.cpp` to `StyleConfigArg`
3. read by `IsoclineProfileManager::ChangeClient(...)`

### 5.3 Isocline style definitions

`ChangeClient(...)` applies style defs with `ic_style_def` (for created profile) using keys:

- `kvars::default_prompt_key` -> `"ic-prompt"`
- `kvars::valid_value_key` -> `"typein_valid_value"`
- `kvars::invalid_value_key` -> `"typein_invalid_value"`
- `kvars::inline_hint_key` -> `"ic-hint"`

`AMPromptIOManager::Prompt(...)` uses those tag names directly for checker highlight output.

## 6. Async Insert-Print Mechanism (Fork)

### 6.1 Public API level

- `ic_print_async(const char*)`
- `ic_request_refresh_async()`
- `ic_is_editline_active()`

### 6.2 Queueing model

In `isocline.c`:

- `ic_print_async` during active editline:
  1. push message into async queue (`ic_env_async_print_push`)
  2. set `refresh_request = true`
  3. wake edit loop via `tty_async_complete(...)`

### 6.3 Drain/redraw behavior

In `editline.c` (`edit_process_refresh_request`):

1. consume refresh request
2. if messages pending:
   - clear hint/extra/completion state
   - clear current edit display
   - drain all queued async messages
   - print drained messages
   - redraw prompt/input

This preserves typed buffer content and repaints input after inserted logs.

### 6.4 Completion-menu interaction

In `editline_completion.c`:

- if completion menu loop receives refresh event (`KEY_EVENT_COMPLETE` + `refresh_request`), it processes async refresh and exits menu flow.
- practical effect: menu closes, message appears, typed text is preserved.

## 7. History Flow

### 7.1 Switch-time behavior

`IsoclineProfileManager::ChangeClient(...)`:

1. `FlushHistory()` current profile into `PromptHistoryManager`
2. switch/create `ic_profile_t`
3. clear Isocline history buffer
4. load new nickname history entries from `PromptHistoryManager`

### 7.2 Input-time behavior

- interactive loop calls `AddHistoryEntry(line)` after successful input.
- manager writes into Isocline runtime history; persisted map is synchronized on flush/exit.

## 8. Completion Flow

- `AMCompleter` installs Isocline completer callback (`ic_set_default_completer`).
- completion UI behavior is rendered by Isocline completion engine (`editline_completion.c`).
- `Prompt(...)` may override completer/highlighter temporarily via:
  - `ic_readline_ex_with_initial(...)`
- `PromptCore(...)` uses token highlighter callback directly via `ic_readline_ex(...)`.

## 9. Signal/Interrupt Hooks (Current State)

In `AMPromptIOManager::InitIsoclineConfig()`:

- registers hooks named `PROMPT` and `COREPROMPT`.
- current callbacks are placeholders (`ic_async_stop()` is commented out).
- implication: signal hook plumbing exists, but stop/unblock integration is not fully enabled in this path.

## 10. Secure Prompt and Progress Output Status

### 10.1 `SecurePrompt`

Current implementation in `PromptCli.cpp` is manual console I/O (`std::cout`, `_getch`/`getchar`), not Isocline editline.

- consequence: secure prompt is not fully unified with Isocline async insert/redraw model.

### 10.2 Progress-like refresh output

Project still has progress rendering paths based on `indicators` (`src/foundation/tools/bar.hpp`) and direct terminal control.

- consequence: progress refresh is not fully unified into Isocline async queue/render pipeline yet.

## 11. Thread-Safety Boundary (Current Effective Rule)

- Isocline core protects async message queue with a spin lock (`async_lock`) in the env.
- External project code should treat Isocline edits as single-owner UI-thread operations.
- Cross-thread message insertion should go through `ic_print_async` (or future queue APIs), not direct editline state mutation.

## 12. Deprecated Prompt Path

- `src/interface/prompt/dep/*` exists but is deprecated/legacy.
- Current architecture above describes the active non-`dep` prompt path.

## 13. Existing Isocline-focused Tests/Demos

- `test/isocline_nerd_icon_print_demo.cpp`
  - validates Nerd icon rendering via `ic_print`.
- `test/isocline_async_prompt_insert_demo.cpp`
  - demonstrates async insert while prompt is active.

## 14. Practical Summary

Current project state already has:

- profile-based Isocline environments
- async insert-print queue with redraw during prompt
- prompt/highlight/completion integration through Isocline

Not yet fully unified to Isocline:

- secure prompt path
- progress refresh path

Those two are the main remaining integration points for a complete "Isocline-only" terminal interaction stack.
