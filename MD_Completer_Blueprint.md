
## Completor Blueprint

### 1) High-Level Architecture

- **Completion Pipeline**: Input → Parse input before cursor → Build query → Fetch candidates (synchronous/asynchronous) → Sort/format → Render → Apply selection
- **Core Types**:
  - `CompletionContext` (cursor position, current token, full line, parsing state, mode)
  - `CompletionCandidate` (display text, insert text, kind, help message, score, metadata)
  - `CompletionResult` (candidate list + match strategy + latency info)
- **Completion Sources** (individually enable/disable):
  - `CommandSource` (commands/subcommands/options)
  - `InternalSource` (task IDs, client names, host config nicknames, variable names, and certain built-in attribute names)
  - `PathSource` (local/remote paths)
- **Coordinator**:
  - A `Completer` that dispatches requests to individual sources based on context and merges results
  - **Unified Flow**: Even for fast command completions, the same `CompletionRequest` pipeline is used to ensure consistent UI behavior, simplify the system, and improve extensibility

### 2) Context Parsing

- Input parser already exists: `@src\cli\TokenTypeAnalyzer.cpp`
- Supports tokenization with quotes, escape characters, and `nickname@path` syntax
- **Target Type Determination** (priority from highest to lowest; stops after first match):

  - Starts with `!` → Disable completion (invokes remote terminal)
  - No valid command yet → Complete module names or top-level function names
  - Valid module name present → Complete function names under that module
  - Valid function name present:
    - Starts with unescaped `$` → Variable name completion
    - Starts with `--` → Complete by full option name
    - Starts with `-` → Complete by short option name
    - Complete function-specific parameters:
      - e.g., `config set`: first parameter is nickname, second is config attribute name
      - e.g., `task inspect`: complete with task IDs
    - Path-like pattern detected (e.g., starts with `/`, `~/`, `c:/`, `nickname@c`):
      1. Path ends with `/` or `\` → List all children under that path as candidates
      2. Otherwise → Traverse parent directory and match items by prefix
  - None of the above rules matched → No completion triggered
  - Stops evaluation after the first matching rule

### 3) Candidate Model

- **Kinds**: Module, Command, Option, VariableName, ClientName, HostConfigNickname, HostConfigAttrName, TaskId, PathLocal, PathRemote
- **Fields**:
  - `insert_text`: actual text to insert
  - `display`: styled text shown in menu
  - `help`: brief usage hint (especially important for commands)
- **Sorting Strategy**:
  - Prefix matches ranked highest
  - For path matches, order by:
    1. Regular files first
    2. Directories next
    3. Symbolic links after
    4. Other special file types last

### 4) Asynchronous Model

- Each keystroke generates a unique request ID; input changes invalidate previous IDs and cancel outdated completion tasks. Results are validated against the current request ID before application, automatically discarding stale async results.
- Remote path completion includes a configurable debounce delay; requests can be canceled cost-free within this window to reduce network I/O pressure.
- **Completion Cache**:
  - Primarily caches path completions, storing `dir`, `nickname`, `vector<PathInfo>`, and other relevant attributes (extensible as needed)
  - Other completions reside in memory and do not require persistent caching
  - Cache should support manual clearing via command (since paths may change) and enforce a size limit
  - Caching only triggered when a directory contains more children than a user-defined threshold; smaller directories are not cached

### 5) Command Completion Data

- Define a static command tree: command → subcommand → options → positional parameter types
- Each node includes usage/help strings
- Completion source recommends only relevant subcommands/options based on the current parsing node to avoid irrelevant suggestions

### 6) Internal Value Sources

- Task IDs: from `AMWorkManager` (running/executing/history)
- Client names: from `ClientMaintainer`
- Host config nicknames: from `ConfigManager` (available even when not connected)
