 Below is a blueprint for implementing the completer described in MD_Completer.md, plus improvement suggestions based on your
  design goals (human-friendly, rich menu, async for remote). I’ll keep it practical and aligned with your existing architecture
  (Prompt/Replxx, Client/Config/Transfer managers, async transfer I/O).

  Blueprint

1) High-level architecture

- Completer pipeline: Input -> ParseContext -> BuildQuery -> FetchCandidates (sync/async) -> Rank/Format -> Render ->
  ApplySelection.
- Core types:
  - CompletionContext (cursor pos, current token, full line, parse state, mode)
  - CompletionCandidate (display, insert_text, kind, help, score, metadata)
  - CompletionResult (vector candidates + match strategy + latency info)
- Completion sources (pluggable):
  - CommandSource (commands/subcommands/options)
  - InternalSource (task IDs, client names, host config nicknames)
  - PathSource (local/remote paths)
- Coordinator:
  - A Completer that dispatches to sources based on context and merges results.

2) Context parsing

- Tokenize with awareness of quotes, escapes, and nickname@path.
- Determine target type:
  - Starts with / or known command prefix => command completion
  - Starts with - => option completion
  - Contains @ => nickname + path (split into nickname/path)
  - Otherwise treat as path unless command grammar says internal IDs
- Identify command scope: command -> subcommand -> option for smarter completions.

3) Candidate model

- kind: Command, Option, ClientName, HostConfig, TaskId, PathLocal, PathRemote.
- insert_text: actual insert; display: shown in menu; help: brief usage (especially for commands).
- score: base + prefix match + fuzzy match + recency + usage frequency.

4) Async model

- Use a request token or incremental query_id so outdated async results are dropped.
- Maintain CompletionCache keyed by (source_type, key, cwd, client, prefix).
- For remote path, send async query to the client; if pending, return stale cache or show “loading” placeholder.

5) UI behaviors

- Tab:
  - single match => insert
  - multiple => if double‑tab, show list; if in menu mode, keep menu
- Menu:
  - Vertical list, highlight selection, show full entry string
  - For commands: show usage in a side line or inline help
  - For paths: format (dir/file, maybe style)
- Non‑terminal mode: attach menu below input, allow up/down selection.

6) Command completion data

- Define a static command tree:
  - command -> subcommands -> options -> positional kinds
- Each node includes usage/help string.
- Source uses current node to suggest relevant subcommands/options only.

7) Path completion details

- For nickname@path:
  - complete nickname before @, then remote path
  - If nickname not resolved yet, offer nicknames first
- For local path:
  - ./.. expansion, ~ home support
  - add trailing / for directories
- Format path output (icons or color tags if your prompt supports styling).

8) Internal values

- Task IDs from AMWorkManager (pending/ conducting/ history).
- Client names from ClientMaintainer.
- Host config nicknames from ConfigManager (even if not connected).

9) Ranking

- Prefix matches first, then fuzzy.
- Then by:
  - command usage frequency
  - recency (last used)
  - “current context” relevance (e.g., current command expects a task id).

10) Caching

- LRU caches for path results.
- Separate TTL for remote (short) and local (medium).
- Async: update cache and signal UI to re-render.

  ———

  Suggestions to improve your design

1. Unified completion flow
   - Even if command completion is fast, use the same CompletionRequest pipeline so UI behavior is consistent. This keeps the
     system simpler and extensible.
2. Typed parser for correctness
   - Basic command grammar makes option completion much smarter (e.g., only suggest --overwrite if it’s valid for that
     subcommand).
3. Incremental results
   - Return partial results quickly (local or cached) and update once async remote returns.
4. Disambiguation rules
   - For strings without @, default to local path unless the command expects an internal ID.
   - If command expects both (e.g., task ID or path), show both, but separate in menu.
5. Helpful menu
   - Show display as full path or full command syntax
   - Provide usage text for commands (your spec wants this)
   - For paths, include file size or modified time optionally
6. “Power user” UX
   - Support fuzzy matching (e.g., gst -> getsize).
   - Add Tab to fill “common prefix” and Tab twice to list all.
7. State‑aware completion
   - Example: if command is task inspect, prefer task IDs over paths.
8. Error resilience
   - If remote path completion times out, show cached results with a “stale” mark.
   - If connection not established, suggest host nicknames and show a hint (“not connected”).

  ———
