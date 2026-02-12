# AMCompleter Workflow Guide

This document explains how completion works in:

- `include/AMCLI/Completer.hpp`
- `src/cli/Completer.cpp`

## 1. Entry Points

- `AMCompleter::Install()` registers Isocline callback via `ic_set_default_completer(...)`.
- Isocline triggers `AMCompleter::IsoclineCompleter(...)` whenever completion is requested.
- The callback forwards work to `AMCompleter::Impl::Complete(...)`.

## 2. High-Level Pipeline

`Complete(...)` follows this pipeline:

1. Build `CompletionContext` from current input and cursor.
2. Classify target type (`TopCommand`, `Subcommand`, `Option`, `Host`, `Client`, `Var`, `Path`, etc.).
3. Collect candidates for that target type.
4. Sort candidates.
5. Emit final completion entries back to Isocline.

## 3. Parsing and Context Resolution

Core helpers:

- `TokenizeInput(...)`: splits input into tokens, handles quoted tokens.
- `FindTokenAtCursor(...)`: finds the active token under cursor.
- `ParseCommandPath_(...)`: determines current command/subcommand path.
- `ComputeArgIndex_(...)`: determines positional argument index.
- `BuildPathContext_(...)`: parses local/remote path completion context.

Important parsed state is stored in:

- `CompletionContext`
- `PathContext`

## 4. Target Classification

`CompletionTarget` is computed from command path + argument position + token prefix:

- Command tree completions: top command / subcommand / options.
- Internal entity completions:
  - variable names
  - host nicknames
  - client nicknames
  - host fields for `config set`
  - task ids
- Path completions (local or remote), including remote prefix parsing like `host@path` and local `@path`.

## 5. Command Metadata Source

`CommandTree` is built from CLI11 bindings (`BindCliOptions(...)`), then queried for:

- top-level commands
- subcommands
- long options
- short options

This keeps completion aligned with real CLI structure.

## 6. Candidate Building

Main collectors:

- `CollectCommandCandidates_(...)`
- `CollectInternalCandidates_(...)`
- `CollectPathCandidates_(...)`

Each candidate uses:

- `insert_text` (actual completion text)
- `display` (styled display text)
- `help`
- `kind`
- optional `path_type`

## 7. Path Completion and Async Behavior

Path completion supports cache + async refresh:

- cache key: `(nickname, absolute_dir)`
- cached entries stored in `cache_`
- remote path listing can be scheduled via `ScheduleAsyncRequest_(...)`
- async worker thread (`AsyncWorkerLoop_`) fetches remote entries and updates cache
- foreground completion can consume latest async result when key/prefix still match

This keeps interactive latency low for remote directories.

## 8. Sorting Rules

`SortCandidates_(...)` sorts by:

- priority score
- lexical order
- special path ordering by `PathTypeOrder(...)` (dir/file/symlink preference logic)

## 9. Isocline Emission

`EmitCandidates_(...)` computes:

- `delete_before`
- `delete_after`

based on token span and cursor, then emits completion items to Isocline with styled labels.

## 10. Runtime Settings Used

Completer reads settings from config (mainly `CompleteOption` and style fields), including:

- max items
- max rows per page
- number pick
- auto fill
- item select sign
- completion delay
- cache limits
- input highlight style tags

These are resolved through `AMConfigManager` methods used in `Completer.cpp`.

## 11. Main Data Structures in `Completer.cpp`

- `CompletionToken`
- `CompletionContext`
- `PathContext`
- `CompletionCandidate`
- `CommandNode` / `CommandTree`
- `CacheKey` / `CacheEntry`
- `AsyncRequest` / `AsyncResult`

## 12. Integration Summary

At runtime:

1. CLI starts and installs completer.
2. User types input.
3. Isocline asks completer for candidates.
4. Completer parses context, collects and ranks candidates.
5. Isocline renders candidate list and applies selected completion.

