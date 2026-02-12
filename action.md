
## Refactor PImpl Pattern

  Promote `AMCompleter::Impl` to an independent class named `AMCompleteEngine`, and decompose `AMCompleteEngine` into the following
  components:

### 1. Core Engine Logic and Standard Definitions

    - Framework of the entire completion pipeline
     - Standardized formats for completion requests and candidates:
       -`CompletionRequest` structure
       - `CompletionCandidate` structure (with fields: `insert_text`, `display`, `kind`, `help`, `score`, metadata)
     - Formalized asynchronous completion workflow:
       - `AsyncRequest` encapsulates:
         - `request_id` for result validation
         - Candidate list
         - A search function that performs the actual completion lookup (the function itself handles timeout logic and cache
  behavior)
         - Additional attributes as needed (e.g., priority, cancellation token)

### 2. Context-Aware Dispatch Functions (Completion Orchestration)

    -`BuildContext_()`: Parses input tokens and determines the completion target type (command, option, path, variable, etc.)
     - New dispatch function: Routes completion requests to appropriate search functions based on `CompletionTarget` enum
     - `SortCandidates_()`: Applies unified scoring and ordering rules across all candidate sources

### 3. Concrete Completion Search Functions (Pluggable Sources)

    -`CollectCommandCandidates_()`: Queries the static `CommandTree` for command/subcommand/option suggestions
     - `CollectInternalCandidates_()`: Gathers values from internal sources (variables, client names, host nicknames, task IDs,
  config attributes)
     - `CollectPathCandidates_()`: Handles local/remote path completion with caching and async remote lookup

> **Design Goal**: Decouple the completion *orchestration* (part 2) from the *data sources* (part 3), with part 1 providing the
> standardized interface and async infrastructure. This enables easier testing, source replacement, and future extension (e.g.,
> plugin-based completion sources).
>
