# WF-7 Compatibility Cutover (Completed Manager Include Cutover)

## 1) Problem Statement / Non-goals

- Problem: keep WF-7 cutover checks and migration metrics reliable after legacy
  compatibility header folders are removed, and finish include cutover of
  legacy manager header prefixes.
- Non-goals in this pass:
  - runtime behavior changes.

## 2) Owned / No-touch Paths

- Owned (WF-7 in this pass):
  - `tools/check_wf7_cutover.ps1`
  - `tools/report_legacy_includes.ps1`
  - include replacements in `src/manager/*` from
    `AMManager/{Config,Logger,SignalMonitor}.hpp` to `infrastructure/*`
  - recovered canonical manager headers in:
    - `include/infrastructure/manager/{Client,Host,Transfer,Var,FileSystem}.hpp`
  - include replacements in first-party code from
    - `AMManager/{Client,Host,Transfer,Var,FileSystem}.hpp`
    - to `infrastructure/manager/{Client,Host,Transfer,Var,FileSystem}.hpp`
  - `include/bootstrap/WF7_STATUS.md`
- No-touch:
  - domain/application/interface behavior.
  - bootstrap/session control flow.

## 3) Dependency Map (Current)

- WF-7 tooling now detects legacy include usage by include-prefix patterns,
  independent of whether `include/AM*` folders still exist.
- Strict cutover mode (`-IncludeSingletonCompat`) keeps singleton-compat header
  usage visible during migration.

## 4) Public Contract Changes

- `tools/check_wf7_cutover.ps1`
  - switched from filesystem-enumerated header sets to rule-based matching:
    - forbidden prefixes: `AMBase/*`, `AMCLI/*`, `AMClient/*`
    - forbidden header: `AMManager/Prompt.hpp`
    - strict-only forbidden headers:
      `AMManager/{Config,Logger,SignalMonitor}.hpp`
  - added full manager-compat gate:
    - `-IncludeManagerCompat` forbids `AMManager/*`
- output now reports prefix/header rule counts.
- `tools/report_legacy_includes.ps1`
  - switched to direct include-pattern scanning and aggregation.
  - now reports legacy usage even when legacy header directories are absent.
- Source include cutover:
  - replaced legacy manager singleton-compat includes with infrastructure
    includes in `src/manager/{FileSystem,host/*,var/*,client/Operator,prompt/*,transfer/*}.cpp`.
  - replaced remaining manager-prefix includes with
    `infrastructure/manager/*` headers across `main.cpp`, `src/manager/*`, and
    compatibility bridge sources.

## 5) Migration Method

- Method: guardrail-first, metric-first, then low-risk include rewrite.
- Step 1: tighten WF-7 checks/reporting.
- Step 2: replace `AMManager/{Config,Logger,SignalMonitor}.hpp` includes with
  infrastructure equivalents while keeping behavior unchanged.
- Step 3: restore manager type contracts under `infrastructure/manager/*` and
  replace all `AMManager/{Client,Host,Transfer,Var,FileSystem}.hpp` includes.

## 6) Compatibility Impact / Rollback

- Compatibility impact:
  - no runtime impact.
  - stricter and more accurate cutover metrics.
- Rollback:
  - restore prior script revisions in `tools/`.

## 7) Done Criteria / Verification

- `check_wf7_cutover` default mode passes with rule-based checks:
  - prefix rules: 3
  - header rules: 1
  - total rules: 4
- strict mode now passes:
  - 0 violations for `AMManager/{Config,Logger,SignalMonitor}.hpp`
- manager-compat mode now passes:
  - 0 violations (`AMManager/*`)
- `report_legacy_includes` now reports actionable totals:
  - `AMBase`: 0
  - `AMCLI`: 0
  - `AMClient`: 0
  - `AMManager`: 0
