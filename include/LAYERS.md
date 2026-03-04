# AMSFTP Layering Policy (Workflow-0)

This repository follows the target layered structure:

- `include/foundation`: shared primitives, common types, error codes, utilities
- `include/infrastructure`: adapters (config IO, logging sinks, signal/platform wrappers)
- `include/domain`: business/domain services and models
- `include/application`: use-cases and command orchestration
- `include/interface`: CLI-facing contracts, rendering/input abstractions
- `include/bootstrap`: composition root and dependency wiring

## Dependency Direction

Allowed direction:

`foundation <- domain <- application <- interface <- bootstrap`

Additional rule:

- `infrastructure` may depend on `foundation` and may implement interfaces
  defined by `domain`/`application`.
- `domain` must never depend on concrete infrastructure implementations.

## Include Rules for Layered Files

For files under `include/<layer>/` and `src/<layer>/`:

1. `foundation` can only include `foundation/*` (plus third-party/system).
2. `infrastructure` can include `foundation/*` and `infrastructure/*`.
3. `domain` can include `foundation/*` and `domain/*`.
4. `application` can include `foundation/*`, `domain/*`, `application/*`.
5. `interface` can include `foundation/*`, `domain/*`, `application/*`,
   `interface/*`.
6. `bootstrap` can include all layer headers because it is the composition root.

## Singleton and Lifetime Rules

1. No new singleton/global mutable services may be introduced.
2. Process-lifetime ownership belongs to `AppHandle` in `bootstrap`.
3. Session-lifetime mutable runtime state belongs to `SessionHandle`.
4. Dependencies must be explicit via constructor/parameter injection.

## Transitional Migration Rules

- Legacy trees (`AMBase`, `AMManager`, `AMCLI`, `AMClient`) are allowed during
  migration.
- New layered files should avoid introducing fresh dependencies to legacy trees.
- The checker script supports optional strict mode to fail on legacy includes.

## Enforcement

- Script: `tools/check_layers.ps1`
- CMake target: `check_layers`

Run manually:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File tools/check_layers.ps1 -RepoRoot .
```

Strict mode (fail on legacy includes from layered files):

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File tools/check_layers.ps1 -RepoRoot . -FailOnLegacyInclude
```
