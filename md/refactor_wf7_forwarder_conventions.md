# Workflow-7 Forwarder Conventions

## Scope

This convention applies to legacy compatibility headers under:

- `include/AMBase/*`
- `include/AMManager/*`
- `include/AMCLI/*`
- `include/AMClient/*`

when they are used as transitional forwarders to layered headers.

## Required Forwarder Shape

Forwarder headers should remain minimal:

1. `#pragma once`
2. exactly one include to the layered canonical header
3. no additional declarations, macros, or behavior

Example:

```cpp
#pragma once
#include "foundation/DataClass.hpp"
```

## Status Marking Rules

- `legacy`: full implementation or aggregate legacy contract remains in header.
- `bridged`: header is a compatibility forwarder to layered path.
- `migrated`: legacy header removed; callers use layered include directly.

## Safe Removal Requirements

Before removing a forwarder header:

1. include usage for that legacy path is zero in first-party code.
2. layered replacement path is stable.
3. rollback instruction is documented in cutover notes.

## Current WF7-B Notes (2026-03-04)

- Bridged and active: all `AMBase/*` public headers, plus
  `AMManager/Config.hpp`, `AMManager/Logger.hpp`,
  `AMManager/SignalMonitor.hpp`.
- Pending layered replacements: `AMClient/FTP.hpp`, `AMClient/Local.hpp`.

## Measurement

Use this command to track remaining first-party legacy includes:

`pwsh -NoProfile -ExecutionPolicy Bypass -File tools/report_legacy_includes.ps1 -RepoRoot .`
