# Project Layer Structure 

## 1. Domain Layer

- Defines business rules, entities, and domain ports.
- Ports are **fundamental capability ports** for upper layers.
- Avoid tiny ports: related capabilities with no clear border should be grouped into one cohesive larger port.
- No dependency on `application`, `interface`, `bootstrap`, or concrete infra details.

## 2. Infrastructure Layer

- Implements domain ports.
- Contains protocol/platform adapters (local/sftp/ftp, storage, OS bindings).
- Depends on domain contracts, not interface behavior.

## 3. Application Layer

- Holds domain ports and performs primary use-case orchestration.
- Returns result state + data (`Result<T>` / equivalent), not UI side effects.
- Must not contain interface-layer business code:
  - no prompt
  - no print
  - no style/render formatting
- Owns application DTO contracts exposed to interface layer.

## 4. Interface Layer

- Holds application service instances directly.
- Performs interface orchestration:
  - argument parsing
  - confirmation/prompt flow
  - print/render/style
- Converts app results/DTOs to user-visible output.

## 5. Bootstrap Layer

- Composition root only.
- Assembles and wires concrete classes across layers.
- Owns startup/runtime binding/lifecycle hookup.
- Must not implement domain rules or interface business flow.

## Dependency Direction

- `domain -> (none)`
- `infrastructure -> domain`
- `application -> domain`
- `interface -> application`
- `bootstrap -> domain/application/infrastructure/interface` (wiring only)

## Confirmation Boundary Pattern (Required)

For operations requiring user confirmation:

1. Application pre-confirm slice computes plan/impact and returns data requiring decision.
2. Interface prompts user.
3. Application post-confirm slice executes according to user decision.

This keeps prompt logic in interface while keeping decision-dependent business behavior in application.
