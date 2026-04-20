# Architecture Rules

## Mandatory

1. Follow layer responsibilities defined in `AgentRestriction/strcture.md`.
2. Do not place prompt/print/style/render business in application layer.
3. Application APIs should return result state + data (`Result<T>` style), not status-only side effects.
4. Related domain capabilities should be grouped into cohesive larger ports; avoid unnecessary tiny ports.
5. DTOs consumed by interface should be owned by application layer.
6. Async/cancel policy must be explicit in app/domain port signatures where needed.
7. Bootstrap is composition-only and must not include use-case business logic.
8. Enforce include/dependency boundary checks via guardrail scripts.
9. Refactor execution should proceed by vertical slices, not big-bang rewrites.
