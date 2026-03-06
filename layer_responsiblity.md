
1. **Foundation**

- Responsibility: universal base types and utilities, no business meaning.
- Example: `JsonValue`, error enums, string/path/time helpers.

2. **Infrastructure**

- Responsibility: concrete technical mechanisms.
- Example: `SuperTomlHandle` (TOML read/write), `AMInfraAsyncWriter` (async queue/thread), logger file IO, SSH/SFTP client adapters.

3. **Domain**

- Responsibility: business model and core rules.
- Example: `Host` rules (nickname uniqueness, required hostname), `ConfigManager` domain operations on config state (`ReadValue/WriteValue/DeleteValue` by `DocumentKind`).

4. **Application**

- Responsibility: use-case orchestration using domain + ports.
- Example: `AddHostWorkflow`:
  - load current hosts
  - call domain validation
  - write config
  - trigger async dump
  - return use-case result.

5. **Interface**

- Responsibility: input/output interaction and presentation.
- Example: CLI arg parsing, interactive prompt, rendering colored tables/progress bars from style config.

6. **Bootstrap**

- Responsibility: dependency wiring and startup composition.
- Example: construct infra objects, inject into domain/application, bind runtime adapters, start main loop.
