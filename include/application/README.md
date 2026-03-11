# application

Use-cases and orchestration that coordinate domain services and ports.

Current headers:

- `application/config/CliConfigSaveWorkflows.hpp`
- `application/host/HostProfileWorkflows.hpp`
- `application/client/ClientSessionWorkflows.hpp`
- `domain/client/ClientPort.hpp`
- `application/client/FileCommandWorkflows.hpp`
- `application/var/VarWorkflows.hpp`
- `application/completion/CompletionWorkflows.hpp`
- `application/transfer/TransferWorkflows.hpp`
- `application/transfer/TaskWorkflows.hpp`

WF4 notes:

- Application workflows are written against explicit ports (no singleton access).
- Interface-layer command handlers should map parser/runtime state into these
  workflow payloads.
- Bootstrap/WF6 is responsible for wiring concrete adapters to these ports.
