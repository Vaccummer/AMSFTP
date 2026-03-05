# infrastructure

Adapters for external systems and platform integration (config IO, logging,
signals, protocol wrappers).

## Client Adapter Canonical Paths

Client adapter headers are now canonical under:

- `include/infrastructure/client/common/Base.hpp`
- `include/infrastructure/client/ftp/FTP.hpp`
- `include/infrastructure/client/sftp/SFTP.hpp`
- `include/infrastructure/client/local/Local.hpp`
- `include/infrastructure/client/runtime/IOCore.hpp`

`BaseClient` in `common/Base.hpp` implements
`domain/client/ClientPort.hpp` as the current domain-facing client
port contract.

Legacy `include/AMClient/*.hpp` headers are compatibility shims for migration
only and should not be used for new includes.

## Manager Adapter Canonical Paths

Manager-type headers used by CLI bootstrap/compatibility wiring are canonical
under:

- `include/infrastructure/manager/Client.hpp`
- `include/infrastructure/manager/Host.hpp`
- `include/infrastructure/manager/Transfer.hpp`
- `include/infrastructure/manager/Var.hpp`
- `include/infrastructure/manager/FileSystem.hpp`

Legacy `include/AMManager/*.hpp` include prefixes are removed from first-party
sources and should not be reintroduced.
