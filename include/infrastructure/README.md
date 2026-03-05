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
`application/client/ClientPort.hpp` as the current application-facing client
port contract.

Legacy `include/AMClient/*.hpp` headers are compatibility shims for migration
only and should not be used for new includes.
