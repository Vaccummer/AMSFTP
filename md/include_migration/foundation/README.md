# foundation

Shared primitives, common types, error codes, and reusable utilities.

Current migrated headers:

- `foundation/Enum.hpp`
- `foundation/DataClass.hpp`
- `foundation/Path.hpp`
- `foundation/RustTomlRead.h`
- `foundation/tools/auth.hpp`
- `foundation/tools/bar.hpp`
- `foundation/tools/enum_related.hpp`
- `foundation/tools/json.hpp`
- `foundation/tools/string.hpp`
- `foundation/tools/time.hpp`

Migration note:

- `TaskControlToken::Instance()` remains as a transitional compatibility API and
  is deprecated in favor of explicit ownership via
  `TaskControlToken::CreateShared()`.
