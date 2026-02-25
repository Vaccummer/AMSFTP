
1. [Medium] Path parsing logic is duplicated between highlighter and completer, and is already drifting.
   src/cli/TokenTypeAnalyzer.cpp:760 and src/cli/searcher/path_searcher.cpp:267 both parse @, resolve nickname/local, substitute
   vars, and build absolute path. This should be one shared PathPrefixContext helper.
2. [Medium] AMFileSystem path operations repeat the same resolve boilerplate across many commands.
   src/manager/FileSystem.cpp:656, src/manager/FileSystem.cpp:714, src/manager/FileSystem.cpp:763, src/manager/
   FileSystem.cpp:978, src/manager/FileSystem.cpp:1001, src/manager/FileSystem.cpp:1055 all do: parse path -> resolve client ->
   build absolute path -> execute op. A shared resolver function would remove a lot of repeated code and reduce inconsistency
   risk.
3. [Medium] Completion/highlight helpers are reimplemented in multiple places.
   src/cli/completer/engine_worker.cpp:17, src/cli/TokenTypeAnalyzer.cpp:57, include/AMCLI/Completer/SearcherCommon.hpp:36
   duplicate helpers like unescape, path-like detect, option-prefix detect, timeout conversion. These should be centralized in
   one header.
4. [Medium] NormalizeStyleTag_ is duplicated in 3 modules.
   src/manager/prompt/api.cpp:83, src/cli/TokenTypeAnalyzer.cpp:193, src/cli/completer/engine_skeleton.cpp:17. Same logic should
   be shared.
5. [Medium] Singleton ownership pattern is inconsistent for set manager.
   src/manager/set/core.cpp:84 returns AMSetCLI::Instance() for AMSetManager::Instance(), unlike normal singleton ownership style
   used elsewhere (example include/AMManager/Host.hpp:197). This is confusing API/lifetime design.
6. [Medium] Naming style conflict in public manager API (AMFileSystem uses lowercase verbs while peers use PascalCase).
   include/AMManager/FileSystem.hpp:31 vs include/AMManager/Host.hpp:207. Public API consistency should be standardized.
7. [Low] FTP/SFTP parsing logic is duplicated across CLI and filesystem layers.
   include/AMCLI/CLIArg.hpp:749 and src/manager/FileSystem.cpp:616 both parse/validate user@host and nickname behaviors. This can
   be one shared parser.
8. [Low] History JSON read/write code duplicates schema-walk logic.
   src/manager/prompt/profile.cpp:343 and src/manager/prompt/profile.cpp:428 both manually convert commands arrays. A serializer/
   deserializer helper would simplify maintenance.
9. [Low] Repeated IsLocalNickname_ helper appears in multiple modules.
   src/cli/TokenTypeAnalyzer.cpp:43, src/manager/client/PathOps.cpp:6, src/manager/client/Operator.cpp:12. Should be one shared
   utility in client manager layer.
10. [Low] Typo conflicts in core names and fields reduce maintainability.
    include/AMBase/DataClass.hpp:278 (ConRequst), include/AMManager/Host.hpp:54 (fileds), include/AMClient/Base.hpp:115
    (ignore_sepcial_file).
11. [Low] Function comment style rule is not consistently followed in short methods.
    include/AMBase/CommonTools.hpp:51 uses inline comments for functions where project guideline asks /** ... */ style docs.
12. [Low] Type alias style is inconsistent with project C++ style in one C-interop header.
    include/AMBase/RustTomlRead.h:18 (using ConfigHandle = struct ConfigHandle;) differs from the usual alias pattern in the
    project.

  Highest-value refactor batch

1. Extract shared helpers: style-tag normalize, token/path primitives, local-nickname check.
2. Introduce shared PathPrefixContext resolver and migrate both TokenTypeAnalyzer and AMPathSearchEngine.
3. Extract AMFileSystem common path-resolution wrapper and migrate repeated operations incrementally.
