@include\AMCLI\TokenTypeAnalyzer.hpp

AMTokenTypeAnalyzer Problem

+ Abundant const decoration

auto *self = const_cast<AMTokenTypeAnalyzer *>(this);

  self->RefreshHostSet();

these codes are too wierd, it's origining from abundant const decoration on functions, fix it

+ Attr missing in PathEngineConfig

PathEngineConfig Should involves all atttrs in settings.toml [HostSet]

Highlight.Path.use_check= true  # default true

Highlight.Path.timeout_ms=1000  # default 1000, when <=0, set to default

+ RefreshHostSet Problems

!QueryKey(it.value(), {"CompleteOption", "Searcher", "Path"},

    &path_cfg)

only if path_cfg is a json object, it's a valid config
if some value missing, use "*" config values


AMTokenTypeAnalyzer::Tokenize Problem

didn't take ` to escape $ or @ into account

so casual on distiguishing option, you should determine command first then judge whether an option is valid


AMTokenTypeAnalyzer::Tokenize Improve

AMTokenType add new items:
Path: path token when  Highlight.Path.use_check is false

Nonexistentpath: nonexistent path token when Highlight.Path.use_check is true

File: regular path token when Highlight.Path.use_check is true

Dir: ...

Symlink: ...

Special: other special path token when Highlight.Path.use_check is true
