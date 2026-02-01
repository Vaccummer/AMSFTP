Tokenization

- Splits by whitespace, but keeps quoted strings ('...' or "...") as a single
  token.
- Tokens track {start, end, quoted}.
- Backtick (`) can escape quotes, so `" or `' do not start/end a quoted span.

Variable tokens

- Variable name chars: [A-Za-z0-9_].
- Supports $NAME or ${NAME}.
- ${...} is trimmed for whitespace before validation.
- Invalid if empty or contains non-allowed chars.

Highlighting flow (priority order)

1. Quoted strings
   - Tokens marked quoted are colored as String over their full span.
   - String has low priority, so other types can override it.
2. Special var/del command handling
   - If the first non-quoted token is var or del, it is colored as Command.
   - For var with = outside quotes:
     - = -> EqualSign
     - RHS after = -> VarValue
     - Any $VAR before = -> DollarSign + VarName
   - For var/del without =:
     - Subsequent tokens that are valid var references get $ + name coloring.
3. Standalone $VAR=... line
   - If the line starts with $ (after trimming) and contains = outside quotes:
     - = -> EqualSign
     - RHS after = -> VarValue
     - $VAR before = -> DollarSign + VarName
     - Also highlights any other $VAR references.
4. Command/module/options (CLI11 cache)
   - modules_: first token highlighted as Module if it is a module (a command
     with subcommands).
   - top_commands_: first token highlighted as Command if it is a top command.
   - Subcommands (nested path) are also highlighted as Command.
   - Options (long or short) are highlighted as Option if valid for the
     resolved command node:
     - --long or --long=... must match known long options.
     - -abc only if each short option char is valid.
5. Nickname@path
   - Any non-quoted token containing @ with a nickname prefix in config:
     - nickname part -> Nickname
     - @ -> AtSign
6. Variable references (general scan)
   - Scans entire input (excluding quoted spans) for $VAR or ${VAR}.
   - Skips backtick-escaped $ (`$).
   - Highlights $ as DollarSign.
   - If varname exists, use [style.InputHighlight.exist_varname].
   - If varname does not exist, use [style.InputHighlight.nonexist_varname].
   - Illegal var tokens fall back to other rules.
7. Other special signs
   - Backtick escape: ` before $, ", or ' -> [style.InputHighlight.escapedsign].
   - Backtick does not escape other characters.
   - Quotes are part of String when they wrap a quoted token.

Priority order (higher wins on overlap)

- EscapeSign (100)
- EqualSign (95)
- VarValue (90)
- VarName / DollarSign (80)
- AtSign / Nickname (70)
- Option (60)
- Module / Command (50)
- String (20)
- Common (0)
