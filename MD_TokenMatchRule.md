 Tokenization

- Splits by whitespace, but keeps quoted strings ('...' or "...") as a single token.
- Tokens track {start, end, quoted}.

  Variable tokens
- Variable name chars: [A-Za-z0-9_].
- Supports $NAME or ${NAME}.
- ${...} is trimmed for whitespace before validation.
- Invalid if empty or contains non‑allowed chars.

  Highlighting flow (priority order)

1. Special var/del command handling
   - If the first non‑quoted token is var or del, it’s colored as Command.
   - For var with = outside quotes:
     - = → EqualSign
     - RHS after = → VarValue
     - Any $VAR before = → DollarSign + VarName
   - For var/del without =:
     - Subsequent tokens that are valid var references get $ + name coloring.
2. Standalone $VAR=... line
   - If the line starts with $ (after trimming) and contains = outside quotes:
     - = → EqualSign
     - RHS after = → VarValue
     - $VAR before = → DollarSign + VarName
     - Also highlights any other $VAR references.
3. Command/module/options (CLI11 cache)
   - modules_: first token highlighted as Module if it’s a module (a command with subcommands).
   - top_commands_: first token highlighted as Command if it’s a top command.
   - Subcommands (nested path) are also highlighted as Command.
   - Options (long or short) are highlighted as Option if valid for the resolved command node:
     - --long or --long=... must match known long options.
     - -abc only if each short option char is valid.
4. Nickname@path
   - Any non‑quoted token containing @ with a nickname prefix in config:
     - nickname part → Nickname
     - @ → AtSign
5. Variable references (general scan)
   - Scans entire input (excluding quoted spans) for $VAR or ${VAR}.
   - Skips backtick‑escaped $ (`$).
   - Highlights $ as DollarSign
   - If varname exists, using [style.InputHighlight.exist_varname]
   - If varname not exists, using [style.InputHighlight.nonexist_varname]
   - If varname is illeagal, sumbit to other rules, if no rules remain, common
6. other special sign
   1. quote sign:
      1. escaped by ` : [style.InputHighlight.escapedsign]
      2. just wrapper, not in data : using string style
      3. wrapped by quote: using string style
      4. not above: submit to others
   2. `:only when it escapes char($ '  "), use [style.InputHighlight.escapedsign], else submmit to  other rules
7. Quoted strings- token marked quoted is colored as String over its full span.

- so string have low piority, other types can overwrite it


The former statement order is not the pasrsing order, the Priority order is the real parsing order

  Real Priority order (higher wins on overlap)

- EscapeSign
- EqualSign (95)
- VarValue (90)
- VarName / DollarSign (80)
- AtSign / Nickname (70)
- Option (60)
- Module / Command (50)
- String (20)
- Common (0)
  - last rule, for every token remains unmatched
