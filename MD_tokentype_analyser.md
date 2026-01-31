
## TokenType Analyzer

```cpp
replxx::Replxx rx;
rx.set_highlighter_callback([](std::string const& input, replxx::colors_t& colors){
    // Syntax highlighting logic to be implemented here
});
```

To implement syntax highlighting for user input, I need to develop a parser and complete the callback function above.

Token types to recognize include:

- **module** (`task`, `config`) — module keywords
- **command** — executable command names
- **varname** (`$varname`, `${varname}`) — variable references
- **varvalue** — the actual value assigned to a variable
- **nickname** — user-defined nicknames/aliases
- string  - wrapped by quote
- **option** (`-f`, `-d`, etc.) — command-line options/flags
- **atsign** — the `@` symbol that actually takes effect (i.e., only when the preceding nickname is defined in the config)
- **dollarsign** — the `$` symbol that triggers variable expansion (excluding escaped `$`; valid only when followed by a syntactically correct variable name, without checking whether the variable actually exists)
- equalsign   = in assign expression
- common (all not above)
