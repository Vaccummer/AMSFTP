
@InteractiveLoop.cpp

In `ResolveSysIcon_`, the `icon` is in the format `[#3490de]icon[/]`. Attempt to convert it to ANSI escape sequences; if the format is invalid, return the original string.

```cpp
SplitCommandLine_(pre_result.command, &argv, &parse_error)
```

This call is unnecessary—delegate command-line parsing to the CLI library instead:

```cpp
CLI::App::parse(std::string commandline, bool program_name_included=false)
```

Consequently, the subsequent `argv.insert(argv.begin(), app_name);` is also unnecessary.
