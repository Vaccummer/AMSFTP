Overview
  The completer is a coordinator that parses the current input, decides what kind of completion is appropriate (command, option,
  variable, host, task ID, or path), gathers candidates from the relevant sources, sorts them, and feeds them into isocline’s completion UI.

  How Completion Works

1. Input parsing and target selection
   The completer tokenizes the current line and uses the cursor position to determine the active token. It then applies the priority rules from your blueprint: module/subcommand, variable, option, command-specific parameters, then path.
   Implementation: src/cli/Completer.cpp
2. Candidate collection
   It gathers candidates based on the target:

- Command/subcommand/option candidates come from a CLI11-derived command tree.
- Variables, clients, hosts, and task IDs come from their managers.
- Paths are resolved locally (sync) or remotely (async with debounce and caching).

  Implementation: src/cli/Completer.cpp

3. Sorting and rendering
   Candidates are sorted (path types obey file/dir/symlink ordering) and sent to isocline with per-token replace ranges.
   Implementation: src/cli/Completer.cpp
4. Async remote path completion
   Remote directory listing is done on a background thread with debounce. Results are cached (if directory size exceeds cache_min_items) and the menu is re-opened when results arrive.
   Implementation: src/cli/Completer.cpp

  Binding to Isocline
  The binding is done by installing a default completer into isocline and using the callback to emit candidates.

1. Install the completer
   At startup of the interactive loop we construct the completer and install it:

  AMCompleter completer(config_manager, client_manager, filesystem, transfer_manager);
  completer.Install();

  This calls:la

  ic_set_default_completer(&AMCompleter::IsoclineCompleter, this);

  Implementation: src/cli/InteractiveLoop.cpp, src/cli/Completer.cpp

2. Isocline callback
   Isocline calls our static completer function when Tab is pressed:

  void AMCompleter::IsoclineCompleter(ic_completion_env_t* cenv, const char* prefix)

  Inside, we use ic_completion_input to get the full input and cursor, then run the completion pipeline and push results with
  ic_add_completion_prim.

  Implementation: src/cli/Completer.cpp

3. Async menu wake
   When remote results arrive, the async worker requests a menu refresh:

  ic_request_completion_menu_async();

  This is a thread-safe isocline extension that injects a Tab event into the input stream.

  Implementation:

- API: include/Isocline/isocline.h, src/Isocline/isocline.c
- TTY injection: include/Isocline/tty.h, src/Isocline/tty.c

  Key Files

- Core completer logic: src/cli/Completer.cpp
- Completer interface: include/AMCLI/Completer.hpp
- Interactive loop install: src/cli/InteractiveLoop.cpp
- Isocline async hook: include/Isocline/isocline.h, src/Isocline/isocline.c, include/Isocline/tty.h, src/Isocline/tty.c

  If you want a diagram or more detailed flow for a specific target (e.g., nickname@path), say which case and I’ll add it.
