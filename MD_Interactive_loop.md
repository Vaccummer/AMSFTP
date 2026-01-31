## DispatchCliCommands Optimization:

- Return `ECM` plus optional extra data if needed (e.g., `enter_interactive`).
  - Suggested pattern: return a small struct like:
    ```
    struct DispatchResult { ECM rcm; bool enter_interactive; };
    ```
  - `rcm` is the primary status; extra flags are optional and should not be relied
    on by non-interactive callers unless explicitly needed.
- At the very beginning of the function, check whether any subcommand matches the input. If none matches, print an error message and return an error code.
- After that, verify whether the current mode is Interactive. If not in interactive mode, exit early and return `EC::OperationUnsupported` with the message: "`{cmd_name}` not supported in Non-Interactive mode".
- Then proceed to implement the logic for dispatching and executing commands in interactive mode.

# Interactive Loop

Interactive mode is fundamentally a loop that follows the pattern: prompt for command → execute command → prompt for command.

However, this loop requires specific configuration and control mechanisms.

## Overall Flow

1. Obtain user input using the `replxx` library.
2. If the command, after trimming leading/trailing whitespace and converting to lowercase, equals `exit`, clean up resources and terminate the program.
3. Preprocess arguments using `CommandPreprocessor`:
   1. Some functions are executed during the preprocessing stage.
   2. Certain operations may be fully completed at this stage.
4. Parse the command using CLI11 (this step may be skipped in specific cases).
5. If parsing fails, print the CLI11 error message.
6. Execute the command via `DispatchCliCommands`.
7. Retrieve the execution result and update status information reflected in the input prompt.

## Practical Parsing Notes

- Use a dedicated parse-from-string path for interactive mode (build argv from the input line).
- Reset CLI11 state each iteration to avoid option/subcommand residue.
- Keep preprocessing deterministic: return one of `{Handled, Continue, Exit}` to avoid ad-hoc branching.

## Input Customization

+ **Prompt**

  + Format:
    ```
    {sysicon} {username}@{hostname}  {last_elapsed}  ✅/❌ {EC_name if not success}
    ({nickname}){work_dir} $
    ```
  + `sysicon` is defined in `setting.style.Icons`; select the appropriate icon based on `GetOSType`.
  + `EC` (error code) is obtained from the function's return value.
  + The prompt generation logic can cache the current `nickname` variable. By detecting changes to this variable, it can decide whether to refresh the `{sysicon} {username}@{hostname} {nickname}` segment.

  ---
+ **Considerations for the `input` function**

  1. Requires a dedicated prompt function with interfaces reserved for future completion support (e.g., `Completer`).
  2. Must set up `set_highlighter_callback` for syntax highlighting.
  3. This `input` function does not share its `replxx` handle with other prompt functions in `PromptManager`, but its handle is still managed by `PromptManager`.
  4. During initialization, register a `COREPROMPT` hook—functionally similar to `PROMPT` but targeted at this specific handle.
  5. Before invoking `input`, activate the `COREPROMPT` signal handler and reset `amgif` (without resetting `iskill`).
  6. After obtaining input content, check the `amgif` state:
     - 6.1 If `amgif.iskill` is triggered, clean up resources and exit.
     - 6.2 If `amgif.is_interrupted` is triggered, print a message informing the user how to exit (e.g., "type 'exit'"), then `continue` the loop.
  7. After retrieving input, deactivate (`silence`) the `COREPROMPT` handler.
  8. If the user input is empty or consists solely of whitespace characters, `continue` to the next iteration.

## Additional Suggestions

- **Return value policy**: `DispatchCliCommands` should be responsible for command-level errors and print them in place; loop should only update prompt state using `rcm`.
- **Interactive-only commands**: keep them registered in CLI11 but only executed in interactive mode; in non-interactive mode, return `EC::OperationUnsupported`.
- **Prompt state**: store last `ECM` + last elapsed time in a small `PromptState` and update only after a successful dispatch.
- **User guidance**: if parsing fails, do not update last status; show the parse error once and continue.
