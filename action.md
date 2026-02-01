## Input History

A new history command feature needs to be added to the input functionality of the interactive mode.

- Use the Up and Down arrow keys to navigate through historical commands.

  - Note: This must not conflict with the autocomplete menu. When the autocomplete menu is active, arrow key navigation should prioritize selecting autocomplete items and suppress history command navigation.
- Historical commands are stored in `.AMSFTP_History.toml` located in the project root directory.

  - Commands must be saved in the format `nickname = list(cmd)`, where each client maintains its own command history and histories are not shared across clients.
  - This file is managed by `ConfigManager`, and `PromptManager` reads history data from it.
- The maximum number of history entries is defined by `settings.InternalVars.MaxHistoryCount`.

  - Minimum and default values are both set to 10.
- `PromptManager` is responsible for loading the history data into `replxx`.
- Pressing the Up arrow navigates backward through history; pressing the Down arrow navigates forward.
- Two temporary entries are appended at the end of the history list during navigation (these are active during selection but are not persisted to history):

  1. The content already entered in the input field before arrow key navigation begins (disabled if the input is empty).
  2. An empty entry used to clear the input field.
- A command is added to history only when:

  - The input content is non-empty upon submission, and
  - The `COREPROMPT` hook has not been triggered.
- Upon program termination, the current history from `replxx` is retrieved and written back to `.AMSFTP_History.toml`.
