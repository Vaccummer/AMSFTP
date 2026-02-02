# Completion Menu

## Manual trigger

- Add an API to open the completion menu programmatically (not only via Tab). This should re-use existing completion data and UI.

## Pagination & numbering

- Add pagination in the completion menu.
- Tab = next page; Shift+Tab = previous page.
- Numbering restarts at 1 on each page.
- Each page shows a page index (e.g., "Page 2/5").

## Selection behavior

- When a match is selected, Left/Right move between matching items.
- When no match is selected, Left/Right move the cursor within the input field.
- completion will be applied if a menu item is chosen
- if user accept completion, just go on to type; if not delete undesired chars
- add an hotkey to close completion menu

## Tab/Shift+Tab + multiline

- Current behavior: Tab/Shift+Tab navigate menu items; Shift+Tab also inserts a newline in multiline mode.
- Desired behavior: Shift+Tab inserts a newline only when the menu is closed; when the menu is open, Shift+Tab navigates to the previous page.

## Columns & limits

- Add a setting for the maximum number of displayed columns in the completion menu.
- The maximum number of items is large (about 1000). Keep this limit and allow it to be configured.

## Sorting

- Add a setting to disable automatic sorting of completion items.
- When sorting is disabled, preserve the original insertion order.

# Editor

## Shift+Enter newline

- Shift+Enter inserts a line break (multiline mode).

## Line prefix

- After line breaks, the leading marker/prefix for each line is customizable.
- The prefix supports styled formatting but is a fixed value (not computed dynamically per line).

## Clipboard

- Add a hotkey to copy the current input to the system clipboard.

# Open questions

- What should the manual "open menu" API be named, and should it require an active completer?
  - you decide it
- Should Left/Right navigation between matches wrap around at the ends?
  - not work if at the ends
  - only work in multi columns situation
- What is the default max columns value?
  - 4
- What is the default max items value (currently 1000)?
  - 1000
- What key combo should trigger clipboard copy, and should it be configurable?
  - abort this feature
- Add ctrl-x to clear input
  - can be reversed by ctrl-z
