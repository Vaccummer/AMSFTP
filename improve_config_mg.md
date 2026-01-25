**Config Manager**

**In the **`modify` function, I need the original value to be used as a placeholder—similar to how `prompt_toolkit` does it—so it appears as if the user has already pre-filled the input. Additionally, this placeholder should support basic styling (you can refer to the documentation of the `prompt_toolkit` and `replxx` libraries for details; see Context7).

**The current Ctrl+C exit behavior in both **`modify` and `add` functions is unstable. Please change it to exit on pressing the **Esc** key instead.
