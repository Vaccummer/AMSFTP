# Repository Guidelines

## Project Overview

**This is a command-line file management tool, conceptually similar to an integrated combination of OpenSSH's **`sftp` and `ssh`, featuring the following capabilities:

1. **Perform basic I/O operations (e.g., copy, delete, move, create) on both local and remote servers.**
2. **Store multiple client configurations—supporting FTP, SFTP, or local clients—and seamlessly switch between them.**
3. **Launch interactive terminal sessions directly from SFTP or local clients, providing full terminal functionality.**

**Key Features:**

* **All I/O operations are executed asynchronously and can be interrupted via **`Ctrl+C`.
* **Richly formatted output with colors, styling, and visual emphasis to highlight important information.**
* **Comprehensive auto-completion support in non-terminal mode, including:**

  * **Command completion**
  * **Host nickname completion**
  * **Path completion**

  **Two completion mechanisms are provided:**

  * **Pressing **`Tab` once completes uniquely matched entries; pressing `Tab` twice lists all possible matches.
  * **Candidate suggestions appear vertically below the cursor in the input line, allowing selection via the up/down arrow keys.**

**IMPORTANT INFORMATION:** The above description serves only as a high-level preview of the entire project. During implementation, you should design your code with compatibility and extensibility in mind to support these features. However, unless explicitly instructed by the user, you should not implement these features at this stage.

## Project Structure & Module Organization

- Pure C++ project, include in "./include", source files in "./src", "main.cpp" in root, and "test.cpp" in "./test"
- using "mvsc" compiler currently, but codes had better to be platform independent

## Library Docmentation Lookup

- use "context7" to look up the use of certain library
- If context7 doesn't return info,  vcpkg root is "D:\Compiler\vcpkg", and packages are installed in
- "D:\Compiler\vcpkg\installed\x64-windows"
- If you need source code of certain library, query user in the command line, he will give you the path.

## Extra Rules

folder "./AgentRestriction" in project root defines project structure and code format or rules, you must check them
