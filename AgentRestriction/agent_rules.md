# Agent Rules

## 1. Execution Constraints

1. Do not build/compile unless the user gives a specific build command.
2. Files ending with `.dep` are deprecated; do not use them as active implementation targets.
3. Do not remove a directory unless it is empty. If removal is needed, ask the user to do it.
4. Before execution, keep confirming with the user until there is no ambiguity in the plan.

## 2. Code Style Constraints

1. Use C++17 style by default.
2. Avoid C-style code when a C++ alternative is reasonable.
3. Follow the repository `clang-format` style.
4. don't use const & on pointer and enum data type in function partameters
5. when a file x.xx is deprecated, rename to x.xx.dep, if a code block is deprecated, mark as:
   // deprecated
   xxxxxxx
   xxxxxxx
   // deprecated
