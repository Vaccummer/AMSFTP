
# Prompt Manager

The prompt manager is primarily responsible for managing content output and user input.

### print Function

- Accepts a variable number of string arguments, along with optional `sep` and `end` parameters, similar to Python's built-in `print` function.
- This function should ideally be thread-safe, implemented using a lock mechanism.

### prompt Function

- **Parameters**:

  - `prompt`: The prompt message displayed to the user.
  - `placeholder`: A placeholder string that simulates pre-filled user input.
  - A reference (or pointer) to a string variable where the actual user input will be stored.
- **Return Value**:Returns a `bool` indicating whether the user canceled the input operation (e.g., by pressing the Esc key).
- **Implementation Notes**:

  - This function can be implemented using the **replxx** library.
  - The `placeholder` can be directly written into the input buffer to simulate pre-entered text.
  - Cancellation (e.g., via the Esc key) can be handled by binding a custom keyboard shortcut.
  - Documentation for replxx functions can be found in **Context7**.
  - The replxx header file is located at:
    `D:\Compiler\vcpkg\packages\replxx_x64-windows\include\replxx.h`
