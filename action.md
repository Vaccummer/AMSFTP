
**ProgressBar Improvement**

- Add a new function in `ConfigManager` to create progress bars, which initializes them based on the configuration read from `style.ProgressBar`.
- Validate and restrict the input color values, mapping them to the following `indicators::Color` enum:

```cpp
namespace indicators {
  enum class Color { grey, red, green, yellow, blue, magenta, cyan, white, unspecified };
}
```

- Since the progress bar configuration is immutable at runtime, a single instance can be created upfront and then duplicated/cloned as needed.
