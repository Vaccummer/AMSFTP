
## ProgressBar

The progress bar must be **thread-safe and can be ASNI escape**

### Display Format

```
{prefix}    {percentage} | {accumulated_size}/{total_size}     [ {elapse_time}<{remain_time}  {speed} ]
```

### Formatting Rules

- **`prefix`**: Left-aligned; width adjustable via user API
- **All other fields**: Fixed width, right-aligned; configurable via user API
- **`accumulated_size` / `total_size`**:
  - Input: `int64_t` value in bytes (provided by user)
  - Display: **4 significant digits** with automatic unit scaling:
    - `B` → `KB` (÷1024) → `MB` → `GB` → `TB`
    - Examples: `1023 B`, `1.02 KB`, `999 KB`, `1.00 MB`, `10.5 GB`
- **`speed`**:
  - Automatically calculated (bytes/sec)
  - Format: Same unit scaling as size fields, **1 decimal place**
  - Example: `2.3 MB/s`
- **Time fields**:
  - Format: `[mm:ss]` (minutes:seconds)
  - Example: `[21:32]` = 21 minutes 32 seconds
  - `elapse_time`: Time elapsed since start
  - `remain_time`: Estimated remaining time (based on current speed)

---

## ProgressBarGroup

Supports **multiple concurrent progress bars** with synchronized refresh:

```
{prefix}    {percentage} | {accumulated_size}/{total_size}     [ {elapse_time}<{remain_time}  {speed} ]
{prefix}    {percentage} | {accumulated_size}/{total_size}     [ {elapse_time}<{remain_time}  {speed} ]
{prefix}    {percentage} | {accumulated_size}/{total_size}     [ {elapse_time}<{remain_time}  {speed} ]
```

### Key Features

- All bars share the same terminal/console output area
- **Atomic refresh**: Entire group redraws simultaneously to prevent visual tearing
- Thread-safe operations for adding/removing bars or updating progress
- Automatic vertical layout management (no overlapping)

Improve

size数值超过1000时换单位,  不足100时取一位小数,  大于等于100取整
