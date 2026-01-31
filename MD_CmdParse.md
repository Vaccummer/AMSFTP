
## Improve Variable Reference System

### Query Functionality

```
var $varname $varname2
var ${varname} ${varname2}
```

Queries the values of both temporary (in-memory) and persisted (storage) variables. Supports batch queries. Output must indicate the variable's scope and apply styling `[style.UserPaths]` to both keys and values, formatted as:

``[Scope] $varname = value``

If the query is triggered but no matching variables are found at all, an error must be raised.

**Additional Requirements:**

- Parse all keys to be queried first. If any illegal key is encountered (e.g., a token not starting with `$`), immediately return an error and abort the entire command execution.
- If some keys are not found during lookup, `AMVarManager` should log an individual "not found" error for each missing key, but continue processing the remaining keys. The final result should return the last encountered error.

The same rules apply to deletion operations below.

### Deletion Functionality

Accepts multiple targets for deletion. Non-existent targets should trigger errors:

```
del $varname1 $varname2
```

- For each non-existent variable, report a per-key error without interrupting deletion of other valid targets.
- If a command triggers query or deletion functionality but contains tokens violating the expected syntax (e.g., assignment operators appearing in a query command), treat it as a syntax error and abort the entire command without execution.
- del all scope variable, need confirm

**Note:** The following four forms are equivalent—they all assign an empty string to the variable and do **not** delete it:

```
var ${varname}=
var $varname =
var ${varname}=""
var $varname = ""
```

### Enumeration

Command:

```
var
```

Output format: list in-memory variables first, followed by storage variables. All entries must be styled appropriately:

```
[InMemory]
$varname = value

[InStorage]
$varname2 = value2
```

# clarify

style.UserPaths is in setting.toml now, i updated it

inner leading or tailing whitespace is always allowed and stripped

If i want to conduct a cmd, the first token must be function name(before substitution)

to eliminate ambigunity, we must operate variable with cmd like var or del
