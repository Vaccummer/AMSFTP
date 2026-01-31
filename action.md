
# All Functions below are used in Interacctive Mode

## check

real_func: `AMFileSystem::ECM AMFileSystem::check(const std::vector<std::string>& nicknames, amf_interrupt_flag)`

```cpp
ClientRef client = resolve_by_name(name);
```

The return result needs to be more detailed—distinguish between "client not established" and "config does not exist"—and error messages must be printed accordingly.

+ This requirement also applies to other functions such as `cd`.
+ The returned `ECM` is only used to set the status. When an error occurs, the function itself must print the error message internally.
  + Format: `❌ {cli_func_name}: {msg}`

## ch

real_func:
`AMFileSystem::change_client(const std::string& nickname, amf_interrupt_flag)`

## disconnect

`AMFileSystem::remove_client`

## cd

`AMFileSystem::cd`

## clients

`AMFileSystem::print_clients`: This function requires a new `detail` option. When enabled, it should print the client status; otherwise, it should print only the client names.
