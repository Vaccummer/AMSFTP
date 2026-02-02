# Improve

```
config get accepts any number of arguments; when called without arguments, it prints information about the current client.

connect:
+ Added new -f, --force option
+ When -f is specified, the client must be fully rebuilt and replaced upon success. This option is primarily intended to apply host configuration changes to the client. If the client does not already exist, the -f option is ignored.
```
