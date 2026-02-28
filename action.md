Great Improve on ConductCmd (sftp/local)

add an str cmd_prefix(you can choose a suitable argname) bool wrap_cmd in HostConfig in config\config.toml, this cmd_prefix is invisible to Client, but should be stored in ClientConfig

ConductCmd itself only recept final command and conduct it. remove cmd check in IsCommandAllowed

add a function in Filesystem ShellRun(str cmd, and other args you think necessary) for CLI bind, it proximately does things:

+ build command(if no prefix, just use arg cmd)
  + prefix'cmd' (if wrap)
  + prefixcmd
+ call ConductCmd
