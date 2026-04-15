1.Wront style
"$code" is varname but styled as "cli.unexpected"
 am@localhost  0ms  ✅
(local) D:/CodeLib > var get $code

"$local:haha" is varname but styled as "cli.unexpected"

 am@localhost  0ms  ✅
(local) D:/CodeLib > var del $local:haha

"1" in "tree -d 1 ." is the option value, and should be styled to "cli.option_value""

 am@localhost  0ms  ✅
(local) D:/CodeLib > tree -d 1 .

task thread 3
num "3" is valid but styled as "cli.unexpected"

2. add a module "pool"

pool is the counterpart of module "client", they share the same output format and function logic, but "pool" manages clients from the public pool instead of maintainer
