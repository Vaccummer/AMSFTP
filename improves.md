# Improve To Completor

# Align Command Complete

(local)D:/CodeLib $
 1 bash  Enter interactive mode
 2 cd  Change working directory
 3 ch  Change current client
 4 client  Client manager
 5 complete  Completion utilities
when no valid function situation, complete menu should show module first , then functions

modules, functions names should be aligned and styled in style.InputHighlight

and two builtin functions are missing: var, del

# Problems in resovling relative path . and ..

AMFS::abspath and AMFS::join should be carefully designed to be able to process:

+ Linux path
+ Windows path
+ Network path
+ relative path
+ .
+ ..
+ mix sep path
+ duplicate sep path

(wsl)/home $ cd am/haha
❌ cd: Get stat failed: File does not exist
 am@172.26.36.83  7ms  ❌ FileNotExist
(wsl)/home $ cd ./am/haha
❌ cd: Get stat failed: File does not exist
 am@172.26.36.83  6ms  ❌ FileNotExist

# Bugs: auto menu show and auto fillin set

It seems that you implement auto menu show by simulate tab key

but if there's only one candidate, it triggers auto fill in, that's not I want

# Adjust: Style set adjust

Now all element style (except path and debugger) is defined in [style.InputHighlight]

debugger style 

path style is defined in [style.Path1]  [style.File2]  the one has greater number override small one

[style.PathExtraStyle] is extra style when path met certain demand(default is empty string, means no user extra style)

[style.File2] define files have certain extension name styles, overide style in [style.Path1]
