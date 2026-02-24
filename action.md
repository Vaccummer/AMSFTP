Var process in complete Improve

exp: ls $dsk/

completer should resolve varname before search for canditates when arg type is path

Var process in highlight Improve

when a token is Path arg type:
if no clear path sign:

1. check it's client name
2. check it's config nickname
3. viewed as current client path

if  has clear path sign: viewed as path

when arg include $varname $varname use var style but the remains use path style
