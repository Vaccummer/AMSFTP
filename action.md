# Input Parse Protocol Improve

## Main Work1: Deleting AMCommandPreprocessor

+ & will be treated as common args and in ArgStruct.Run, it detects &
  + task submit acts the same way
    + add a position arg to detect & (only allows &)
    + remains -a --async usage
+ removing preprocessor also removes shorthand assignment behavior
+ unify variable-name restriction to [_a-zA-Z0-9]+
+ Shrink preprocessor to a function
  + identify heading !
  + process ` escape on char(except $)

## Main Work2: Implement Var Replace in VarManager

Now we use Post-parse substitution, Apply substitution before filesystem/path resolution in path-arg Run()

Var Replace Rules

+ Restore ` escape on $ and don't replace
+ check whether var use rule is leagal, if not don't replace
+ forbid recursive replace
+ Find in private zone first then pulic zone
+ if varname not exists, don't replace

## Other Improve

Unify var-name validation in one place (varsetkn::IsValidVarname) and reuse it
