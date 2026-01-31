# Completer

various and convenient completer is the most fascinating feature of this programm, so try your best to make this part human-friendly and easy-use. If you have some suggestion about my design(my idea always has some flaws), just tell me

# Overview

## Completer Target Type

+ CLI Function Name
  + subcommand name
  + func name
  + options (when type in "-")
+ Internal Values
  + TaskID
  + ClientNames
  + HostConfigNicknames
+ Path
  + Local Path
  + ServerPath
  + some times user may typein {nickname}@{path} or just typein path, you'd better distinguish it because former match nicknames, but latter match paths

## Complete Methods

+ Complete Menu
+ + all matched target will be showed in complete menu
    + i prefer show the whole entry in complete menu just like below
      ```bash
      /
        /model         choose what model and reasoning effort to use
        /approvals     choose what Codex can do without approval
        /permissions   choose what Codex is allowed to do
        /experimental  toggle experimental features
        /skills        use skills to improve how Codex performs specific tasks
        /review        review my current changes and find issues
      ```

  the chosen entry has highlight

  pure command entry has function usage instructions

  path match entry will format path
+ Tab complete

  + when just one target, direct fill in
  + when multi targets, print all matches when recieve multi continuous tab key (like unix path completer)

# How Complete Work

+ Async
  + must implement async complete in remote path match
  + had better implement async complete in local path(sometimes local path has many items and it takes long)
  + optional to implement async in command complete
    + if want to unify function interface, you can use async
    + but if not, sync way is ok
