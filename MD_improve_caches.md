# Config Manager

@src\manager\Config.cpp

 Improve1

AMConfigManager::LoadHistory and EnsureHistoryLoaded_() are same functions, remove one

Improve2

AMConfigManager::Format(ori_string, style_name, Pathinfo){}
Styles data position changed in setting.toml, now it has two main style domain: non-path([style.InputHighlight]) path([style.Path1] [style.File2] [style.PathExtraStyle])

if it's path,  pass in PathInfo else seemed as common string

remember to use [!r].......[/r] to escape [ or ] in ori string

Improve3

AMConfigManager::GetClientConfig(conststd::string &nickname, bool use_compression)

remove use_compression, use_compression already defined in config now

Improve4

AMConfigManager::GetSettingString and 

intAMConfigManager::GetSettingInt

can be combined to a templete function

Improve5
UserPaths renamed to UserVars

both in code and setting.toml
Improve6
Add a BBCEscape function to escape like "[!r][Config][/r]"

Improve7

Move function positions, and place cli bind functions together

Improve8

CLI bind function must report error, just like Delete does
