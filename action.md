@src\manager\Prompt.cpp

@include\AMManager\Config.hpp

set AMPromptManager's base class AMHistoryManager

move history operation from AMPromptManager to its Base Class AMHistoryManager

move functions in ConfigManager to AMHistoryManager

+ ECM LoadHistory();
+ ECM GetHistoryCommands(conststd::string&nickname, std::vector[std::string](std::string) *out);
+ ECMSetHistoryCommands(conststd::string&nickname, conststd::vector[std::string](std::string) &commands, booldump_now = true)
