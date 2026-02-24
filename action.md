@config\settings.toml

I changed [Style.Prompt] to [Style.CLIPrompt]

i add [Style.ValueQueryHighlight] for latter use

@src\manager\prompt\prompt.cpp

PromptManager::Prompt Improve

PromptManager::Prompt is used for query user's input for some arg's value
  it have brand-new complete and highlight from CorePrompt

Extra Args: 

+ checker: bool(std::string)
+ candidates: vector `<string>`

checker is a func to judge whether input is valid: use style in Style.ValueQueryHighlight

candidates is the complete source

checker and candidates both could be empty
