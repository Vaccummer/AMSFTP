@src\manager\host\core.cpp

write a check func in namespace configkn to check whether a given string is valid for certain host attr,  use a enum to decide which attr

add check func in AMHostManager::PromptAddFields_ and AMHostManager::PromptModifyFields_
in AMHostManager::PromptAddFields_, if an attr has default value, set default as placeholder
