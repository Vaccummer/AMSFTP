what do you think of plan blow

@src\cli\completer\engine_worker.cpp

remove AMCompletionToken, use AMTokenTypeAnalyzer::AMToken

AMCompleteEngine::BuildContext_ Improve

My expected protocol:

1. use AMTokenTypeAnalyzer::SplitToken to split
2. analyse short-hand expression (independent flow, won't go on with the protocol)
3. get module and cmd option( exclude named arg)
   1. module and cmd must be determined first, all other tokens are invalid, and will cause abort in completion
      1. but if this is the first nonempty token, complete module/top cmd
      2. if this is the first nonempty token after valid module, complete its cmds
   2. option must be valid for the cmd, if option is not exist, will be viewed as arg, but allow duplicate
      1. -ov if o exists but v not,  viewed as arg
   3. named arg only suport expression like: -n value; --name value; --name=value
      1. ilegal expression viewed as arg
   4. ilegal arg like token will be viewed as arg, but won't stop option parse
4. find where cursor is, get prefix and postfix
5. get AMCommandArgSemantic according to module, cmd, option record and any other neccessary context
6. transit AMCommandArgSemantic to targets according to prefix and any other neccessary context
