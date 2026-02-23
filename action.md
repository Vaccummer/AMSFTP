# BindHelper Class

AddFunction(str name, str help)

AddFlag(str short_name,str long_name, str help)

AddOption(str short_name,str long_name, size_t min_num, size_t max_num, AMCommandArgSemantic)

all add function return a node that record CLI11::APP ptr, CommandNode ptr, parent func name
