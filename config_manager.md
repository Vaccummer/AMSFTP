# Config Processor

config format is defined in config.yaml

processor main function

1. read config.yaml, ouput a flattened std::map type
2. you have to return a value like {{key1, key2, key3}, value}
   for example {{"hosts", "wsl", "username"}, "am"}, {{"private_keys"}, {"C:\Users\am\.ssh\id_rsa", "C:\Users\am\.ssh\id_ed25519"}}, the value type can be int, bool, str, vector `<string>`

improve

1. add a filter function to filter illegal keys, I provide some format like
   {"hosts","*", "username"}, {"private_keys"}, any key has different length will be aborted,
   any key not match the format will be aborted, if a string in format has ^or$, it means use regex
2. add a query function to get value of certain key
3. add a modify function to change certain value
4. add a dump function to write the map back to yaml file
