Refactor terminal and channel related codes to current structure:

1. ports
   include terminal port and channel port, both are abstract classes
   defines interfaces signatures
   in domain layer
   Channel Port: supplies all kinds of interfaces that operate on channels iteself, for example: read, write,close, read_write loop

   Terminal port: supplies interfaces to manage channels, for example: create, remove, rename channels, or get channel name list
   some terminal port interfaces may rely on channel port, like: terminal->remove relies on channel->close. terminal->rename will change channel name related attr
2. implemention

in infra layer, includes three parts:

1. libssh2 implemention, implement terminal port and channel port with libssh2
2. local implemention, implemention ports with local terminal
3. some shared helper functions or classes
   ps: intermeidiate class like CachedChannelPort is not allowed now
