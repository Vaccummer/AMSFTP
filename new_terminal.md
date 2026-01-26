 @include/AMCleint/AMSFTPClient.hpp

There's already Safechannel and ConductCmd function, improve them

I abort terminal plan, but my app still offers limitted support for command conduct  

I need client can conduct certain cmd in remote server, and user can terminate cmd all the time.

but terminate in different stages result in different actions

+ before cmd sent, just exit with opeation aborted info
+ before msg recieved, cancel conduct and send exit cmd to server
+ before status code got, set code to -1 and return

Whenever exit, must ganrantee server process end and channel closed
