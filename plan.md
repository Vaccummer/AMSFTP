
ExecuteTerminalSession_ is so complicated, you reafactor it to a class, split original codes to multi interfaces:

1. one dedicated thread to monitor user keyboard strike
2. terminal, channel check
