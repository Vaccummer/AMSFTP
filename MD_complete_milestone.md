  Assumptions to Confirm

1. Remote completion triggers only for nickname@path (no bare /path or @path).
   1. for bare path, if current client is not local, it triggers remote completion
   2. @path is local, don't trigger
2. No auto-connect on Tab; only currently connected clients are used.
   1. yes
3. Async completion does not auto-refresh the menu; user hits Tab again to see cached results.
   1. show menu automatically, tab is for swtiching to another page
