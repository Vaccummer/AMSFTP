ProgressBar render improvement

now i need to progressbar class Independent of indicators and render bar itself

[Style.ProgressBar] in settings.toml

progressbar init with such style config, and supplies interface to set total and start trace

+ style config holds interval and refresh_interval_ms, then calculate the window_size, min is 1

the protocol is

1. set total and start
   + start will set internal steady clock
2. collect args required and call render (args include src/dst hostname and filename, transferred, total)
   2.1 calculate percentage, add transferred to window deque and calculate speed and format it, calculate elapse time
   2.2 intepreter bar_template to real string
   2.3 get terminal width, minus offset, then get width for prefix(if <=0 direct return bar string)
   2.4 intepreter prefix_template and truncate with hint width or padding to hint width
3. join two part and return
