
Extra Improve

Grammer Extend

+ support ${zone:varname}
+ : is still invalid char for zone name or varname, but permit in parse cause it's viewed as operator

Highlight Demand

+ the "{}" of var should has style its too(set in [Style.InputHighlight])
+ $zone:varname  zone use nickname style  : use single style(set in [Style.InputHighlight]) varname use varname style

Complete Demand

+ if no : char, complete source is current zone and public zone's varname
+ if has : char, complete source is target zone's varname
+ pay attention to support for ${xxxxxx like prefix
  + current complete seems not to support this prefix
  + you should add } when fill in like complete hostname target in path arg
