# Interrupt Bug

(base)D:\CodeLib\CPP\AMSFTP\build\win-clang-debug $ .\amsftp.exe bash
Init time: 3ms
󰨡 am@localhost  -  ✅
(local)C:/Users/am $ walk .
Signal Triggered: 2
iwalk interrupted by user
󰨡 am@localhost  301ms  ❌ Terminate
(local)C:/Users/am $
󰨡 am@localhost  301ms  ❌ Terminate
(local)C:/Users/am $
󰨡 am@localhost  301ms  ❌ Terminate
(local)C:/Users/am $
󰨡 am@localhost  301ms  ❌ Terminate
(local)C:/Users/am $
󰨡 am@localhost  301ms  ❌ Terminate
(local)C:/Users/am $ walk .
 am@AM-Laptop c-cli                                                    3.10.16 ❌ -1073741510 ⏳ 16s  56%[12/22GB] 🕜09:09:00

Ctrl-C Interupt has severe problem, when you interupt a function for th first time, it's ok and exit normally. but if you interupt another function or this function again, the app exit with -1073741510
