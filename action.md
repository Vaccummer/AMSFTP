+ Bug1: error in process ..

(local)D:/CodeLib/Go/learn/pkg1 $ cd ../..
❌ cd: Invalid empty path

(wsl)/home/am/250415/250414 $ cd ../../1
 am@172.26.36.83  5ms  ✅

+ Improve1: tab effect adjust

when in editor mode:  if has only one match, don't show menu just fill in that match

+ Improve2: unify path sep

In this programm, we unify path sep to /  regardless of OS type

(local)D:/CodeLib $ ls ./
  1 a.json            5 Configs\          9 Powershell\      13 Rust
  2 CPP\              6 Cursor\          10 Projects\        14 SuperLauncher
  3 CS\               7 Go\              11 Pwsh_Scripts\    15 data
  4 C\                8 Launcher_New\    12 Python\          16 trash\

+ Bug2: Still has problem in resolving . and ..

(wsl)/home/am $ cd ./250415/250414/
 am@172.26.36.83  5ms  ✅
(wsl)250415/250414 $ ls
2.MP4                         6.MP4
250414.mp4                    7.MP4
3.MP4                         未命名.prproj
4.MP4                         试验.MP4
5.MP4                         Adobe Premiere Pro Auto-Save
 am@172.26.36.83  9ms  ✅
(wsl)250415/250414 $ cd ..
 am@172.26.36.83  6ms  ✅
(wsl)250415/250414/250415 $ ls
Open directory {path} failed: File does not exist
 am@172.26.36.83  7ms  ❌ FileNotExist


(local)D:/ $ cd ./codelib
❌ cd: Path not found: codelib
󰨡 am@localhost  6ms  ❌ PathNotExist
(local)D:/ $ cd codelib
󰨡 am@localhost  6ms  ✅
(local)D:/CodeLib $
