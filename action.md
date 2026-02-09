AMTransferManager::Show now accept multi taskids

1. remove duplicated ids
2. check ids exists, prompt error if id not valid
3. print non-conducting tasks in a table
4. print conducting tasks(include paused) in porgressbar(1 bar per task)

AMTransferManager::List: print all task in table format(even conducting)

+ if possible, dynamic update conducting task info just like nvidia-smi
  + if implement such feature, set a sign for Pint in PromptManager to cache print string

# Table Keys

(use - for key not suits current status)

id 

status(Pending, Paused,Conducting, Finished)(also task display order)

Elapsed(From conducting point till now)

Files (success_filenum/filenum)

Size(transferred/total)

ThreadID
