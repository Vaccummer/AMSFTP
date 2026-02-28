Unify and normalize the use of TaskControlToken

ControlSignal :{Running = 0, Pause = 1, Interupt=SIGINT, Kill=SIGTERM}

remove this overload boolTerminate(std::optional `<int>` signal)

remove GetSignal()

remove interrupted_  killed_  state_

signal_ == SIGINT -> interrupted ; signal_ == SIGTERM -> killed

remove check(), use IsRunning()

remove set(), add SetStatus(ControlSignal)

rename iskill to IsKill()  

remove reset() kill()
