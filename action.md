# Add  New TaskStatus: Paused

the add of new status Paused will result in greate change in AMWorkManager

General Desctiption

1. TaskStatus: :Paused set when call TaskStatus.pause() on Conducting task
2. when a task is paused, it will be offloaded from current task

   1. you can change WkProgressData::is_terminate to below and tell it from terminate by reading exact control_sign value

   control_sign.load(std::memory_order_acquire) !=

   static_cast `<int>`(ControlSignal::Running);

   1. keep related data for resuming by breakpoint mechanism
3. A task is pause won't be assigned to any thread
4. when call resume() on a paused task, set task status to Pending and wait for assigning

remember when conduct ever paused task, don't overwrite its starting time. you can set a sign in TaskInfo to skip starting time set
