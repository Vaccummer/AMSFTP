@src\manager\config\manager.cpp

we're going to remove most AMConfigManager functions, but some functions in it need to be moved and implemented somewhere else

implement FindKnownHost in AMConfigCoreData

implement PrivateKeys in AMConfigCoreData (remove boolprint_sign, just return keys)

implement UpsertKnownHost in AMConfigCoreData

remain BuildKnownHostCallback

implement GetClientConfig in AMConfigCoreData

move uservar related functions to AMConfigCoreData
