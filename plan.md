
@config\settings.toml

redesign ClientAppService completely:

1. inheritage relationship: no derived, parent, impl.
2. constructor: need struct ClientServiceArg (you can refer to setting.toml [Options.ClientManager])
3. important attrs

3.1 unique_ptr`<IClientMaintainerPort>`, create func is defined in client port header, use args in ClientServiceArg to construct it

3.2 ClientContainer: std::map<nickname, std::map<ID, clienthandle>>, transfer clients public pool, no heartbeat

3.3 ClientHandle local_client_

3.4 ClientHandle current_client_

3.5 all kinds of callbacks: disconnect/trace/auth/know_host

3.6 controltokenport 

4. important functions

4.1 ClientServiceArg GetInitArg() fetch back args and wrap into ClientServiceArg

4.2 ClientHandle GetClient(nickname)

4.2 ClientHandle GetCurrentClient()

4.3 nickname GetCurrentNickname()

4.4 pair<ECM, ClientHandle> CreateClient(HostConfig) create client, bind callbacks, but don't add to maintainer

4.5 ECM AddClient(ClientHandle, force overwrite) add to maintainer, maintainer recieve only one client per nickname, so use overwrite can replace if already exists one

4.6 ClientState CheckClient(nickname, bool reconnect, bool update) reconnect means if wrong, reconnect the client, update means don't use state cache, use realtime result instead(use UpdateOSType)

4.7 std::map `<nickname, ClientHandle>` GetClients()

4.8 ECM RemoveClient(nickname)

4.9 pair<ECM, ClientHandle> GetPublicClient(nickname) get client from ClientContainer, use nickname to find client, then check, if error, remove from container, find next client until no client found

4.10 AddPublicClient(ClientHandle) add client to container, no check, directly put in

4.11 SetPublicClientCallback(optional `<disconnectcb>`, optional `<trace_cb>`, optional<know_host_cb>, optional `<auth_cb>`): nullopt -> remain same, if has value, set to it
