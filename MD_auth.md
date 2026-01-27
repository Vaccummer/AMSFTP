## Authentication Enhancement: Password Handling Upgrade

### Core Design

- Set up a **fixed compile-time key** for encrypting passwords in configuration storage
- **Decrypt only at the moment of authentication** when passing credentials to libssh2/FTP libraries
- Implement a **privacy-aware input function** for auth callbacks (masked input, e.g., `••••••`)

### AuthCBInfo Structure Redesign

```cpp
struct AuthCBInfo {
    bool          NeedPassword;   // Whether password is required
    ConnRequest   request;        // Connection request context
    bool          isPass;         // true = password auth, false = key-based auth
};
```

### Unified Callback Mechanism

Callbacks shall be triggered for **all authentication outcomes**:

- ✅ **Success**: Password accepted
- ❌ **Failure**: Incorrect password
- ❔ **Prompt**: Password required

### Password Callback Implementation (in ClientManager)

All user-interaction operations **must be thread-safe** (mutex protected). Callback messages:

| Scenario                         | Message Format                                                                                                               |
| -------------------------------- | ---------------------------------------------------------------------------------------------------------------------------- |
| **Password required**      | `❔ [{client}] Require Password: ` *(followed by masked input)*                                                          |
| **Wrong password**         | `❌ [{client}] Wrong Password!`                                                                                            |
| **Authentication success** | `✅ [{client}] Password authorization successful!<br>`→ *Simultaneously persist the new password to config (encrypted)* |

### Security Notes

- Passwords remain **encrypted at rest** in config files
- Decryption occurs **only in memory** during authentication handshake
- Memory holding plaintext passwords **must be zeroed immediately** after use
- Privacy input ensures passwords are **never displayed** during entry
