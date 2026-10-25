# End-to-End Encrypted Chat Application

## Overview
This is a hybrid end-to-end encrypted chat application built for DISS3110 Part II. The server acts only as a relay for ciphertext - it cannot read message contents.

## Encryption Design
- **Asymmetric**: Browser Web Crypto generates RSA-OAEP-2048 keys with SHA-256.
- **Symmetric**: Each message or file uses a fresh AES-256-GCM key and random 96-bit IV.
- **Key Wrapping**: The recipient's public key wraps the AES key with RSA-OAEP.
- **Key Handling**: The private key is non-exportable and kept in browser memory for that page session. It is not saved to localStorage.
- **Integrity**: AES-GCM authentication detects ciphertext or IV tampering.

## Features
- End-to-end encryption (server cannot decrypt)
- Real-time messaging via WebSocket
- Support for text messages
- Support for file/media sharing (encrypted)
- User presence
- Per-message encryption
- Non-corruption of encrypted files
- Public key exchange

## Security Scope and Limitations
- The relay handles encrypted message/file bytes and public keys; it has no private key or decryption operation.
- The demo does not authenticate public keys. A malicious server could substitute a public key and impersonate a participant.
- Per-message AES keys do not provide forward secrecy because the recipient's RSA private key is long-lived for the browser session.
- User identities and connection metadata are not authenticated; this is a local classroom demonstration, not a production messenger.
- Run only on a trusted machine/network. Do not expose the development server to the public internet.

## Running the Application

### Start server (Windows)
```bash
cd e2ee_chat
start_server.bat
```
Open http://127.0.0.1:5000/ in two browser windows. Each page session generates its own keys. Use the Flask-served page so the client, styles, and Socket.IO connection share one origin.

## Testing
1. Open two browser windows/tabs at http://127.0.0.1:5000/.
2. Choose a display name and generate keys in each tab.
3. Connect, select the other tab, and exchange messages or files up to 10 MiB.
4. The server relays the ciphertext; the recipient browser verifies/decrypts it.

The server listens only on loopback, has debug mode disabled, and rejects unregistered senders and oversized transfers. The chat is still a coursework prototype; it has not undergone a formal cryptographic or penetration review.
