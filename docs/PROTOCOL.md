# Protocol Specification — simplechat v1

## Protocol Identifier

```
PROTOCOL_NAME    = "simplechat"
PROTOCOL_VERSION = 1
CONTEXT          = "simplechat-v1"
```

Any unexpected `protocol_version` in bootstrap or frames causes immediate session
termination.

## Roles

| Role | CLI | Responsibilities |
| --- | --- | --- |
| Host | `simplechat host` | Tor onion service, Wormhole send, wait for join, accept joiner pubkey |
| Joiner | `simplechat join <code>` | Wormhole receive, Tor connect, send joiner pubkey |

## Session Establishment

### Host

1. Start ephemeral Tor (Stem-managed).
2. Publish ephemeral onion service on a fixed local port.
3. Generate ephemeral X25519 keypair `(H_sk, H_pk)`. Keep `H_sk` local only.
4. Build bootstrap bundle (JSON, UTF-8):

```json
{
  "protocol": "simplechat",
  "protocol_version": 1,
  "onion_address": "<56-char-v3-onion>.onion",
  "onion_port": 9400,
  "host_ephemeral_public_key": "<base64 32-byte X25519 public key>"
}
```

5. Transfer bundle via Magic Wormhole (`send`).
6. Display wormhole code; wait for inbound Tor TCP connection.
7. Read joiner handshake frame containing joiner public key.
8. Perform key agreement; enter VERIFYING / ESTABLISHED.

### Joiner

1. Receive and validate bootstrap bundle via Wormhole (`receive`).
2. Validate `protocol`, `protocol_version`, onion address form, port range, pubkey length.
3. Generate ephemeral X25519 keypair `(J_sk, J_pk)`. Keep `J_sk` local only.
4. Connect to `onion_address:onion_port` through Tor SOCKS.
5. Send handshake frame with `J_pk`.
6. Perform key agreement; enter VERIFYING / ESTABLISHED.

## Key Agreement

```
shared_secret = X25519(local_sk, peer_pk)   # 32 bytes (Curve25519 ECDH)
```

Never use `shared_secret` directly as an encryption key. Derive directional keys
and fingerprint material via HKDF-SHA256 (see `docs/CRYPTO.md`).

Both peers must obtain the same `shared_secret` and therefore the same derived keys.

## Forward Secrecy (Session-Level Only)

- Fresh X25519 keypair per session; never reused across sessions.
- Private keys and session keys never written to disk.
- On session close, sensitive material is overwritten where practical.

**v1 provides forward secrecy between sessions, but does not provide post-compromise
security or per-message forward secrecy.** There is one session encryption key pair
(directional) for the lifetime of the session. A ratcheting design is out of scope.

## Mutual Verification (Optional)

After key agreement both peers compute a fingerprint (see CRYPTO.md) and display:

```
Fingerprint: 7F3A-91C2-44D8
Compare this fingerprint with your peer over a separate trusted channel.
Identity verification: NOT VERIFIED
```

User may mark verified if fingerprints match. Chat works without verification;
UI must state that peer identity has not been independently verified.

Fingerprint match does **not** prove absence of malware or device compromise.

## Encrypted Chat

After ESTABLISHED, all chat payloads use ChaCha20-Poly1305 (IETF). Each message
binds `version`, `message_type`, `direction`, and `counter` as AAD.

## Session Teardown

On close (user quit, protocol error, crypto failure, Tor failure):

1. Stop accepting new messages.
2. Close TCP connection.
3. Wipe ephemeral crypto material.
4. Shut down onion service / Tor if owned by this session.
5. Transition to CLOSED and exit.

Fail closed: never silently reset security state after cryptographic failure.
