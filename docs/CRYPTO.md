# Cryptographic Design — simplechat v1

## Libraries

| Purpose | Library / API |
| --- | --- |
| X25519 ECDH | PyNaCl `nacl.public.PrivateKey` / `PublicKey` (libsodium) |
| ChaCha20-Poly1305 IETF | PyNaCl bindings `crypto_aead_chacha20poly1305_ietf_*` |
| HKDF-SHA256 | `cryptography.hazmat.primitives.kdf.hkdf.HKDF` |
| Fingerprint hash | `hashlib.sha256` (stdlib) after HKDF extract of fp material |
| Secure wipe (best-effort) | overwrite `bytearray` then release references |

**Decision:** Magic Wormhole already depends on `cryptography`. Using its HKDF
avoids hand-rolling RFC 5869 while keeping the dependency set small. PyNaCl’s
`SecretBox` is XSalsa20-Poly1305; the requirement is ChaCha20-Poly1305, so we use
libsodium’s IETF AEAD bindings via PyNaCl rather than SecretBox.

## X25519

```
local = PrivateKey.generate()          # 32-byte sk, 32-byte pk
shared = Box(local, PublicKey(peer_pk)).shared_key()
# equivalently: crypto_scalarmult(sk, peer_pk) → 32 bytes
```

Private keys never leave the crypto module; never logged; never persisted.

## KDF (HKDF-SHA256)

```
CONTEXT = b"simplechat-v1"

# Extract-then-expand conceptually via HKDF with distinct info strings:

host_to_joiner_key = HKDF(
    algorithm=SHA256(), length=32, salt=None,
    info=CONTEXT + b"|host-to-joiner"
).derive(shared_secret)

joiner_to_host_key = HKDF(
    algorithm=SHA256(), length=32, salt=None,
    info=CONTEXT + b"|joiner-to-host"
).derive(shared_secret)

fingerprint_key = HKDF(
    algorithm=SHA256(), length=32, salt=None,
    info=CONTEXT + b"|fingerprint"
).derive(shared_secret)
```

Role mapping:

| Role | send_key | receive_key |
| --- | --- | --- |
| Host | `host_to_joiner_key` | `joiner_to_host_key` |
| Joiner | `joiner_to_host_key` | `host_to_joiner_key` |

Both peers derive identical directional keys from the same `shared_secret`.

## Fingerprint

```
digest = SHA256(CONTEXT + b"|fingerprint-display" + fingerprint_key)
# display first 6 bytes as hex pairs grouped:
# XX XX XX XX XX XX → XXXX-XXXX-XXXX (uppercase)
```

Domain separation is explicit (`CONTEXT` and distinct HKDF info / display label).
Do not truncate the raw shared secret for display.

## AEAD

- Algorithm: ChaCha20-Poly1305 IETF (12-byte nonce, 16-byte tag).
- Nonce: `counter.to_bytes(12, "big")` — unique per (key, counter).
- AAD: `version || type || direction || counter_be64`.
- Reject decryption failures without returning plaintext.
- Implementation refuses to encrypt if nonce/counter would reuse.

## Replay / Counter Design

Per direction:

```
send_counter    starts at 0; increments after each successful encrypt+send
recv_expected   starts at 0
```

Accept rule (strict):

```
if received_counter != recv_expected: reject / terminate
else: process; recv_expected += 1
```

- Duplicates rejected
- Old counters rejected
- Skipped counters rejected (no sliding window in v1)
- Counter max: `2^64 - 1`; overflow → terminate session
- After session close, all further messages rejected

Lost messages → terminate and re-establish a new session rather than recover.

## Key Destruction

On `CLOSING` / `CLOSED`:

1. Overwrite key `bytearray`s with zeros.
2. Drop references to `PrivateKey` / session objects.
3. Best-effort only; Python GC and OS swap are residual risks (documented).

## Security decisions (v1)

| Decision | Choice | Rationale |
| --- | --- | --- |
| AEAD | ChaCha20-Poly1305 IETF via PyNaCl bindings | Requirement; not SecretBox (XSalsa20) |
| KDF | HKDF-SHA256 via `cryptography` | Established API; already a Wormhole dependency |
| Bootstrap transport | `wormhole` CLI subprocess | Avoids Twisted reactor reuse; auditable boundary |
| Replay window | Strict expected-counter only | Simplicity; fail closed on loss |
| Ratcheting | None | Session-level FS only; documented limitation |
