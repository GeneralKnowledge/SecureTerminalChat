# Message and Frame Format — simplechat v1

## Transport Framing

All messages on the Tor TCP stream use length-prefixed framing:

```
offset  size   field
0       4      length   uint32 big-endian  (= number of bytes following this field)
4       length body
```

### Body Layout

```
offset  size   field
0       1      version       uint8   (= 1)
1       1      message_type  uint8
2       8      counter       uint64 big-endian
10      n      payload       bytes
```

So `length = 1 + 1 + 8 + len(payload) = 10 + len(payload)`.

### Limits

| Limit | Value | Rationale |
| --- | --- | --- |
| `MAX_FRAME_BODY` | 65536 | Cap peer-controlled allocations |
| `MAX_PLAINTEXT` | 32768 | Chat text / handshake payload bound |
| `MIN_FRAME_BODY` | 10 | version + type + counter with empty payload |

Rules:

- Reject `length == 0`, `length < MIN_FRAME_BODY`, `length > MAX_FRAME_BODY`.
- Handle partial TCP reads; buffer until a full frame is available.
- Handle multiple frames in one read.
- Never allocate based on an unchecked length.

## Message Types

| Value | Name | When | Payload |
| --- | --- | --- | --- |
| `0x01` | `HANDSHAKE` | Joiner → Host once | 32-byte raw X25519 public key |
| `0x02` | `CHAT` | Either direction after ESTABLISHED | ChaCha20-Poly1305 ciphertext (nonce ‖ ct‖tag layout per crypto module) |
| `0x03` | `CLOSE` | Either direction | Empty ciphertext/payload allowed |
| `0x04` | `VERIFY` | Optional notify | 1 byte: `0x00` unverified, `0x01` verified |

Unknown types → terminate connection.

## Encrypted Chat Payload (`CHAT`)

Ciphertext format (inside frame payload):

```
12 bytes  nonce
rest      ciphertext || 16-byte Poly1305 tag
  (as returned by crypto_aead_chacha20poly1305_ietf_encrypt)
```

**Associated data (AAD), authenticated but not encrypted:**

```
aad = version || message_type || direction || counter_be64
```

Where `direction` is one byte:

| Value | Meaning |
| --- | --- |
| `0x01` | host → joiner |
| `0x02` | joiner → host |

Nonce construction (no reuse with same key):

```
nonce = counter.to_bytes(12, "big")
```

Directional keys ensure host→joiner and joiner→host never share a keystream.
Each direction’s counter starts at `0` and increments by `1` per sent message.

## Handshake Payload

Unencrypted (public key material only):

```
payload = 32-byte X25519 public key (raw)
```

`counter` for the handshake frame MUST be `0`. Host rejects otherwise.

## Bootstrap Bundle (Wormhole, not Tor-framed)

JSON object documented in `PROTOCOL.md`. Validated before any Tor connect.
