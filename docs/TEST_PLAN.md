# Test Plan — simplechat v1

## Unit: Cryptography

- [ ] X25519 agreement: both sides produce identical shared secrets
- [ ] HKDF: matching session keys for same shared secret
- [ ] Host/joiner derive opposite send/receive keys correctly
- [ ] Different sessions → different keys
- [ ] Fingerprint deterministic for same material
- [ ] Different material → different fingerprints
- [ ] Encrypt/decrypt round-trip
- [ ] Modified ciphertext rejected
- [ ] Modified AAD rejected
- [ ] Wrong key cannot decrypt
- [ ] Nonce/counter reuse prevented by API

## Unit: Replay

- [ ] First message (counter 0) accepted
- [ ] Duplicate counter rejected
- [ ] Old (lower) counter rejected
- [ ] Skipped counter rejected
- [ ] Very large counter rejected if not expected
- [ ] Counter overflow handling terminates
- [ ] Messages after session close rejected

## Unit: Framing

- [ ] Partial reads reassemble
- [ ] Multiple frames in one buffer
- [ ] Zero-length / undersized rejected
- [ ] Oversized rejected
- [ ] Malformed lengths rejected
- [ ] Truncated frames wait or fail cleanly
- [ ] Malformed ciphertext path fails closed

## Unit: State Machine

- [ ] Valid transitions succeed
- [ ] Invalid transitions rejected
- [ ] Terminal CLOSED has no outbound edges

## Integration

- [ ] In-process loopback: handshake + encrypted chat without Tor
- [ ] Two-thread/process local socket peer test with plaintext round-trip
- [ ] Optional live test (skip if no Tor/network): Wormhole + Tor + chat

## Logging Safety

- [ ] Debug logger does not emit key material in crypto paths (spot checks)
