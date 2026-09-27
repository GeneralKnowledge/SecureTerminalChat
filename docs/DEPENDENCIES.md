# Dependency Review — simplechat v1

## Direct Dependencies

| Package | Purpose | Justification |
| --- | --- | --- |
| `pynacl` | X25519, ChaCha20-Poly1305 IETF | libsodium bindings; do not implement crypto |
| `stem` | Launch/control Tor, ephemeral onion services | Standard Tor controller library |
| `magic-wormhole` | Bootstrap bundle transfer **over Tor** | PAKE rendezvous; CLI invoked with `--tor` + session control port |
| `cryptography` | HKDF-SHA256 | Established KDF API; already pulled in by Wormhole |

## Standard Library

`argparse`, `asyncio`/`socket`, `json`, `hashlib`, `hmac`, `struct`, `logging`,
`dataclasses`, `enum`, `typing`, `base64`, `secrets`, `sys`, `threading`.

## Explicitly Rejected

- Web frameworks, databases, brokers, cloud SDKs
- Custom TLS stacks or hand-rolled ciphers
- Docker as a runtime requirement for v1
- GUI frameworks until CLI protocol is complete

## System Requirements

- Python ≥ 3.11
- Tor binary on `PATH` (or configurable path) for real peer sessions
- Network access for Wormhole mailbox and Tor

## Test Dependencies

| Package | Purpose |
| --- | --- |
| `pytest` | Unit / integration tests |
| `pytest-timeout` | Prevent hung Tor/Wormhole tests |

## Security Notes

- Pin major versions in `pyproject.toml`; prefer audited releases.
- Debug logging must never print keys, secrets, plaintext, auth tags, or Wormhole
  transit secrets.
