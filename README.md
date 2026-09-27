# Minimal Secure Python Chat (simplechat)

Peer-to-peer CLI chat with:

1. **Magic Wormhole over Tor** — bootstrap only (onion address + host ephemeral public key); rendezvous via the session Tor, not clearnet
2. **Tor** — ephemeral onion transport for all chat traffic
3. **X25519** — ephemeral session key agreement (PyNaCl / libsodium)
4. **ChaCha20-Poly1305** — authenticated encryption (IETF AEAD via PyNaCl)
5. **HKDF-SHA256** — directional session keys with domain separation (`simplechat-v1`)

Designed to be small, boring, explicit, testable, and auditable.

## Quick start

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"

# Requires `tor` on PATH for real sessions
simplechat host
# → share the wormhole code

simplechat join 7-example-code-here
```

## Security properties (v1)

**Provides:** confidentiality, integrity, session-level forward secrecy, strict
replay protection, optional fingerprint verification, no long-term identity,
no central message store. Bootstrap and chat both use Tor so peers’ clearnet
IPs are not exposed to each other or to the Wormhole relay.

**Does not provide:** post-compromise security, per-message forward secrecy
(no Double Ratchet), protection against endpoint malware, anonymity against a
global traffic-analysis adversary, or hiding that a Wormhole transfer occurred
(mailbox still sees appid/timing).

See `docs/` for the full threat model, protocol specification, and limitations.

## Development

```bash
pytest -m "not live"
```

## Project layout

See `docs/PROJECT_STRUCTURE.md`. Layering: `chat/` → `protocol/` → `crypto/` +
`transport/` + `bootstrap/`. The UI never calls crypto primitives directly.
