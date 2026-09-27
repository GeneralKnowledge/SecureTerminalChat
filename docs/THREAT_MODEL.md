# Threat Model — simplechat v1

## Scope

simplechat v1 is a minimal peer-to-peer CLI chat. Peers bootstrap via Magic Wormhole,
communicate over Tor onion services, agree on an ephemeral X25519 session key, and
exchange ChaCha20-Poly1305 encrypted messages.

This is **not** a Signal replacement. There is no Double Ratchet, no long-term
identity keys, and no persistent accounts.

## Assets

| Asset | Protection goal |
| --- | --- |
| Chat plaintext | Confidentiality; never logged |
| Ephemeral X25519 private keys | Never leave process; never persist; wiped on close |
| Derived session keys | Same as above |
| Bootstrap bundle (onion address + host public key) | Integrity via Wormhole PAKE; confidentiality of rendezvous |
| Message integrity / ordering | AEAD + strict counters |

## Adversaries Considered

1. **Passive network observer** on the clearnet path toward Tor relays
2. **Active network attacker** who can modify or replay Tor-exit / onion traffic they can reach
3. **Attacker with recorded prior-session ciphertext** who later obtains no endpoint keys
4. **Malicious peer** (application-level abuse is out of scope; crypto still binds messages)

## What v1 Protects Against

- Passive observers of Tor transport cannot read chat plaintext (AEAD confidentiality).
- Modification of encrypted messages is detected (Poly1305 authentication).
- Replay of previously accepted messages is rejected (strict monotonic counters).
- Compromise of a *previous* session’s captured traffic does not decrypt that session
  after ephemeral keys are destroyed (session-level forward secrecy).
- Bootstrap eavesdroppers without the Wormhole code cannot easily obtain the onion
  address and host ephemeral public key (Wormhole PAKE properties).

## What v1 Does NOT Protect Against

- Malware on either endpoint
- Compromised operating system / keyloggers
- Compromised Tor infrastructure (directory authorities, malicious relays enabling
  traffic analysis beyond Tor’s own guarantees)
- Compromised cryptographic libraries (PyNaCl / libsodium, cryptography, Stem, Wormhole)
- An attacker controlling a user’s device
- Future compromise of an endpoint *during* an active session (no PCS / no ratchet)
- Traffic-analysis attacks beyond what Tor itself provides
- A malicious peer sending application-level abuse (spam, social engineering)
- Proof that the peer’s device is free of malware (fingerprint verification only
  confirms matching session material over an out-of-band channel)

## Trust Boundaries

```
[User CLI] → [chat/] → [protocol/] → [crypto/]
                              ↓
                         [transport/Tor]
                              ↓
                         [bootstrap/Wormhole]  (session setup only)
```

- The chat UI never calls crypto primitives directly.
- Private keys never cross into bootstrap, transport, or UI layers.
- Wormhole carries only the bootstrap bundle; never chat plaintext.

## Residual Risks

- If the Wormhole code is leaked before the join completes, an attacker may obtain
  the onion address and host public key and attempt to connect first.
- Strict counter semantics mean a lost frame ends the session (fail closed).
- Fingerprint verification is optional; unverified sessions are clearly labeled.
