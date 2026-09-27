# Security Assumptions and Known Limitations — simplechat v1

## Assumptions

1. Endpoints run untampered Python and dependencies on a trustworthy OS for the
   duration of the session.
2. The Tor binary and Stem control port interaction are available and honest.
3. Magic Wormhole’s PAKE and mailbox behave as documented; the wormhole code is
   conveyed to the joiner over a channel the user considers adequate for bootstrap.
4. libsodium (via PyNaCl) and `cryptography`’s HKDF are correct.
5. Users who enable fingerprint verification compare codes on a separate channel
   not controlled by the same network attacker of interest.

## Known Limitations

| Limitation | Impact |
| --- | --- |
| No Double Ratchet | No PCS; no per-message forward secrecy within a session |
| No long-term identities | Cannot authenticate a peer across sessions without out-of-band fingerprint check each time |
| Strict counters | Packet loss ends the session |
| Best-effort key wipe | GC/swap may retain remnants |
| Optional verification | Unverified sessions are vulnerable to Wormhole-code theft MITM before connect |
| Tor traffic analysis | Not mitigated beyond Tor itself |
| Endpoint malware | Out of scope |

## Claims We Do Not Make

- That fingerprint verification proves a clean device
- That v1 is anonymous against a global passive adversary beyond Tor’s model
- That v1 replaces Signal, TLS, or Tor Browser hardening
