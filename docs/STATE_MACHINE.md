# State Machine — simplechat v1

## States

| State | Meaning |
| --- | --- |
| `STARTING` | Process started; parsing CLI; allocating session object |
| `BOOTSTRAPPING` | Tor starting and/or Wormhole transfer in progress |
| `CONNECTING` | Waiting for peer TCP (host) or dialing onion (joiner) |
| `HANDSHAKING` | Public-key exchange / key derivation in progress |
| `VERIFYING` | Fingerprint shown; optional user verification |
| `ESTABLISHED` | Encrypted chat active |
| `CLOSING` | Teardown in progress |
| `CLOSED` | Terminal; no further transitions |

## Allowed Transitions

```
STARTING      → BOOTSTRAPPING | CLOSING
BOOTSTRAPPING → CONNECTING | CLOSING
CONNECTING    → HANDSHAKING | CLOSING
HANDSHAKING   → VERIFYING | CLOSING
VERIFYING     → ESTABLISHED | CLOSING
ESTABLISHED   → CLOSING
CLOSING       → CLOSED
CLOSED        → (none)
```

Any other transition is rejected and forces `CLOSING` → `CLOSED`.

## Event Triggers

| Event | Typical transition |
| --- | --- |
| Tor ready + Wormhole started | STARTING → BOOTSTRAPPING |
| Bundle sent/received | BOOTSTRAPPING → CONNECTING |
| TCP connected | CONNECTING → HANDSHAKING |
| Keys derived + fingerprint ready | HANDSHAKING → VERIFYING |
| User continues (verified or skip) | VERIFYING → ESTABLISHED |
| User quit / error / peer close | * → CLOSING → CLOSED |

## Invariants

- Crypto send/receive only in `ESTABLISHED` (handshake uses dedicated plaintext frame type).
- After entering `CLOSING`, no new plaintext is accepted from the UI.
- `CLOSED` destroys session key material; subsequent crypto ops raise errors.
