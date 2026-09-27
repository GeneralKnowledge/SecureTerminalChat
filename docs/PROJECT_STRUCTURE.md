# Project Structure — simplechat v1

```
simplechat/
├── docs/
│   ├── THREAT_MODEL.md
│   ├── PROTOCOL.md
│   ├── STATE_MACHINE.md
│   ├── FRAME_FORMAT.md
│   ├── CRYPTO.md
│   ├── DEPENDENCIES.md
│   ├── TEST_PLAN.md
│   ├── SECURITY.md
│   └── PROJECT_STRUCTURE.md
├── src/simplechat/
│   ├── __init__.py
│   ├── __main__.py
│   ├── cli.py
│   ├── bootstrap/
│   │   └── wormhole_bootstrap.py
│   ├── transport/
│   │   └── tor_transport.py
│   ├── crypto/
│   │   ├── agreement.py
│   │   ├── kdf.py
│   │   ├── aead.py
│   │   ├── fingerprint.py
│   │   └── wipe.py
│   ├── protocol/
│   │   ├── constants.py
│   │   ├── framing.py
│   │   ├── counters.py
│   │   ├── handshake.py
│   │   ├── state.py
│   │   └── session.py
│   └── chat/
│       ├── ui.py
│       └── runner.py
├── tests/
│   ├── test_crypto.py
│   ├── test_aead.py
│   ├── test_counters.py
│   ├── test_framing.py
│   ├── test_state.py
│   ├── test_fingerprint.py
│   ├── test_handshake.py
│   └── test_integration_loopback.py
├── pyproject.toml
├── README.md
└── LICENSE
```

Layering rule: `chat/` → `protocol/` → `crypto/` + `transport/` + `bootstrap/`.
UI never imports AEAD/X25519 primitives directly.
