"""Protocol constants for simplechat v1."""

from __future__ import annotations

PROTOCOL_NAME = "simplechat"
PROTOCOL_VERSION = 1
CONTEXT = b"simplechat-v1"

# Frame limits
MAX_FRAME_BODY = 65536
MAX_PLAINTEXT = 32768
MIN_FRAME_BODY = 10  # version + type + counter
LENGTH_PREFIX_SIZE = 4

# Message types
MSG_HANDSHAKE = 0x01
MSG_CHAT = 0x02
MSG_CLOSE = 0x03
MSG_VERIFY = 0x04

# Direction bytes (AAD)
DIR_HOST_TO_JOINER = 0x01
DIR_JOINER_TO_HOST = 0x02

# Onion defaults
DEFAULT_ONION_PORT = 9400

# AEAD
NONCE_SIZE = 12
TAG_SIZE = 16
KEY_SIZE = 32
PUBKEY_SIZE = 32

# Counter
COUNTER_MAX = (1 << 64) - 1
