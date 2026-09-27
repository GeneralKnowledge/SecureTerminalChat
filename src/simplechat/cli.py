"""CLI entry point: simplechat host | simplechat join <code>."""

from __future__ import annotations

import argparse
import logging
import sys


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="simplechat",
        description=(
            "Minimal secure peer-to-peer chat "
            "(Magic Wormhole bootstrap, Tor transport, X25519 + ChaCha20-Poly1305)."
        ),
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug logging (never logs cryptographic secrets).",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("host", help="Host a chat session and print a wormhole code")

    join = sub.add_parser("join", help="Join a chat session with a wormhole code")
    join.add_argument("code", help="Magic Wormhole code from the host")

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    # Keep third-party noise down unless debug
    if not args.debug:
        logging.getLogger("stem").setLevel(logging.WARNING)
        logging.getLogger("wormhole").setLevel(logging.WARNING)

    from simplechat.chat.runner import run_host, run_join

    if args.command == "host":
        return run_host()
    if args.command == "join":
        return run_join(args.code)
    parser.error(f"unknown command {args.command}")
    return 2


if __name__ == "__main__":
    sys.exit(main())
