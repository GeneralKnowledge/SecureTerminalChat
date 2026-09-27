"""CLI entry point: simplechat host | simplechat join <code>."""

from __future__ import annotations

import argparse
import logging
import sys

from simplechat.protocol.profile import SecurityProfile, parse_profile


def _add_profile_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--profile",
        choices=[p.value for p in SecurityProfile],
        default=SecurityProfile.TOR.value,
        help=(
            "Security profile: 'tor' (default; Wormhole+chat over Tor) or "
            "'direct' (clearnet Wormhole + plain TCP; IPs visible)."
        ),
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="simplechat",
        description=(
            "Minimal secure peer-to-peer chat "
            "(Magic Wormhole bootstrap, Tor or direct transport, "
            "X25519 + ChaCha20-Poly1305)."
        ),
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug logging (never logs cryptographic secrets).",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    host = sub.add_parser("host", help="Host a chat session and print a wormhole code")
    _add_profile_args(host)
    host.add_argument(
        "--advertise",
        metavar="HOST",
        help="Direct profile only: address to put in the bootstrap bundle "
        "(default: guessed local IPv4).",
    )
    host.add_argument(
        "--listen-port",
        type=int,
        default=0,
        metavar="PORT",
        help="Direct profile only: TCP listen port (0 = ephemeral).",
    )

    join = sub.add_parser("join", help="Join a chat session with a wormhole code")
    _add_profile_args(join)
    join.add_argument("code", help="Magic Wormhole code from the host")

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    if not args.debug:
        logging.getLogger("stem").setLevel(logging.WARNING)
        logging.getLogger("wormhole").setLevel(logging.WARNING)

    from simplechat.chat.runner import run_host, run_join

    profile = parse_profile(args.profile)

    if args.command == "host":
        if profile == SecurityProfile.TOR and (
            args.advertise is not None or args.listen_port != 0
        ):
            parser.error("--advertise/--listen-port only apply to --profile direct")
        return run_host(
            profile=profile,
            advertise=args.advertise,
            listen_port=args.listen_port,
        )
    if args.command == "join":
        return run_join(args.code, profile=profile)
    parser.error(f"unknown command {args.command}")
    return 2


if __name__ == "__main__":
    sys.exit(main())
