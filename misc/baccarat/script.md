from __future__ import annotations

import argparse
import json
import os
import re
import socket
import ssl
import sys

from game import (
    load_banker_agents,
    load_player_agents,
    simulate_pairing,
)

BASE_SEED = 20250311
RESOLVED_ROUNDS_PER_PAIRING = 10000
TARGET_BANKROLL = 100000
KELLY_FRACTION = 0.9  # near-full Kelly for faster growth to target
MAX_FRACTION = 0.35   # hard cap on fraction of bankroll risked per bet


def build_winrate_table() -> dict[tuple[str, str], float]:
    """Return player-resolved-winrate for every (player_module, banker_module)."""
    players = load_player_agents()
    bankers = load_banker_agents()
    table: dict[tuple[str, str], float] = {}
    for player_agent in players:
        for banker_agent in bankers:
            stats = simulate_pairing(
                player_agent,
                banker_agent,
                RESOLVED_ROUNDS_PER_PAIRING,
                BASE_SEED,
                "tournament",
            )
            table[(player_agent.module_name, banker_agent.module_name)] = (
                stats.player_resolved_winrate
            )
    return table


DISPLAY_TO_MODULE = {
    "OmniCybr": "omnicybr",
    "NipCat": "nipcat",
    "NorthStar": "northstar",
    "BlackShard": "blackshard",
    "VoltaicAI": "voltaicai",
}


class SocketLines:
    def __init__(self, sock: socket.socket) -> None:
        self._f = sock.makefile("rwb", buffering=0)

    def readline(self) -> str:
        raw = self._f.readline()
        if not raw:
            raise ConnectionError("server closed connection")
        return raw.decode("ascii", "ignore").rstrip("\n")

    def send(self, line: str) -> None:
        self._f.write((line + "\n").encode("ascii"))


def kelly_bet(win_prob: float, bankroll: int) -> int:
    edge = 2 * win_prob - 1
    if edge <= 0:
        return 1
    fraction = min(KELLY_FRACTION * edge, MAX_FRACTION)
    amount = int(bankroll * fraction)
    amount = max(1, min(amount, bankroll))
    return amount


CACHE_PATH = os.path.join(os.path.dirname(__file__), "winrates.json")


def load_or_build_winrate_table() -> dict[tuple[str, str], float]:
    if os.path.exists(CACHE_PATH):
        raw = json.load(open(CACHE_PATH))
        return {tuple(k.split("|")): v for k, v in raw.items()}
    table = build_winrate_table()
    json.dump({f"{p}|{b}": v for (p, b), v in table.items()}, open(CACHE_PATH, "w"))
    return table


def run(host: str, port: int, verbose: bool, use_ssl: bool = True) -> None:
    print("Loading win-rate table...", file=sys.stderr)
    winrates = load_or_build_winrate_table()
    if verbose:
        for (p, b), wr in sorted(winrates.items()):
            print(f"  player={p:10s} banker={b:10s} player_winrate={wr:.3%}", file=sys.stderr)

    raw_sock = socket.create_connection((host, port))
    if use_ssl:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        sock = context.wrap_socket(raw_sock, server_hostname=host)
    else:
        sock = raw_sock
    io = SocketLines(sock)

    banker_display = None
    player_display = None
    bankroll = None

    round_count = 0
    while True:
        line = io.readline()
        if verbose:
            print(line)

        m = re.match(r"BankerAI\s*::\s*(\S+)", line)
        if m:
            banker_display = m.group(1)
            continue
        m = re.match(r"PlayerAI\s*::\s*(\S+)", line)
        if m:
            player_display = m.group(1)
            continue
        m = re.match(r"Bankroll\s*::\s*(\d+)", line)
        if m:
            bankroll = int(m.group(1))
            continue

        if line.startswith("Bet side"):
            player_mod = DISPLAY_TO_MODULE[player_display]
            banker_mod = DISPLAY_TO_MODULE[banker_display]
            player_wr = winrates[(player_mod, banker_mod)]
            if player_wr >= 0.5:
                side = "player"
                win_prob = player_wr
            else:
                side = "banker"
                win_prob = 1.0 - player_wr
            io.send(side)
            continue

        if line.startswith("Bet amount"):
            amount = kelly_bet(win_prob, bankroll)
            round_count += 1
            if round_count % 25 == 0 or verbose:
                print(f"[client] round={round_count} bankroll={bankroll} "
                      f"player={player_display} banker={banker_display} "
                      f"side={side} win_prob={win_prob:.3%} bet={amount}", file=sys.stderr)
            io.send(str(amount))
            continue

        if "FLAG" in line:
            print("\n*** FLAG FOUND ***")
            print(line)
            return

        if "bankroll depleted" in line:
            print("\n*** LOST ***", file=sys.stderr)
            return


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("host")
    parser.add_argument("port", type=int)
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("--no-ssl", action="store_true", help="connect without TLS (plain TCP)")
    args = parser.parse_args()
    run(args.host, args.port, args.verbose, use_ssl=not args.no_ssl)
