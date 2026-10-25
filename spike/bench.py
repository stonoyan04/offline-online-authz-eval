"""Measure local verification cost and token size against delegation depth.

Usage:
    python bench.py                      # print a table
    python bench.py --out results.csv    # also save CSV with machine info

Run this on the author's machine or the experiment VM. Numbers from a shared
cloud sandbox are only a sanity check and must not go into the paper.
"""

from __future__ import annotations

import argparse
import csv
import platform
import statistics
import sys
import time
from datetime import datetime, timedelta, timezone
from importlib.metadata import version

from biscuit_auth import KeyPair

from agentauthz.delegation import delegate, issue, key_hex, verify


def build_chain(depth: int):
    root = KeyPair()
    holders = [KeyPair() for _ in range(depth + 1)]
    token = issue(
        root,
        user="alice",
        holder=holders[0].public_key,
        operations=["search", "buy"],
        max_amount=300,
        ttl=timedelta(days=1),
    )
    for i in range(depth):
        token = delegate(token, holders[i], holders[i + 1].public_key, max_amount=300 - i)
    return root, holders[-1], token


def measure(depth: int, iterations: int) -> dict:
    root, holder, token = build_chain(depth)
    b64 = token.to_base64()
    presenter = key_hex(holder.public_key)
    now = datetime.now(timezone.utc)

    for _ in range(min(200, iterations)):  # warm-up
        verify(b64, root.public_key, presenter=presenter, operation="buy", amount=10, now=now)

    samples = []
    for _ in range(iterations):
        start = time.perf_counter_ns()
        decision = verify(
            b64, root.public_key, presenter=presenter, operation="buy", amount=10, now=now
        )
        samples.append(time.perf_counter_ns() - start)
        if not decision.allowed:
            raise RuntimeError(f"depth {depth}: unexpected deny: {decision.reason}")

    samples.sort()
    us = lambda ns: ns / 1000  # noqa: E731
    return {
        "depth": depth,
        "token_bytes": len(token.to_bytes()),
        "iterations": iterations,
        "p50_us": round(us(samples[len(samples) // 2]), 1),
        "p95_us": round(us(samples[int(len(samples) * 0.95)]), 1),
        "p99_us": round(us(samples[int(len(samples) * 0.99)]), 1),
        "mean_us": round(us(statistics.fmean(samples)), 1),
    }


def machine_info() -> dict:
    return {
        "python": sys.version.split()[0],
        "biscuit_python": version("biscuit-python"),
        "platform": platform.platform(),
        "machine": platform.machine(),
        "processor": platform.processor() or "unknown",
        "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--max-depth", type=int, default=10)
    parser.add_argument("--iterations", type=int, default=2000)
    parser.add_argument("--out", help="CSV file to write")
    args = parser.parse_args()

    rows = [measure(d, args.iterations) for d in range(args.max_depth + 1)]
    info = machine_info()

    print(f"# {info}")
    header = list(rows[0])
    print("  ".join(f"{h:>11}" for h in header))
    for row in rows:
        print("  ".join(f"{row[h]:>11}" for h in header))

    if args.out:
        with open(args.out, "w", newline="") as f:
            for key, value in info.items():
                f.write(f"# {key}: {value}\n")
            writer = csv.DictWriter(f, fieldnames=header, lineterminator="\n")
            writer.writeheader()
            writer.writerows(rows)
        print(f"saved {args.out}")


if __name__ == "__main__":
    main()
