"""Find the highest request rate this machine sustains: generator and gateways.

Usage:
    python evaluation/find_max_rate.py                 # default rate steps
    python evaluation/find_max_rate.py --rates 400,800,1600

Runs `baseline` at rising rates (both modes, 30 s each) as run ids
capacity-<rate>, and stops after the first rate at which neither gateway kept
up with the generator on schedule (gen lag p99 over GEN_LAG_LIMIT_MS, or the
gateway failed, see `verdict`): above it, measured latency is the
generator's, not the gateways'. For every rate it says whether each gateway
kept up (success and median latency, see `gateway_ok`). Finished runs are
reused, so the ramp can be restarted.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Callable, Optional

ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / "evaluation" / "results"
RATES = (400, 600, 800, 1000, 1500, 2000, 3000)
GEN_LAG_LIMIT_MS = 5.0  # same rule as aggregate.py
MIN_SUCCESS = 0.999
MAX_P50_MS = 10.0  # a gateway whose median is this far above its few-ms baseline is queueing


def gateway_ok(phase: dict) -> bool:
    """The gateway answered (almost) everything without building a queue."""
    return phase["success_rate"] >= MIN_SUCCESS and (phase["p50_ms"] or 0) <= MAX_P50_MS


def verdict(rate: float, summary: dict) -> dict:
    """A mode's numbers are valid only if the generator kept its schedule in it.

    A collapsing gateway makes the generator fall behind too (thousands of
    requests in flight), so lag in that mode is a symptom, not the generator's
    limit. The generator held the rate if some mode was valid and answered.
    """
    row: dict = {"rate": rate}
    for mode, result in summary.items():
        ph = result["phases"][0]
        row[mode] = {k: ph[k] for k in ("success_rate", "p50_ms", "p99_ms", "send_lag_p99_ms")}
        lag = ph["send_lag_p99_ms"]
        row[mode]["valid"] = lag is not None and lag <= GEN_LAG_LIMIT_MS
        row[mode]["gateway_ok"] = row[mode]["valid"] and gateway_ok(ph)
    row["generator_ok"] = any(row[m]["gateway_ok"] for m in summary)
    return row


def ramp(rates, run_one: Callable[[float], dict]) -> list[dict]:
    """Verdict per rate, up to and including the first rate the generator cannot hold."""
    rows = []
    for rate in rates:
        rows.append(verdict(rate, run_one(rate)))
        if not rows[-1]["generator_ok"]:
            break
    return rows


def run_capacity(rate: float, results: Path = RESULTS, duration: float = 30) -> dict:
    run_id = f"capacity-{rate:g}"
    summary = results / run_id / "summary.json"
    if not summary.exists():
        cmd = [sys.executable, str(ROOT / "evaluation" / "run_experiment.py"), "--scenario", "baseline",
               "--rate", str(rate), "--duration", str(duration), "--run-id", run_id]
        subprocess.run(cmd, cwd=ROOT, check=True)
    return json.loads(summary.read_text())


def main(argv: Optional[list[str]] = None) -> None:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--rates", default=",".join(str(r) for r in RATES))
    args = p.parse_args(argv)
    rows = ramp([float(r) for r in args.rates.split(",")], run_capacity)
    print(f"\n{'rate':>6}  gen  " + "  ".join(f"{m:>7}: ok%    p50    p99  lag99" for m in ("offline", "online")))
    for row in rows:
        cells = []
        for mode in ("offline", "online"):
            m = row.get(mode)
            cells.append(f"{'yes' if m['gateway_ok'] else 'NO':>7}: {m['success_rate'] * 100:5.1f} "
                         f"{m['p50_ms'] or 0:6.2f} {m['p99_ms'] or 0:6.2f} {m['send_lag_p99_ms']:6.2f}"
                         if m else f"{'-':>7}")
        print(f"{row['rate']:>6g}  {'ok ' if row['generator_ok'] else 'NO '}  " + "  ".join(cells))
    held = [r["rate"] for r in rows if r["generator_ok"]]
    print(f"\ngenerator sustains: {max(held):g} req/s" if held else "\ngenerator sustains none of the rates")
    for mode in ("offline", "online"):
        ok = [r["rate"] for r in rows if r["generator_ok"] and r.get(mode, {}).get("gateway_ok")]
        print(f"{mode} gateway keeps up to: {max(ok):g} req/s" if ok else f"{mode} gateway: none")


if __name__ == "__main__":
    main()
