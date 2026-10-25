"""Run the experiment plan from evaluation/README.md, one run_experiment.py call per run.

Usage:
    python evaluation/run_matrix.py --dry-run          # list runs and estimated time
    python evaluation/run_matrix.py                    # run everything not done yet
    python evaluation/run_matrix.py --only revoke      # one group of the plan
    python evaluation/run_matrix.py --repeats 1        # quick pass, one run each

Each run gets a fixed id (matrix-<config>-r<k>), so the matrix can be stopped
and restarted: runs whose folder already has a summary.json are skipped. Keep
the machine otherwise idle while it runs, and plugged in.
"""

from __future__ import annotations

import argparse
import random
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / "evaluation" / "results"
RATE = 200  # req/s for every fault experiment; gen lag p99 < 1 ms at this rate on the Mac
DEPTHS = (0, 1, 2, 3, 5)  # delegation group
KEEP_WARM = 4  # spinners for baseline-warm; removes the host idle tail on the Mac (README)
SETUP_S = 8  # process start-up and teardown per run, roughly
TASK_REQUESTS = 5  # requests per agent task (group tasks)


@dataclass
class Config:
    group: str
    name: str
    args: dict = field(default_factory=dict)
    repeats: int = 5
    # Random delay (0..jitter s) added to fault_at per run. Revocation lag depends on
    # where the revocation lands inside the refresh / cache period, and that phase is
    # otherwise the same in every run, so the repetitions would not sample it.
    jitter: float = 0.0

    def run_args(self, run_id: str) -> dict:
        a = dict(self.args)
        if self.jitter:
            a["fault_at"] = round(a["fault_at"] + random.Random(run_id).uniform(0, self.jitter), 3)
        return a

    def argv(self, run_id: str = "") -> list[str]:
        out = []
        for key, value in self.run_args(run_id).items():
            out += [f"--{key.replace('_', '-')}", str(value)]
        return out

    def seconds(self) -> float:
        """Rough wall time of one run: both modes, each waiting for a fresh list first."""
        a = self.args
        per_mode = a.get("duration", 60) + self.jitter + a.get("refresh_seconds", 5) + 1
        return len(a.get("modes", "offline,online").split(",")) * per_mode + SETUP_S


def plan() -> list[Config]:
    """The experiment plan in evaluation/README.md."""
    configs = []
    for rate in (50, 100, 200, 400):
        configs.append(Config("baseline", f"baseline-{rate}", {"scenario": "baseline", "rate": rate}))
    # Same with the host kept busy, so steady-state latency reflects the gateways, not CPU idle states.
    for rate in (50, 100, 200, 400):
        configs.append(Config("baseline-warm", f"baseline-{rate}-warm",
                              {"scenario": "baseline", "rate": rate, "keep_warm": KEEP_WARM}))
    # End-to-end cost of delegation: the load is sent by the last agent of a chain of
    # `chain_depth` hops (offline: Biscuit attenuation; online: RFC 8693 exchanges).
    for depth in DEPTHS:
        configs.append(Config("delegation", f"delegation-depth{depth}", {
            "scenario": "baseline", "rate": RATE, "chain_depth": depth, "keep_warm": KEEP_WARM}))
    for delay in (10, 50, 200):
        configs.append(Config("slow", f"slow-{delay}ms",
                              {"scenario": "slow", "rate": RATE, "delay_ms": delay}))
    for scenario in ("error", "hang", "freeze"):
        configs.append(Config("outage", scenario, {"scenario": scenario, "rate": RATE}))
    # Online with an introspection cache through the same faults. Offline does not depend on
    # the cache and is measured by "outage". The fault starts at a random point of one TTL
    # (the cache refills on a fixed cycle from the first request, so a fixed start would put
    # every repetition at the same cache age); it still lasts 20 s, followed by 20 s after.
    for scenario in ("error", "hang", "freeze"):
        for ttl in (5, 30):
            configs.append(Config("outage-cached", f"{scenario}-ttl{ttl}", {
                "scenario": scenario, "modes": "online", "rate": RATE, "cache_ttl": ttl,
                "fault_at": 20, "duration": 60 + ttl,
            }, jitter=ttl))
    configs.append(Config("flapping", "flapping",
                          {"scenario": "flapping", "rate": RATE, "flap_period": 4, "flap_down": 0.5}))
    # One run measures both modes: offline with refresh interval R, online with cache TTL T.
    # The revocation lands at a random point of one interval after second 20; the lag is
    # at most the interval, so the run ends 10 s after the latest possible refusal.
    for refresh, ttl in ((1, 0), (5, 5), (30, 30)):
        interval = max(refresh, ttl)
        configs.append(Config("revoke", f"revoke-refresh{refresh}-ttl{ttl}", {
            "scenario": "revoke", "rate": RATE, "refresh_seconds": refresh, "cache_ttl": ttl,
            "fault_at": 20, "duration": 20 + 2 * interval + 10,
        }, repeats=20, jitter=interval))
    # Agents delegate *during* the fault: each task hands a fresh token to a new sub-agent
    # (offline: local attenuation; online: RFC 8693 exchange), which then sends
    # TASK_REQUESTS requests. Same request load as the fault runs. With an introspection
    # cache (online only) the fresh token is never cached yet when delegation happens.
    for scenario in ("baseline", "error", "hang", "freeze"):
        base = {"scenario": scenario, "workload": "tasks", "rate": RATE // TASK_REQUESTS,
                "task_requests": TASK_REQUESTS}
        configs.append(Config("tasks", f"tasks-{scenario}", base))
        configs.append(Config("tasks", f"tasks-{scenario}-ttl30", {**base, "modes": "online", "cache_ttl": 30}))
    return configs


def run_ids(config: Config, repeats: Optional[int] = None) -> list[str]:
    return [f"matrix-{config.name}-r{k + 1}" for k in range(repeats or config.repeats)]


def is_done(run_id: str, results: Path = RESULTS) -> bool:
    return (results / run_id / "summary.json").exists()


def main(argv: Optional[list[str]] = None) -> None:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--only", action="append", choices=sorted({c.group for c in plan()}),
                   help="run only this group (repeatable)")
    p.add_argument("--repeats", type=int, help="override the number of repetitions")
    p.add_argument("--dry-run", action="store_true")
    args = p.parse_args(argv)

    todo = [(c, rid) for c in plan() if not args.only or c.group in args.only
            for rid in run_ids(c, args.repeats) if not is_done(rid)]
    total = sum(c.seconds() for c, _ in todo)
    print(f"{len(todo)} runs to do, about {total / 3600:.1f} h")
    if args.dry_run:
        for c, rid in todo:
            print(f"  {rid:40} {' '.join(c.argv(rid))}")
        return

    started = time.monotonic()
    failed = []
    for i, (c, rid) in enumerate(todo, 1):
        print(f"\n[{i}/{len(todo)}] {rid}  ({(time.monotonic() - started) / 60:.0f} min elapsed)", flush=True)
        cmd = [sys.executable, str(ROOT / "evaluation" / "run_experiment.py"), *c.argv(rid), "--run-id", rid]
        if subprocess.run(cmd, cwd=ROOT).returncode != 0 or not is_done(rid):
            failed.append(rid)
    print(f"\ndone in {(time.monotonic() - started) / 3600:.1f} h; failed: {failed or 'none'}")
    if failed:
        sys.exit(1)


if __name__ == "__main__":
    main()
