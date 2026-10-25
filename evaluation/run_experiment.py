"""Run one experiment: both gateway modes through the same fault timeline.

Starts the authorization server and the two gateways as separate processes,
then for each mode in turn: sends load at a fixed rate, injects the fault at
`--fault-at` for `--fault-for` seconds, keeps going to observe recovery, and
writes every request to CSV. Modes run one after the other so they never
compete for the CPU.

Examples:
    # authorization server returns errors for 20 s in the middle of a 60 s run
    python evaluation/run_experiment.py --scenario error --rate 200 --duration 60

    # authorization server adds 50 ms to every answer
    python evaluation/run_experiment.py --scenario slow --delay-ms 50

    # authorization server process frozen (SIGSTOP): unresponsive host
    python evaluation/run_experiment.py --scenario freeze

    # revocation lag: revoke the token at --fault-at, measure time to first 401
    python evaluation/run_experiment.py --scenario revoke --refresh-seconds 5

    # agent tasks: 40 tasks/s, each delegates to a new sub-agent, which sends 5 requests
    python evaluation/run_experiment.py --workload tasks --scenario error --rate 40

Scenarios: baseline, slow, error, hang, freeze, flapping, revoke.
Results: evaluation/results/<run-id>/{offline,online}.csv.gz, summary.json, meta.json;
with --workload tasks also {offline,online}-tasks.csv.gz (one row per task).

Run this on a dedicated machine or VM, not on shared cloud hardware.
"""

from __future__ import annotations

import argparse
import asyncio
import csv
import json
import os
import platform
import secrets
import signal
import subprocess
import sys
import time
from datetime import datetime, timezone
from importlib.metadata import version
from pathlib import Path
from typing import Optional

import httpx
from biscuit_auth import KeyPair

sys.path.insert(0, str(Path(__file__).resolve().parent))
from loadgen import delegation_chain, offline_hop, online_hop, run_load, summarize  # noqa: E402
from samples_io import open_text  # noqa: E402
from tasks import offline_task_hop, online_task_hop, run_tasks, summarize_tasks  # noqa: E402

from agentauthz.gateway.http import gateway_client  # noqa: E402

from agentauthz.keys import private_hex, public_hex  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
# Generated per run, never stored: the processes only listen on localhost.
ADMIN = secrets.token_urlsafe(24)
CLIENT_ID, CLIENT_SECRET = "gateway", secrets.token_urlsafe(24)


# --------------------------------------------------------------------------
# Processes
# --------------------------------------------------------------------------


def start_spinners(n: int) -> list[subprocess.Popen]:
    """Busy-loop processes that keep the host's cores out of idle states.

    At low request rates the host idles between requests and many requests pay
    a wake-up penalty (see "Low-load latency tail" in evaluation/README.md).
    """
    return [subprocess.Popen([sys.executable, "-c", "while True: pass"]) for _ in range(n)]


def stop_procs(procs) -> None:
    for proc in procs:
        proc.terminate()
    for proc in procs:
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()


class Stack:
    """Authorization server + offline gateway + online gateway (+ optional spinners)."""

    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        self.root = KeyPair()
        self.procs: dict[str, subprocess.Popen] = {}
        self.spinners: list[subprocess.Popen] = []
        self.frozen = False
        self.authz = f"http://127.0.0.1:{args.authz_port}"
        self.gateways = {
            "offline": f"http://127.0.0.1:{args.offline_port}",
            "online": f"http://127.0.0.1:{args.online_port}",
        }

    def _spawn(self, name: str, module: str, *extra: str) -> None:
        env = os.environ | {
            "AUTHZ_ROOT_KEY": private_hex(self.root),
            "AUTHZ_ADMIN_TOKEN": ADMIN,
            "AUTHZ_CLIENTS": f"{CLIENT_ID}:{CLIENT_SECRET}",
            "AUTHZ_CLIENT_ID": CLIENT_ID,
            "AUTHZ_CLIENT_SECRET": CLIENT_SECRET,
        }
        log = open(self.args.out / f"{name}.log", "w")
        self.procs[name] = subprocess.Popen(
            [sys.executable, "-m", module, *extra, "--log-level", "warning"],
            cwd=ROOT, env=env, stdout=log, stderr=subprocess.STDOUT,
        )

    @staticmethod
    def _wait_healthy(url: str, timeout: float = 15) -> None:
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                if httpx.get(f"{url}/healthz", timeout=1).status_code == 200:
                    return
            except httpx.HTTPError:
                pass
            time.sleep(0.2)
        raise RuntimeError(f"{url} did not become healthy")

    def start(self) -> None:
        a = self.args
        self._spawn("authz", "agentauthz.authz_server", "--port", str(a.authz_port))
        self._wait_healthy(self.authz)
        common = ["--authz-url", self.authz]
        self._spawn(
            "offline", "agentauthz.demo_service", "--mode", "offline",
            "--port", str(a.offline_port), "--issuer-key", public_hex(self.root),
            "--refresh-seconds", str(a.refresh_seconds),
            *(["--max-staleness", str(a.max_staleness)] if a.max_staleness is not None else []),
            *common,
        )
        self._spawn(
            "online", "agentauthz.demo_service", "--mode", "online",
            "--port", str(a.online_port), "--timeout", str(a.timeout),
            "--cache-ttl", str(a.cache_ttl), *common,
        )
        for url in self.gateways.values():
            self._wait_healthy(url)
        self.spinners = start_spinners(a.keep_warm)

    def stop(self) -> None:
        if self.frozen:
            self.thaw()
        stop_procs([*self.spinners, *self.procs.values()])

    # ---- control --------------------------------------------------------

    def admin(self, method: str, path: str, **kw) -> httpx.Response:
        r = httpx.request(method, f"{self.authz}{path}",
                          headers={"Authorization": f"Bearer {ADMIN}"}, timeout=5, **kw)
        r.raise_for_status()
        return r

    def grant(self, holder: KeyPair, fmt: str) -> str:
        body = {"user": "alice", "holder_key": public_hex(holder),
                "operations": ["search", "buy"], "max_amount": 300,
                "ttl_seconds": 86400, "format": fmt}
        return self.admin("POST", "/admin/grants", json=body).json()["token"]

    def post_authz(self, path: str, **kw) -> httpx.Response:
        return httpx.post(f"{self.authz}{path}", timeout=5, **kw)

    def set_fault(self, **config) -> None:
        self.admin("PUT", "/admin/fault", json=config)

    def revoke(self, token: str) -> None:
        self.admin("POST", "/revoke", data={"token": token})

    def freeze(self) -> None:
        os.kill(self.procs["authz"].pid, signal.SIGSTOP)
        self.frozen = True

    def thaw(self) -> None:
        os.kill(self.procs["authz"].pid, signal.SIGCONT)
        self.frozen = False


# --------------------------------------------------------------------------
# One mode through the timeline
# --------------------------------------------------------------------------


def fault_config(args: argparse.Namespace) -> Optional[dict]:
    s = args.scenario
    if s == "slow":
        return {"mode": "slow", "delay_ms": args.delay_ms, "jitter_ms": args.jitter_ms}
    if s == "error":
        return {"mode": "error"}
    if s == "hang":
        return {"mode": "hang", "hang_seconds": args.fault_for + 5}
    if s == "flapping":
        return {"mode": "flapping", "period_seconds": args.flap_period, "down_fraction": args.flap_down}
    return None


def mode_result(samples: list, tasks: Optional[list], phases: list, events: dict) -> dict:
    """summary.json entry of one mode. For tasks, `phases` summarizes tasks (their
    send lag decides validity) and `requests` the requests inside them."""
    if tasks is None:
        return {"phases": summarize(samples, phases=phases), "events": events}
    return {"phases": summarize_tasks(tasks, phases=phases),
            "requests": summarize(samples, phases=phases), "events": events}


async def run_mode(stack: Stack, mode: str, args: argparse.Namespace) -> tuple[list, dict, Optional[list]]:
    holder = KeyPair()
    token = stack.grant(holder, "biscuit" if mode == "offline" else "opaque")
    # Delegate before the load starts: offline attenuates the Biscuit locally, online
    # exchanges tokens at the server. The last holder signs every request.
    hop = offline_hop(stack.root.public_key) if mode == "offline" else online_hop(stack.post_authz)
    holder, token = delegation_chain(holder, token, args.chain_depth, hop)
    stack.set_fault(mode="none")
    await asyncio.sleep(args.refresh_seconds + 1)  # offline gateway picks up a fresh list

    events: dict[str, float] = {"chain_depth": args.chain_depth, "token_bytes": len(token)}
    config = fault_config(args)
    loop = asyncio.get_running_loop()
    origin: list[float] = []  # perf_counter value at run time 0

    def timed(name: str, action) -> None:
        """Run a blocking control call off the event loop; record when it took effect."""
        def go() -> None:
            action()
            events[f"{name}_effective"] = round(time.perf_counter() - origin[0], 3)
        loop.run_in_executor(None, go)

    def on_tick(t: float) -> None:
        if not origin:
            origin.append(time.perf_counter() - t)
        if "fault_on" not in events and t >= args.fault_at:
            events["fault_on"] = round(t, 3)
            if args.scenario == "freeze":
                stack.freeze()
                events["fault_on_effective"] = round(t, 3)
            elif args.scenario == "revoke":
                timed("fault_on", lambda: stack.revoke(token))
            elif config:
                timed("fault_on", lambda: stack.set_fault(**config))
        if "fault_off" not in events and t >= args.fault_at + args.fault_for:
            events["fault_off"] = round(t, 3)
            if args.scenario == "freeze":
                stack.thaw()
                events["fault_off_effective"] = round(t, 3)
            elif config:
                timed("fault_off", lambda: stack.set_fault(mode="none"))

    tick = None if args.scenario == "baseline" else on_tick
    tasks = None
    if args.workload == "tasks":
        # The agent's own client to the authorization server (online delegation).
        http = gateway_client(timeout=args.timeout)
        http.base_url = stack.authz
        hop = offline_task_hop(stack.root.public_key) if mode == "offline" else online_task_hop(http, args.timeout)
        try:
            tasks, samples = await run_tasks(
                stack.gateways[mode], holder, token, hop, rate=args.rate, duration=args.duration,
                requests_per_task=args.task_requests, timeout=args.client_timeout, on_tick=tick,
            )
        finally:
            await http.aclose()
    else:
        samples = await run_load(
            stack.gateways[mode], holder, lambda: token,
            rate=args.rate, duration=args.duration, timeout=args.client_timeout, on_tick=tick,
        )
    if stack.frozen:
        stack.thaw()
    stack.set_fault(mode="none")

    if args.scenario == "revoke":
        phases = [("before", 0, args.fault_at), ("after_revoke", args.fault_at, args.duration)]
        # Lag from the moment the revocation took effect at the issuer to the
        # first request the gateway refused because of it.
        revoked_at = events.get("fault_on_effective", args.fault_at)
        denied = [s.t_sched for s in samples if s.t_sched >= revoked_at and s.status == 401]
        events["revocation_lag_s"] = round(min(denied) - revoked_at, 3) if denied else None
    elif args.scenario == "baseline":
        phases = [("steady", args.warmup, args.duration)]
    else:
        end = args.fault_at + args.fault_for
        phases = [
            ("before", args.warmup, args.fault_at),
            ("during", args.fault_at, end),
            ("after", end, args.duration),
        ]
    return samples, mode_result(samples, tasks, phases, events), tasks


def write_csv(path: Path, samples: list, meta: dict) -> None:
    with open_text(path, "w") as f:
        for key, value in meta.items():
            f.write(f"# {key}: {value}\n")
        if not samples:
            return
        writer = csv.DictWriter(f, fieldnames=list(samples[0].row()), lineterminator="\n")
        writer.writeheader()
        writer.writerows(s.row() for s in samples)


def repo_relative(path: Path) -> str:
    """Path relative to the repository root, so result files do not leak local paths."""
    path = Path(path).resolve()
    try:
        return str(path.relative_to(ROOT))
    except ValueError:
        return str(path)


def git_commit() -> str:
    """Commit the code was run from, with '+dirty' if there were local changes."""
    try:
        sha = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True,
                             text=True, check=True).stdout.strip()
        dirty = subprocess.run(["git", "status", "--porcelain", "--untracked-files=no"], cwd=ROOT,
                               capture_output=True, text=True).stdout.strip()
        return sha + ("+dirty" if dirty else "")
    except (OSError, subprocess.CalledProcessError):
        return "unknown"


def machine_info() -> dict:
    info = {
        "python": sys.version.split()[0],
        "biscuit_python": version("biscuit-python"),
        "fastapi": version("fastapi"),
        "uvicorn": version("uvicorn"),
        "httpx": version("httpx"),
        "httpcore": version("httpcore"),
        "sniffio": version("sniffio"),
        "platform": platform.platform(),
        "machine": platform.machine(),
        "cpu_count": os.cpu_count(),
    }
    if sys.platform == "darwin":
        try:
            info["cpu"] = subprocess.run(
                ["sysctl", "-n", "machdep.cpu.brand_string"], capture_output=True, text=True
            ).stdout.strip()
        except OSError:
            pass
    return info


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--scenario", default="error",
                   choices=["baseline", "slow", "error", "hang", "freeze", "flapping", "revoke"])
    p.add_argument("--modes", default="offline,online")
    p.add_argument("--rate", type=float, default=200, help="requests per second (tasks per second with --workload tasks)")
    p.add_argument("--workload", choices=["requests", "tasks"], default="requests",
                   help="tasks: each task delegates to a new sub-agent, which then sends --task-requests requests")
    p.add_argument("--task-requests", type=int, default=5)
    p.add_argument("--duration", type=float, default=60)
    p.add_argument("--warmup", type=float, default=5, help="seconds excluded from 'before'")
    p.add_argument("--fault-at", type=float, default=20)
    p.add_argument("--fault-for", type=float, default=20)
    p.add_argument("--delay-ms", type=float, default=50)
    p.add_argument("--jitter-ms", type=float, default=0)
    p.add_argument("--flap-period", type=float, default=4)
    p.add_argument("--flap-down", type=float, default=0.5)
    p.add_argument("--refresh-seconds", type=float, default=5)
    p.add_argument("--max-staleness", type=float, default=None)
    p.add_argument("--timeout", type=float, default=2.0, help="online gateway deadline")
    p.add_argument("--cache-ttl", type=float, default=0.0, help="online introspection cache")
    p.add_argument("--client-timeout", type=float, default=10.0)
    p.add_argument("--chain-depth", type=int, default=0,
                   help="delegation hops from the granted agent to the agent that sends the load")
    p.add_argument("--keep-warm", type=int, default=0,
                   help="busy-loop processes that keep the host's cores awake during the run")
    p.add_argument("--authz-port", type=int, default=18001)
    p.add_argument("--offline-port", type=int, default=18000)
    p.add_argument("--online-port", type=int, default=18002)
    p.add_argument("--out-dir", default=str(ROOT / "evaluation" / "results"))
    p.add_argument("--run-id", default=None)
    args = p.parse_args()
    if args.workload == "tasks" and args.scenario == "revoke":
        p.error("--workload tasks does not support the revoke scenario")

    run_id = args.run_id or datetime.now().strftime(f"%Y%m%d-%H%M%S-{args.scenario}")
    args.out = Path(args.out_dir) / run_id
    args.out.mkdir(parents=True, exist_ok=True)
    meta_args = {k: v for k, v in vars(args).items() if k != "out"}
    meta_args["out_dir"] = repo_relative(args.out_dir)
    meta = {"run_id": run_id, "args": meta_args,
            "machine": machine_info(),
            "git_commit": git_commit(),
            "started": datetime.now(timezone.utc).isoformat(timespec="seconds")}
    (args.out / "meta.json").write_text(json.dumps(meta, indent=2, default=str))

    stack = Stack(args)
    summary: dict = {}
    try:
        stack.start()
        for mode in args.modes.split(","):
            unit = "tasks/s" if args.workload == "tasks" else "req/s"
            print(f"== {mode}: {args.scenario}, {args.rate:g} {unit} for {args.duration:g} s")
            samples, result, tasks = asyncio.run(run_mode(stack, mode, args))
            header = {"mode": mode, "scenario": args.scenario, **meta["machine"]}
            write_csv(args.out / f"{mode}.csv.gz", samples, header)
            summary[mode] = result
            if tasks is not None:
                write_csv(args.out / f"{mode}-tasks.csv.gz", tasks, header)
                for ph in result["phases"]:
                    print(f"   {ph['phase']:>12}: tasks ok {ph['task_success_rate']:.1%}"
                          f"  delegated {ph['delegation_success_rate']:.1%}"
                          f"  delegate p50 {ph['delegate_p50_ms']} ms  task p50 {ph['task_p50_ms']} ms"
                          f"  p99 {ph['task_p99_ms']} ms  gen lag p99 {ph['send_lag_p99_ms']} ms"
                          f"  {ph['errors'] or ''}")
                continue
            for ph in result["phases"]:
                print(f"   {ph['phase']:>12}: ok {ph['success_rate']:.1%}  p50 {ph['p50_ms']} ms"
                      f"  p99 {ph['p99_ms']} ms  authz p50 {ph['authz_p50_ms']} ms"
                      f"  fail p50 {ph['fail_p50_ms']} ms"
                      f"  gen lag p99 {ph['send_lag_p99_ms']} ms  {ph['errors'] or ''}")
            if result["events"].get("revocation_lag_s") is not None or args.scenario == "revoke":
                print(f"   revocation lag: {result['events'].get('revocation_lag_s')} s")
    finally:
        stack.stop()
    (args.out / "summary.json").write_text(json.dumps(summary, indent=2))
    print(f"saved {args.out}")


if __name__ == "__main__":
    main()
