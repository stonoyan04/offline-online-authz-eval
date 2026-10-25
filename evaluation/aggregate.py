"""Combine the repetitions of each matrix configuration into paper tables.

Usage:
    python evaluation/aggregate.py              # check validity, write tables
    python evaluation/aggregate.py --check      # only list runs that break the gen-lag rule

Reads evaluation/results/matrix-<config>-r<k>/ folders. A run is valid only if
every phase kept `gen lag p99` under GEN_LAG_LIMIT_MS; invalid runs are listed
and left out. For each configuration, mode and phase the tables give the
median over the valid runs and the min-max spread, as the plan in
evaluation/README.md asks. Output goes to evaluation/tables/ (gitignored):
CSV for checking, LaTeX for the paper.
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import statistics
import sys
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).resolve().parent))
from samples_io import open_text, samples_path  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / "evaluation" / "results"
TABLES = ROOT / "evaluation" / "tables"
MODES = ("offline", "online")
GEN_LAG_LIMIT_MS = 5.0  # a run is valid only if gen lag p99 stays at a few ms
RECOVERY_WINDOW_S = 10.0
METRICS = ("success_rate", "p50_ms", "p95_ms", "p99_ms", "authz_p50_ms", "fail_p50_ms")
# Agent-task runs (run_experiment.py --workload tasks): phases summarize tasks.
TASK_METRICS = ("task_success_rate", "delegation_success_rate", "delegate_p50_ms", "delegate_p99_ms",
                "task_p50_ms", "task_p99_ms")


def is_tasks(run: dict) -> bool:
    return run["meta"]["args"].get("workload") == "tasks"


def config_of(run_id: str) -> Optional[str]:
    m = re.fullmatch(r"matrix-(.+)-r\d+", run_id)
    return m.group(1) if m else None


def load_runs(results: Path = RESULTS) -> dict[str, list[dict]]:
    """config -> runs, each {'run_id', 'meta', 'summary', 'path'}."""
    out: dict[str, list[dict]] = {}
    for d in sorted(results.glob("matrix-*")):
        config = config_of(d.name)
        if config is None or not (d / "summary.json").exists():
            continue
        out.setdefault(config, []).append({
            "run_id": d.name,
            "path": d,
            "meta": json.loads((d / "meta.json").read_text()),
            "summary": json.loads((d / "summary.json").read_text()),
        })
    return out


def violations(run: dict, limit: float = GEN_LAG_LIMIT_MS) -> list[str]:
    """Phases where the generator fell behind its schedule."""
    bad = []
    for mode in MODES:
        for ph in run["summary"].get(mode, {}).get("phases", []):
            lag = ph.get("send_lag_p99_ms")
            if lag is not None and lag > limit:
                bad.append(f"{mode}/{ph['phase']}: gen lag p99 {lag} ms")
    return bad


def recovery_s(csv_path: Path, fault_off: float, window: float = RECOVERY_WINDOW_S) -> Optional[float]:
    """Seconds from the end of the fault to the last refused request shortly after it.

    0 means no request failed after the fault ended. None if the file is missing.
    """
    if not csv_path.exists():
        return None
    last = None
    with open_text(csv_path) as f:
        for r in csv.DictReader(line for line in f if not line.startswith("#")):
            t = float(r["t_sched"])
            if fault_off <= t < fault_off + window and r["status"] != "200":
                last = t
    return round(last - fault_off, 3) if last is not None else 0.0


def spread(values: list[float]) -> dict:
    values = [v for v in values if v is not None]
    if not values:
        return {"median": None, "min": None, "max": None}
    return {"median": round(statistics.median(values), 3), "min": min(values), "max": max(values)}


def phase_rows(config: str, runs: list[dict], metrics: tuple = METRICS, recovery: bool = True) -> list[dict]:
    """One row per mode and phase: median and spread of each metric over the runs."""
    rows = []
    modes = [m for m in MODES if m in runs[0]["summary"]]  # outage-cached runs are online only
    phases = [p["phase"] for p in runs[0]["summary"][modes[0]]["phases"]]
    for mode in modes:
        for phase in phases:
            row = {"config": config, "mode": mode, "phase": phase, "runs": len(runs)}
            for metric in metrics:
                vals = []
                for run in runs:
                    ph = next((p for p in run["summary"][mode]["phases"] if p["phase"] == phase), None)
                    vals.append(ph.get(metric) if ph else None)
                s = spread(vals)
                row.update({f"{metric}": s["median"], f"{metric}_min": s["min"], f"{metric}_max": s["max"]})
            if recovery and phase == "after":
                rec = [recovery_s(samples_path(run["path"], mode),
                                  run["summary"][mode]["events"].get("fault_off_effective",
                                                                     run["meta"]["args"]["fault_at"]
                                                                     + run["meta"]["args"]["fault_for"]))
                       for run in runs]
                s = spread(rec)
                row.update({"recovery_s": s["median"], "recovery_s_min": s["min"], "recovery_s_max": s["max"]})
            rows.append(row)
    return rows


def revocation_rows(config: str, runs: list[dict]) -> list[dict]:
    rows = []
    a = runs[0]["meta"]["args"]
    for mode in MODES:
        lags = [r["summary"][mode]["events"].get("revocation_lag_s") for r in runs]
        missing = sum(v is None for v in lags)
        lags = sorted(v for v in lags if v is not None)
        interval = a["refresh_seconds"] if mode == "offline" else a["cache_ttl"]
        rows.append({
            "config": config, "mode": mode, "interval_s": interval, "runs": len(runs),
            "never_refused": missing,
            "median_s": round(statistics.median(lags), 3) if lags else None,
            "min_s": lags[0] if lags else None,
            "max_s": lags[-1] if lags else None,
        })
    return rows


def write_csv(path: Path, rows: list[dict]) -> None:
    keys: list[str] = []
    for row in rows:
        keys += [k for k in row if k not in keys]
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=keys, lineterminator="\n")
        w.writeheader()
        w.writerows(rows)


def fmt(v, digits: int = 2) -> str:
    return "--" if v is None else f"{v:.{digits}f}"


def latex_outage(rows: list[dict]) -> str:
    """Success rate during the fault and recovery time, per scenario and mode."""
    lines = [r"\begin{tabular}{llrrr}", r"\toprule",
             r"Fault & Mode & Success during (\%) & Time to refuse (ms) & Recovery (s) \\", r"\midrule"]
    by = {(r["config"], r["mode"], r["phase"]): r for r in rows}
    configs = {r["config"] for r in rows}
    for config in sorted(configs):
        # slow faults never refuse a request; their latency has its own table (slow.tex)
        if (config, "offline", "during") not in by or config.startswith("slow-"):
            continue
        # online with an introspection cache through the same fault (group outage-cached)
        ttls = sorted(int(m.group(1)) for c in configs if (m := re.fullmatch(rf"{re.escape(config)}-ttl(\d+)", c)))
        entries = [(config, "offline", "offline"),
                   (config, "online", r"online ($T{=}0$)" if ttls else "online")]
        entries += [(f"{config}-ttl{t}", "online", rf"online ($T{{=}}{t}$\,s)") for t in ttls]
        for key, mode, label in entries:
            d, a = by[(key, mode, "during")], by.get((key, mode, "after"), {})
            lines.append(f"{config} & {label} & {fmt(d['success_rate'] * 100, 1)} & "
                         f"{fmt(d['fail_p50_ms'], 1)} & {fmt(a.get('recovery_s'), 2)} \\\\")
    lines += [r"\bottomrule", r"\end{tabular}", ""]
    return "\n".join(lines)


def latex_latency(rows: list[dict]) -> str:
    """Steady-state latency per rate, on the idle host and with the host kept busy.

    One row per rate and host, offline and online side by side, to keep the table short.
    """
    lines = [r"\begin{tabular}{rlrrrrrr}", r"\toprule",
             r"& & \multicolumn{2}{c}{Authz p50} & \multicolumn{2}{c}{p50} & \multicolumn{2}{c}{p99} \\",
             r"\cmidrule(lr){3-4}\cmidrule(lr){5-6}\cmidrule(lr){7-8}",
             r"Rate & Host & off & on & off & on & off & on \\", r"\midrule"]
    cells: dict[tuple[int, bool], dict[str, dict]] = {}
    for r in rows:
        m = re.fullmatch(r"baseline-(\d+)(-warm)?", r["config"])
        if m and r["phase"] == "steady":
            cells.setdefault((int(m.group(1)), bool(m.group(2))), {})[r["mode"]] = r
    for (rate, warm), by_mode in sorted(cells.items()):
        values = []
        for key in ("authz_p50_ms", "p50_ms", "p99_ms"):
            values += [fmt(by_mode[mode][key]) if mode in by_mode else "--" for mode in MODES]
        lines.append(f"{rate} & {'busy' if warm else 'idle'} & " + " & ".join(values) + " \\\\")
    lines += [r"\bottomrule", r"\end{tabular}", ""]
    return "\n".join(lines)


def latex_slow(rows: list[dict]) -> str:
    """End-to-end latency while the authorization server answers slowly."""
    lines = [r"\begin{tabular}{rlrr}", r"\toprule",
             r"Added delay (ms) & Mode & p50 (ms) & p99 (ms) \\", r"\midrule"]
    keyed = []
    for r in rows:
        m = re.fullmatch(r"slow-(\d+)ms", r["config"])
        if m and r["phase"] == "during":
            keyed.append(((int(m.group(1)), MODES.index(r["mode"])), r))
    for (delay, _), r in sorted(keyed, key=lambda kr: kr[0]):
        lines.append(f"{delay} & {r['mode']} & {fmt(r['p50_ms'])} & {fmt(r['p99_ms'])} \\\\")
    lines += [r"\bottomrule", r"\end{tabular}", ""]
    return "\n".join(lines)


def latex_delegation(rows: list[dict]) -> str:
    """Authorization time and end-to-end latency by delegation depth (group delegation)."""
    lines = [r"\begin{tabular}{rlrrr}", r"\toprule",
             r"Depth & Mode & Authz p50 (ms) & p50 (ms) & p99 (ms) \\", r"\midrule"]
    keyed = []
    for r in rows:
        m = re.fullmatch(r"delegation-depth(\d+)", r["config"])
        if m and r["phase"] == "steady":
            keyed.append(((int(m.group(1)), MODES.index(r["mode"])), r))
    for (depth, _), r in sorted(keyed, key=lambda kr: kr[0]):
        lines.append(f"{depth} & {r['mode']} & {fmt(r['authz_p50_ms'])} & {fmt(r['p50_ms'])} & "
                     f"{fmt(r['p99_ms'])} \\\\")
    lines += [r"\bottomrule", r"\end{tabular}", ""]
    return "\n".join(lines)


def latex_tasks(rows: list[dict]) -> str:
    """Agent tasks (delegate, then 5 requests) per fault: share served during the fault,
    and the cost of delegating and of a whole task before it (group tasks)."""
    lines = [r"\begin{tabular}{llrrrr}", r"\toprule",
             r"Fault & Mode & Tasks done (\%) & Delegated (\%) & Delegation p50 (ms) & Task p50 (ms) \\",
             r"& & \multicolumn{2}{c}{during the fault} & \multicolumn{2}{c}{before it} \\",
             r"\midrule"]
    by = {(r["config"], r["mode"], r["phase"]): r for r in rows}
    for config in sorted({r["config"] for r in rows if not re.search(r"-ttl\d+$", r["config"])}):
        scenario = config.removeprefix("tasks-")
        ttls = sorted({int(m.group(1)) for c, _, _ in by
                       if (m := re.fullmatch(rf"{re.escape(config)}-ttl(\d+)", c))})
        entries = [(config, "offline", "offline"),
                   (config, "online", r"online ($T{=}0$)" if ttls else "online")]
        entries += [(f"{config}-ttl{t}", "online", rf"online ($T{{=}}{t}$\,s)") for t in ttls]
        for key, mode, label in entries:
            served = by.get((key, mode, "during")) or by.get((key, mode, "steady"))
            cost = by.get((key, mode, "before")) or by.get((key, mode, "steady"))
            if not served or not cost:
                continue
            lines.append(f"{scenario} & {label} & {fmt(served['task_success_rate'] * 100, 1)} & "
                         f"{fmt(served['delegation_success_rate'] * 100, 1)} & "
                         f"{fmt(cost['delegate_p50_ms'])} & {fmt(cost['task_p50_ms'])} \\\\")
    lines += [r"\bottomrule", r"\end{tabular}", ""]
    return "\n".join(lines)


def latex_revocation(rows: list[dict]) -> str:
    lines = [r"\begin{tabular}{lrrrr}", r"\toprule",
             r"Mode & Interval (s) & Median lag (s) & Min (s) & Max (s) \\", r"\midrule"]
    for r in sorted(rows, key=lambda r: (r["mode"], r["interval_s"])):
        lines.append(f"{r['mode']} & {r['interval_s']:g} & {fmt(r['median_s'])} & "
                     f"{fmt(r['min_s'])} & {fmt(r['max_s'])} \\\\")
    lines += [r"\bottomrule", r"\end{tabular}", ""]
    return "\n".join(lines)


def main(argv: Optional[list[str]] = None, results: Path = RESULTS, out_dir: Path = TABLES) -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--check", action="store_true", help="only report invalid runs")
    args = p.parse_args(argv)

    configs = load_runs(results)
    valid: dict[str, list[dict]] = {}
    invalid = 0
    for config, runs in configs.items():
        for run in runs:
            bad = violations(run)
            if bad:
                invalid += 1
                print(f"INVALID {run['run_id']}: {'; '.join(bad)}")
            else:
                valid.setdefault(config, []).append(run)
    total = sum(len(r) for r in configs.values())
    print(f"{total - invalid} of {total} runs valid (gen lag p99 <= {GEN_LAG_LIMIT_MS:g} ms in every phase)")
    if args.check:
        return 1 if invalid else 0

    out_dir.mkdir(parents=True, exist_ok=True)
    phases, revocations, tasks = [], [], []
    for config, runs in sorted(valid.items()):
        if is_tasks(runs[0]):
            tasks += phase_rows(config, runs, TASK_METRICS, recovery=False)
        elif runs[0]["meta"]["args"]["scenario"] == "revoke":
            revocations += revocation_rows(config, runs)
        else:
            phases += phase_rows(config, runs)
    write_csv(out_dir / "phases.csv", phases)
    write_csv(out_dir / "tasks.csv", tasks)
    (out_dir / "tasks.tex").write_text(latex_tasks(tasks))
    write_csv(out_dir / "revocation.csv", revocations)
    (out_dir / "outage.tex").write_text(latex_outage(phases))
    (out_dir / "revocation.tex").write_text(latex_revocation(revocations))
    (out_dir / "latency.tex").write_text(latex_latency(phases))
    (out_dir / "slow.tex").write_text(latex_slow(phases))
    (out_dir / "delegation.tex").write_text(latex_delegation(phases))
    for name in ("phases.csv", "revocation.csv", "outage.tex", "revocation.tex", "latency.tex", "slow.tex",
                 "delegation.tex", "tasks.csv", "tasks.tex"):
        print(f"saved {(out_dir / name).relative_to(ROOT) if (out_dir / name).is_relative_to(ROOT) else out_dir / name}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
