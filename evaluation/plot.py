"""Generate the paper's figures from the result folders.

Usage:
    python evaluation/plot.py                  # every figure the results allow
    python evaluation/plot.py outage [RUN]     # success rate over time during a fault
    python evaluation/plot.py latency [RUN]    # CDF of authorization and end-to-end latency
    python evaluation/plot.py revocation       # revocation lag vs. refresh interval / cache TTL

RUN is a folder in evaluation/results/; by default the newest suitable run.
Figures are written to evaluation/figures/ as PDF (for the paper) and PNG (for
a quick look). Never edit them by hand: change this script and re-run it.
"""

from __future__ import annotations

import argparse
import csv
import json
import statistics
import sys
from pathlib import Path
from typing import Optional

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
from matplotlib.ticker import FuncFormatter, NullFormatter  # noqa: E402

sys.path.insert(0, str(Path(__file__).resolve().parent))
from samples_io import open_text, samples_path  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / "evaluation" / "results"
FIGURES = ROOT / "evaluation" / "figures"

MODES = ("offline", "online")
# Categorical slots 1 and 2 of the validated palette (blue, orange): colorblind-safe
# as a pair. Line style and markers differ too, so the figures survive grayscale print.
COLOR = {"offline": "#2a78d6", "online": "#eb6834"}
STYLE = {"offline": "-", "online": "--"}
MARKER = {"offline": "o", "online": "s"}
LABEL = {"offline": "Offline (Biscuit)", "online": "Online (introspection)"}
# Outage with the online cache: four curves in the categorical order (blue, orange, aqua,
# yellow; validated for CVD separation). Aqua and yellow are below 3:1 on white, so every
# curve also has its own dash pattern and a legend entry.
CACHED_STYLE = [("#2a78d6", "-"), ("#eb6834", "--"), ("#1baf7a", "-."), ("#eda100", ":")]
INK, MUTED, GRID = "#1f1f1e", "#6b6a65", "#e4e3df"
COLUMN_WIDTH = 3.5  # inches, one IEEE column
LATENCY_RATE = 200  # req/s of the fault experiments

plt.rcParams.update({
    "font.family": "serif",
    "font.size": 8,
    "axes.edgecolor": MUTED,
    "axes.labelcolor": INK,
    "axes.spines.top": False,
    "axes.spines.right": False,
    "axes.grid": True,
    "grid.color": GRID,
    "grid.linewidth": 0.6,
    "xtick.color": MUTED,
    "ytick.color": MUTED,
    "legend.frameon": False,
    "lines.linewidth": 1.5,
    "pdf.fonttype": 42,  # embed TrueType, as IEEE PDF eXpress requires
})


# --------------------------------------------------------------------------
# Data
# --------------------------------------------------------------------------

def read_samples(path: Path) -> list[dict]:
    """One dict per request from a run CSV; '#' lines are machine metadata."""
    with open_text(path) as f:
        rows = csv.DictReader(line for line in f if not line.startswith("#"))
        return [
            {
                "t": float(r["t_sched"]),
                "latency_ms": float(r["latency_ms"]),
                "status": int(r["status"]),
                "authz_ms": float(r["authz_ms"]) if r["authz_ms"] else None,
            }
            for r in rows
        ]


def read_run(run: Path) -> tuple[dict, dict]:
    return (json.loads((run / "meta.json").read_text()),
            json.loads((run / "summary.json").read_text()))


def success_over_time(samples: list[dict], duration: float, bin_s: float = 1.0) -> tuple[list, list]:
    """Share of requests answered 200, per time bin of scheduled send time."""
    n = int(round(duration / bin_s))
    ok, total = [0] * n, [0] * n
    for s in samples:
        i = int(s["t"] // bin_s)
        if 0 <= i < n:
            total[i] += 1
            ok[i] += s["status"] == 200
    centers = [(i + 0.5) * bin_s for i in range(n)]
    rates = [o / t if t else float("nan") for o, t in zip(ok, total)]
    return centers, rates


def success_since_fault(runs: list[Path], mode: str, before: float = 15.0, after: float = 40.0,
                        bin_s: float = 1.0) -> tuple[list, list]:
    """Share of requests answered 200 per time bin, with time counted from each run's fault start.

    Pools the runs, so runs whose fault starts at different times (outage-cached) line up.
    """
    n = int(round((before + after) / bin_s))
    ok, total = [0] * n, [0] * n
    for run in runs:
        fault_at = read_run(run)[0]["args"]["fault_at"]
        for s in read_samples(samples_path(run, mode)):
            i = int((s["t"] - fault_at + before) // bin_s)
            if 0 <= i < n:
                total[i] += 1
                ok[i] += s["status"] == 200
    centers = [-before + (i + 0.5) * bin_s for i in range(n)]
    return centers, [o / t if t else float("nan") for o, t in zip(ok, total)]


def ecdf(values: list[float]) -> tuple[list[float], list[float]]:
    xs = sorted(values)
    n = len(xs)
    return xs, [(i + 1) / n for i in range(n)]


def steady_window(meta: dict) -> tuple[float, float]:
    """Time range with no fault: the whole run for baseline, else before the fault."""
    a = meta["args"]
    end = a["duration"] if a["scenario"] == "baseline" else a["fault_at"]
    return a["warmup"], end


def revocation_points(runs: list[Path]) -> dict[str, dict[float, list[float]]]:
    """mode -> interval -> lags. Interval is the refresh period (offline) or cache TTL (online)."""
    out: dict[str, dict[float, list[float]]] = {m: {} for m in MODES}
    for run in runs:
        meta, summary = read_run(run)
        a = meta["args"]
        if a["scenario"] != "revoke":
            continue
        for mode in MODES:
            lag = summary.get(mode, {}).get("events", {}).get("revocation_lag_s")
            if lag is None:
                continue
            interval = a["refresh_seconds"] if mode == "offline" else a["cache_ttl"]
            out[mode].setdefault(float(interval), []).append(lag)
    return out


def is_cached_outage(run: Path) -> bool:
    """An outage-cached run: online only, introspection cache on."""
    a = read_run(run)[0]["args"]
    return a["scenario"] != "revoke" and a.get("cache_ttl", 0) > 0


def outage_runs(runs: list[Path]) -> list[Path]:
    """Runs for the per-scenario outage figure (both modes, no cache)."""
    return [r for r in runs if not is_cached_outage(r)]


def cached_outage_curves(scenario: str, runs: list[Path]) -> list[tuple[str, list[Path], str]]:
    """(label, runs, mode) for offline, online without cache, and online per cache TTL.

    Matrix runs only, so each curve pools the repetitions of one configuration.
    Empty if there are no cached runs for the scenario.
    """
    matrix = [r for r in runs if r.name.startswith("matrix-") and read_run(r)[0]["args"]["scenario"] == scenario]
    base = [r for r in matrix if not is_cached_outage(r)]
    by_ttl: dict[float, list[Path]] = {}
    for r in matrix:
        if is_cached_outage(r):
            by_ttl.setdefault(read_run(r)[0]["args"]["cache_ttl"], []).append(r)
    if not by_ttl or not base:
        return []
    curves = [(LABEL["offline"], base, "offline"), ("Online, no cache", base, "online")]
    curves += [(f"Online, cache TTL {ttl:g} s", by_ttl[ttl], "online") for ttl in sorted(by_ttl)]
    return curves


def delegation_points(runs: list[Path]) -> dict[str, dict[int, list[float]]]:
    """mode -> chain depth -> authz p50 (ms) of each run in the delegation group."""
    out: dict[str, dict[int, list[float]]] = {m: {} for m in MODES}
    for run in runs:
        if not run.name.startswith("matrix-delegation-"):
            continue
        meta, summary = read_run(run)
        for mode in MODES:
            ph = next((p for p in summary.get(mode, {}).get("phases", []) if p["phase"] == "steady"), None)
            if ph and ph.get("authz_p50_ms") is not None:
                out[mode].setdefault(int(meta["args"]["chain_depth"]), []).append(ph["authz_p50_ms"])
    return out


def find_runs(scenarios: tuple[str, ...]) -> list[Path]:
    """Result folders of the given scenarios, oldest first."""
    runs = []
    for d in sorted(RESULTS.iterdir()) if RESULTS.exists() else []:
        if (d / "meta.json").exists() and (d / "summary.json").exists():
            if json.loads((d / "meta.json").read_text())["args"]["scenario"] in scenarios:
                runs.append(d)
    return runs


# --------------------------------------------------------------------------
# Figures
# --------------------------------------------------------------------------

def save(fig, name: str, out_dir: Path) -> list[Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    paths = [out_dir / f"{name}.pdf", out_dir / f"{name}.png"]
    fig.savefig(paths[0], bbox_inches="tight", metadata={"CreationDate": None, "ModDate": None})
    fig.savefig(paths[1], bbox_inches="tight", dpi=200)
    plt.close(fig)
    return paths


def plot_outage(run: Path, out_dir: Path = FIGURES) -> list[Path]:
    meta, _ = read_run(run)
    a = meta["args"]
    fig, ax = plt.subplots(figsize=(COLUMN_WIDTH, 1.9))
    ax.axvspan(a["fault_at"], a["fault_at"] + a["fault_for"], color=GRID, lw=0)
    ax.text(a["fault_at"] + a["fault_for"] / 2, 50, f"fault:\n{a['scenario']}",
            ha="center", va="center", color=MUTED, fontsize=7)
    for mode in MODES:
        path = samples_path(run, mode)
        if not path.exists():
            continue
        t, rate = success_over_time(read_samples(path), a["duration"])
        ax.plot(t, [r * 100 for r in rate], STYLE[mode], color=COLOR[mode], label=LABEL[mode])
    ax.set_xlim(0, a["duration"])
    ax.set_ylim(-3, 103)
    ax.set_xlabel("Time (s)")
    ax.set_ylabel("Successful requests (%)")
    ax.legend(loc="lower left", bbox_to_anchor=(0, 1.0), ncol=2, borderaxespad=0.2)
    return save(fig, f"outage_{a['scenario']}", out_dir)


def plot_outage_cached(scenario: str, curves: list[tuple[str, list[Path], str]],
                       out_dir: Path = FIGURES, fault_for: float = 20.0) -> list[Path]:
    """Success rate around the fault for offline and online with each cache TTL, runs pooled."""
    before, after = 15.0, fault_for + 20.0
    fig, ax = plt.subplots(figsize=(COLUMN_WIDTH, 2.1))
    ax.axvspan(0, fault_for, color=GRID, lw=0)
    ax.text(fault_for / 2, 50, f"fault:\n{scenario}", ha="center", va="center", color=MUTED, fontsize=7)
    for (label, runs, mode), (color, style) in zip(curves, CACHED_STYLE):
        t, rate = success_since_fault(runs, mode, before, after)
        ax.plot(t, [r * 100 for r in rate], style, color=color, label=label, lw=1.4)
    ax.set_xlim(-before, after)
    ax.set_ylim(-3, 103)
    ax.set_xlabel("Time since fault start (s)")
    ax.set_ylabel("Successful requests (%)")
    ax.legend(loc="lower left", bbox_to_anchor=(0, 1.0), ncol=2, borderaxespad=0.2, fontsize=6.5)
    return save(fig, f"outage_cached_{scenario}", out_dir)


def plot_latency(run: Path, out_dir: Path = FIGURES) -> list[Path]:
    meta, _ = read_run(run)
    lo, hi = steady_window(meta)
    fig, axes = plt.subplots(1, 2, figsize=(COLUMN_WIDTH * 2, 1.9), sharey=True)
    panels = [("authz_ms", "Authorization time (ms)"), ("latency_ms", "End-to-end latency (ms)")]
    for ax, (field, xlabel) in zip(axes, panels):
        for mode in MODES:
            path = samples_path(run, mode)
            if not path.exists():
                continue
            values = [s[field] for s in read_samples(path)
                      if lo <= s["t"] < hi and s["status"] == 200 and s[field] is not None]
            if values:
                xs, ys = ecdf(values)
                ax.plot(xs, ys, STYLE[mode], color=COLOR[mode], label=LABEL[mode])
        ax.set_xscale("log")
        ax.xaxis.set_major_formatter(FuncFormatter(lambda v, _: f"{v:g}"))
        ax.xaxis.set_minor_formatter(NullFormatter())
        ax.set_xticks([t for t in (0.1, 0.2, 0.5, 1, 2, 5, 10, 20, 50, 100, 200, 500, 1000, 2000)
                       if ax.dataLim.x0 <= t <= ax.dataLim.x1 * 1.5])
        ax.set_xlabel(xlabel)
    axes[0].set_ylabel("CDF")
    axes[0].set_ylim(0, 1.0)
    axes[0].legend(loc="lower right")
    warm = "_warm" if meta["args"].get("keep_warm") else ""
    return save(fig, f"latency_cdf_{meta['args']['scenario']}_{meta['args']['rate']:g}{warm}", out_dir)


def latency_runs(runs: list[Path]) -> list[Path]:
    """Newest run for the idle host and for the busy host (keep_warm), matrix runs preferred."""
    runs = [r for r in runs if not r.name.startswith("matrix-delegation-")]  # those have their own figure
    runs = [r for r in runs if read_run(r)[0]["args"]["rate"] == LATENCY_RATE] or runs
    picked = {}
    for r in sorted(runs, key=lambda r: r.name.startswith("matrix-")):  # stable: oldest first in each group
        picked[bool(read_run(r)[0]["args"].get("keep_warm"))] = r
    return [picked[k] for k in sorted(picked)]


def plot_delegation(runs: list[Path], out_dir: Path = FIGURES) -> list[Path]:
    """Authorization time vs delegation depth: median over runs, bars from min to max."""
    points = delegation_points(runs)
    fig, ax = plt.subplots(figsize=(COLUMN_WIDTH, 1.9))
    for mode in MODES:
        depths = sorted(points[mode])
        if not depths:
            continue
        med = [statistics.median(points[mode][d]) for d in depths]
        lo = [m - min(points[mode][d]) for m, d in zip(med, depths)]
        hi = [max(points[mode][d]) - m for m, d in zip(med, depths)]
        ax.errorbar(depths, med, yerr=[lo, hi], fmt=STYLE[mode], marker=MARKER[mode], markersize=4,
                    color=COLOR[mode], label=LABEL[mode], lw=1.4, capsize=2)
    ax.set_xlabel("Delegation depth (hops)")
    ax.set_ylabel("Authorization p50 (ms)")
    ax.set_ylim(bottom=0)
    ax.legend(loc="lower left", bbox_to_anchor=(0, 1.0), ncol=2, borderaxespad=0.2)
    return save(fig, "delegation_depth", out_dir)


def plot_revocation(runs: list[Path], out_dir: Path = FIGURES) -> list[Path]:
    points = revocation_points(runs)
    intervals = sorted({i for m in MODES for i in points[m]})
    fig, ax = plt.subplots(figsize=(COLUMN_WIDTH, 2.0))
    offset = {"offline": -0.12, "online": 0.12}
    for mode in MODES:
        for k, interval in enumerate(intervals):
            lags = points[mode].get(interval)
            if not lags:
                continue
            x = k + offset[mode]
            ax.scatter([x] * len(lags), lags, s=10, color=COLOR[mode], alpha=0.45,
                       marker=MARKER[mode], linewidths=0)
            ax.plot([x - 0.1, x + 0.1], [statistics.median(lags)] * 2, color=COLOR[mode], lw=2)
        ax.scatter([], [], s=12, color=COLOR[mode], marker=MARKER[mode],
                   label=f"{LABEL[mode]}: {'refresh interval' if mode == 'offline' else 'cache TTL'}")
    ax.set_xticks(range(len(intervals)), [f"{i:g}" for i in intervals])
    ax.set_xlabel("Revocation-list refresh interval / introspection cache TTL (s)")
    ax.set_ylabel("Revocation lag (s)")
    ax.legend(loc="upper left")
    return save(fig, "revocation_lag", out_dir)


# --------------------------------------------------------------------------

def main(argv: Optional[list[str]] = None) -> None:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("figure", nargs="?", default="all", choices=["all", "outage", "latency", "revocation", "delegation"])
    p.add_argument("run", nargs="?", type=Path, help="result folder (outage, latency)")
    p.add_argument("--out-dir", type=Path, default=FIGURES)
    args = p.parse_args(argv)

    outages = ("error", "hang", "freeze", "slow", "flapping")
    made: list[Path] = []
    if args.figure in ("all", "outage"):
        all_outage = find_runs(outages)
        runs = [args.run] if args.run else outage_runs(all_outage)
        if args.figure == "all":
            # newest run of each fault scenario
            runs = list({read_run(r)[0]["args"]["scenario"]: r for r in runs}.values())
        for run in runs[-1:] if args.figure == "outage" else runs:
            made += plot_outage(run, args.out_dir)
        if args.figure == "all":
            curves = cached_outage_curves("error", all_outage)
            if curves:
                made += plot_outage_cached("error", curves, args.out_dir)
    if args.figure in ("all", "latency"):
        runs = [args.run] if args.run else latency_runs(find_runs(("baseline",)) or find_runs(outages))
        for run in runs:
            made += plot_latency(run, args.out_dir)
    if args.figure in ("all", "delegation"):
        runs = find_runs(("baseline",))
        if delegation_points(runs)["offline"]:
            made += plot_delegation(runs, args.out_dir)
    if args.figure in ("all", "revocation"):
        runs = find_runs(("revoke",))
        if runs:
            made += plot_revocation(runs, args.out_dir)
        elif args.figure == "revocation":
            sys.exit("no revoke runs in evaluation/results/")
    for path in made:
        print(f"saved {path.relative_to(ROOT) if path.is_relative_to(ROOT) else path}")


if __name__ == "__main__":
    main()
