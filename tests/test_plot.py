"""Plot scripts: data reduction is correct and every figure renders."""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "evaluation"))
from loadgen import Sample  # noqa: E402
from plot import (  # noqa: E402
    cached_outage_curves, delegation_points, ecdf, plot_delegation, latency_runs, outage_runs, plot_latency, plot_outage, plot_outage_cached,
    plot_revocation, read_samples, success_since_fault,
    revocation_points, steady_window, success_over_time,
)
from run_experiment import write_csv  # noqa: E402

ARGS = {"scenario": "error", "rate": 10.0, "duration": 6.0, "warmup": 1.0,
        "fault_at": 2.0, "fault_for": 2.0, "refresh_seconds": 5, "cache_ttl": 0.0}


def make_run(root: Path, name: str, args: dict, lags=None) -> Path:
    """A result folder like run_experiment.py writes: 10 req/s, online fails during the fault."""
    run = root / name
    run.mkdir()
    summary = {}
    for mode in ("offline", "online"):
        samples = []
        for i in range(int(args["rate"] * args["duration"])):
            t = i / args["rate"]
            failing = mode == "online" and args["fault_at"] <= t < args["fault_at"] + args["fault_for"]
            status = 503 if failing else 200
            samples.append(Sample(i, t, 0.1, 2.0 + i % 3, status, None if failing else 0.5 + i % 2, ""))
        write_csv(run / f"{mode}.csv", samples, {"mode": mode})
        summary[mode] = {"phases": [], "events": {"revocation_lag_s": (lags or {}).get(mode)}}
    (run / "meta.json").write_text(json.dumps({"run_id": name, "args": args}))
    (run / "summary.json").write_text(json.dumps(summary))
    return run


def test_success_over_time_bins_by_scheduled_time(tmp_path):
    run = make_run(tmp_path, "r", ARGS)
    t, rate = success_over_time(read_samples(run / "online.csv"), duration=6.0)
    assert t == [0.5, 1.5, 2.5, 3.5, 4.5, 5.5]
    assert rate == [1.0, 1.0, 0.0, 0.0, 1.0, 1.0]


def test_read_samples_skips_metadata_and_keeps_missing_authz(tmp_path):
    rows = read_samples(make_run(tmp_path, "r", ARGS) / "online.csv")
    assert len(rows) == 60
    assert rows[25]["status"] == 503 and rows[25]["authz_ms"] is None


def test_latency_runs_pick_newest_matrix_run_per_host_state(tmp_path):
    base = {**ARGS, "scenario": "baseline", "rate": 200.0}
    old = make_run(tmp_path, "matrix-baseline-200-r1", base)
    idle = make_run(tmp_path, "matrix-baseline-200-r2", base)
    warm = make_run(tmp_path, "matrix-baseline-200-warm-r1", {**base, "keep_warm": 4})
    other = make_run(tmp_path, "p99-warm-200", {**base, "keep_warm": 4})  # diagnostic, not matrix
    slow_rate = make_run(tmp_path, "matrix-baseline-50-r1", {**base, "rate": 50.0})
    chain = make_run(tmp_path, "matrix-delegation-depth5-r1", {**base, "keep_warm": 4, "chain_depth": 5})
    assert latency_runs([old, idle, warm, other, slow_rate, chain]) == [idle, warm]
    assert latency_runs([slow_rate]) == [slow_rate]


def test_ecdf_and_steady_window():
    assert ecdf([3.0, 1.0, 2.0, 4.0]) == ([1.0, 2.0, 3.0, 4.0], [0.25, 0.5, 0.75, 1.0])
    assert steady_window({"args": ARGS}) == (1.0, 2.0)
    assert steady_window({"args": {**ARGS, "scenario": "baseline"}}) == (1.0, 6.0)


def test_revocation_points_group_by_mode_interval(tmp_path):
    runs = [
        make_run(tmp_path, "a", {**ARGS, "scenario": "revoke", "refresh_seconds": 5, "cache_ttl": 0.0},
                 lags={"offline": 2.1, "online": 0.01}),
        make_run(tmp_path, "b", {**ARGS, "scenario": "revoke", "refresh_seconds": 5, "cache_ttl": 0.0},
                 lags={"offline": 4.0, "online": None}),
        make_run(tmp_path, "c", ARGS),  # not a revoke run: ignored
    ]
    assert revocation_points(runs) == {"offline": {5.0: [2.1, 4.0]}, "online": {0.0: [0.01]}}


def make_online_run(root, name, fault_at, ttl, served_s):
    """Online-only cached run: requests succeed until `served_s` into the fault."""
    args = {**ARGS, "duration": 30.0, "fault_at": fault_at, "fault_for": 10.0, "cache_ttl": ttl,
            "modes": "online"}
    run = root / name
    run.mkdir()
    samples = []
    for i in range(int(args["rate"] * args["duration"])):
        t = i / args["rate"]
        failing = fault_at + served_s <= t < fault_at + 10.0
        samples.append(Sample(i, t, 0.1, 2.0, 503 if failing else 200, None if failing else 0.5, ""))
    write_csv(run / "online.csv.gz", samples, {"mode": "online"})
    (run / "meta.json").write_text(json.dumps({"run_id": name, "args": args}))
    (run / "summary.json").write_text(json.dumps({"online": {"phases": [], "events": {}}}))
    return run


def test_success_since_fault_aligns_runs_on_their_fault_start(tmp_path):
    a = make_online_run(tmp_path, "a", fault_at=10.0, ttl=5, served_s=0.0)
    b = make_online_run(tmp_path, "b", fault_at=12.0, ttl=5, served_s=2.0)
    t, rate = success_since_fault([a, b], "online", before=2.0, after=4.0)
    assert t == [-1.5, -0.5, 0.5, 1.5, 2.5, 3.5]
    assert rate == [1.0, 1.0, 0.5, 0.5, 0.0, 0.0]


def test_cached_outage_curves_and_plain_outage_selection(tmp_path):
    base = make_run(tmp_path, "matrix-error-r1", ARGS)
    t30 = make_online_run(tmp_path, "matrix-error-ttl30-r1", 10.0, 30, 5.0)
    t5 = make_online_run(tmp_path, "matrix-error-ttl5-r1", 11.0, 5, 1.0)
    other = make_run(tmp_path, "matrix-hang-r1", {**ARGS, "scenario": "hang"})
    runs = [base, t30, t5, other]
    curves = cached_outage_curves("error", runs)
    assert [(label, rs, mode) for label, rs, mode in curves] == [
        ("Offline (Biscuit)", [base], "offline"), ("Online, no cache", [base], "online"),
        ("Online, cache TTL 5 s", [t5], "online"), ("Online, cache TTL 30 s", [t30], "online")]
    assert cached_outage_curves("hang", runs) == []  # no cached runs: no figure
    assert outage_runs(runs) == [base, other]  # cached runs never replace the two-mode figure
    made = plot_outage_cached("error", curves, tmp_path / "figures")
    assert {p.name for p in made} == {"outage_cached_error.pdf", "outage_cached_error.png"}


def make_depth_run(root, name, depth, authz):
    args = {**ARGS, "scenario": "baseline", "rate": 200.0, "chain_depth": depth, "keep_warm": 4}
    run = root / name
    run.mkdir()
    summary = {m: {"phases": [{"phase": "steady", "authz_p50_ms": a}], "events": {}} for m, a in authz.items()}
    (run / "meta.json").write_text(json.dumps({"run_id": name, "args": args}))
    (run / "summary.json").write_text(json.dumps(summary))
    return run


def test_delegation_points_and_figure(tmp_path):
    runs = [make_depth_run(tmp_path, "matrix-delegation-depth0-r1", 0, {"offline": 0.2, "online": 1.1}),
            make_depth_run(tmp_path, "matrix-delegation-depth0-r2", 0, {"offline": 0.3, "online": 1.0}),
            make_depth_run(tmp_path, "matrix-delegation-depth5-r1", 5, {"offline": 0.9, "online": 1.2}),
            make_depth_run(tmp_path, "matrix-baseline-200-warm-r1", 0, {"offline": 9.0, "online": 9.0})]
    assert delegation_points(runs) == {"offline": {0: [0.2, 0.3], 5: [0.9]}, "online": {0: [1.1, 1.0], 5: [1.2]}}
    made = plot_delegation(runs, tmp_path / "figures")
    assert {p.name for p in made} == {"delegation_depth.pdf", "delegation_depth.png"}


def test_every_figure_renders(tmp_path):
    out = tmp_path / "figures"
    run = make_run(tmp_path, "e", ARGS)
    rev = make_run(tmp_path, "v", {**ARGS, "scenario": "revoke"}, lags={"offline": 2.0, "online": 0.0})
    made = plot_outage(run, out) + plot_latency(run, out) + plot_revocation([rev], out)
    assert {p.name for p in made} == {
        "outage_error.pdf", "outage_error.png", "latency_cdf_error_10.pdf",
        "latency_cdf_error_10.png", "revocation_lag.pdf", "revocation_lag.png",
    }
    assert all(p.stat().st_size > 1000 for p in made)
