"""Aggregation: repetitions are combined correctly and invalid runs are left out."""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "evaluation"))
from aggregate import config_of, latex_delegation, latex_latency, latex_slow, load_runs, main, recovery_s, violations  # noqa: E402
from loadgen import Sample  # noqa: E402
from run_experiment import write_csv  # noqa: E402

ARGS = {"scenario": "error", "fault_at": 2.0, "fault_for": 2.0, "refresh_seconds": 5, "cache_ttl": 0.0}


def phase(name, ok, p50, lag=0.5):
    return {"phase": name, "success_rate": ok, "p50_ms": p50, "p99_ms": p50 * 2, "authz_p50_ms": 0.4,
            "fail_p50_ms": None if ok == 1.0 else 2.0, "send_lag_p99_ms": lag}


def make_run(root, run_id, args=ARGS, online_during=0.0, lag=0.5, lags=None, recover_at=4.5,
             modes=("offline", "online")):
    run = root / run_id
    run.mkdir()
    summary = {}
    for mode in modes:
        during = 1.0 if mode == "offline" else online_during
        summary[mode] = {
            "phases": [phase("before", 1.0, 2.0), phase("during", during, 3.0, lag), phase("after", 1.0, 2.0)],
            "events": {"fault_off_effective": 4.0, "revocation_lag_s": (lags or {}).get(mode)},
        }
        samples = [Sample(i, i / 10, 0.1, 2.0,
                          503 if mode == "online" and 2.0 <= i / 10 < recover_at else 200, 0.4, "")
                   for i in range(60)]
        write_csv(run / f"{mode}.csv", samples, {"mode": mode})
    (run / "meta.json").write_text(json.dumps({"run_id": run_id, "args": args}))
    (run / "summary.json").write_text(json.dumps(summary))
    return run


def test_config_of():
    assert config_of("matrix-slow-50ms-r3") == "slow-50ms"
    assert config_of("matrix-revoke-refresh5-ttl5-r12") == "revoke-refresh5-ttl5"
    assert config_of("20261011-135515-error") is None


def test_violations_flag_generator_lag(tmp_path):
    assert violations(json.loads(json.dumps({"summary": {
        "offline": {"phases": [phase("during", 1.0, 3.0, lag=0.9)]},
        "online": {"phases": [phase("during", 0.0, 3.0, lag=12.0)]}}}))) == [
        "online/during: gen lag p99 12.0 ms"]


def test_recovery_is_time_of_last_refusal_after_the_fault(tmp_path):
    run = make_run(tmp_path, "matrix-error-r1", recover_at=4.5)
    assert recovery_s(run / "online.csv", 4.0) == 0.4  # last refusal at t=4.4
    assert recovery_s(run / "offline.csv", 4.0) == 0.0
    assert recovery_s(run / "missing.csv", 4.0) is None


def test_tables_use_median_over_valid_runs_only(tmp_path):
    results, out = tmp_path / "results", tmp_path / "tables"
    results.mkdir()
    make_run(results, "matrix-error-r1", online_during=0.0)
    make_run(results, "matrix-error-r2", online_during=0.2)
    make_run(results, "matrix-error-r3", online_during=0.1)
    make_run(results, "matrix-error-r4", online_during=0.9, lag=50.0)  # generator fell behind
    rev = {**ARGS, "scenario": "revoke", "refresh_seconds": 5, "cache_ttl": 5}
    for k, (off, on) in enumerate([(1.0, 0.5), (3.0, None), (2.0, 4.0)], 1):
        make_run(results, f"matrix-revoke-refresh5-ttl5-r{k}", args=rev, lags={"offline": off, "online": on})

    assert main(["--check"], results, out) == 1
    assert main([], results, out) == 0
    assert len(load_runs(results)["error"]) == 4

    rows = {(r["mode"], r["phase"]): r for r in _read(out / "phases.csv")}
    online = rows[("online", "during")]
    assert online["runs"] == "3"  # the invalid run is left out
    assert float(online["success_rate"]) == 0.1
    assert (online["success_rate_min"], online["success_rate_max"]) == ("0.0", "0.2")
    assert float(rows[("online", "after")]["recovery_s"]) == 0.4

    rev_rows = {r["mode"]: r for r in _read(out / "revocation.csv")}
    assert float(rev_rows["offline"]["median_s"]) == 2.0
    assert rev_rows["online"]["never_refused"] == "1"
    assert "error & online & 10.0" in (out / "outage.tex").read_text()


def test_outage_table_adds_cached_online_rows(tmp_path):
    results, out = tmp_path / "results", tmp_path / "tables"
    results.mkdir()
    make_run(results, "matrix-error-r1", online_during=0.0)
    for ttl, during in ((30, 0.5), (5, 0.2)):
        for k in (1, 2):
            make_run(results, f"matrix-error-ttl{ttl}-r{k}", args={**ARGS, "cache_ttl": ttl},
                     online_during=during, modes=("online",))
    make_run(results, "matrix-hang-r1", args={**ARGS, "scenario": "hang"}, online_during=0.05)
    make_run(results, "matrix-slow-50ms-r1", args={**ARGS, "scenario": "slow", "delay_ms": 50},
             online_during=1.0)  # slow faults have their own table, not this one
    assert main([], results, out) == 0
    rows = {(r["config"], r["mode"], r["phase"]): r for r in _read(out / "phases.csv")}
    assert float(rows[("error-ttl5", "online", "during")]["success_rate"]) == 0.2
    assert ("error-ttl5", "offline", "during") not in rows  # online-only runs
    body = [line for line in (out / "outage.tex").read_text().splitlines() if line.endswith(r"\\")][1:]
    assert body == [
        r"error & offline & 100.0 & -- & 0.00 \\",
        r"error & online ($T{=}0$) & 0.0 & 2.0 & 0.40 \\",
        r"error & online ($T{=}5$\,s) & 20.0 & 2.0 & 0.40 \\",
        r"error & online ($T{=}30$\,s) & 50.0 & 2.0 & 0.40 \\",
        r"hang & offline & 100.0 & -- & 0.00 \\",
        r"hang & online & 5.0 & 2.0 & 0.40 \\",
    ]


def test_latency_table_orders_rates_and_marks_busy_host():
    def row(config, mode, phase="steady", p50=2.0):
        return {"config": config, "mode": mode, "phase": phase, "authz_p50_ms": 0.4,
                "p50_ms": p50, "p99_ms": p50 * 2}
    rows = [row("baseline-400-warm", "online"), row("baseline-50", "offline", p50=6.0),
            row("baseline-400-warm", "offline"), row("error", "offline"), row("baseline-50", "online")]
    body = [line for line in latex_latency(rows).splitlines() if line.endswith(r"\\")][2:]
    # one row per rate and host: authz, p50, p99, each as offline then online
    assert body == [r"50 & idle & 0.40 & 0.40 & 6.00 & 2.00 & 12.00 & 4.00 \\",
                    r"400 & busy & 0.40 & 0.40 & 2.00 & 2.00 & 4.00 & 4.00 \\"]


def test_delegation_table_orders_depth_then_mode():
    def row(depth, mode, authz):
        return {"config": f"delegation-depth{depth}", "mode": mode, "phase": "steady",
                "authz_p50_ms": authz, "p50_ms": authz + 1, "p99_ms": authz + 2}
    rows = [row(5, "online", 1.2), row(0, "offline", 0.2), row(5, "offline", 0.9), row(0, "online", 1.1),
            {"config": "baseline-200-warm", "mode": "offline", "phase": "steady",
             "authz_p50_ms": 9, "p50_ms": 9, "p99_ms": 9}]
    body = [line for line in latex_delegation(rows).splitlines() if line.endswith(r"\\")][1:]
    assert body == [r"0 & offline & 0.20 & 1.20 & 2.20 \\", r"0 & online & 1.10 & 2.10 & 3.10 \\",
                    r"5 & offline & 0.90 & 1.90 & 2.90 \\", r"5 & online & 1.20 & 2.20 & 3.20 \\"]


def test_slow_table_uses_the_fault_phase_sorted_by_delay():
    rows = [{"config": c, "mode": m, "phase": ph, "p50_ms": p, "p99_ms": p}
            for c, m, ph, p in [("slow-200ms", "online", "during", 203.0), ("slow-10ms", "online", "during", 13.0),
                                ("slow-10ms", "online", "before", 3.0), ("slow-10ms", "offline", "during", 2.0)]]
    body = [line for line in latex_slow(rows).splitlines() if line.endswith(r"\\")][1:]
    assert body == [r"10 & offline & 2.00 & 2.00 \\", r"10 & online & 13.00 & 13.00 \\",
                    r"200 & online & 203.00 & 203.00 \\"]


def _read(path):
    import csv
    with open(path, newline="") as f:
        return list(csv.DictReader(f))


def make_task_run(root, run_id, scenario="error", modes=("offline", "online"), online_during=0.0, lag=1.0,
                  cache_ttl=0.0):
    run = root / run_id
    run.mkdir()

    def tph(name, ok, delegate_ms):
        return {"phase": name, "tasks": 100, "task_success_rate": ok, "delegation_success_rate": ok,
                "delegate_p50_ms": delegate_ms, "delegate_p99_ms": delegate_ms * 2, "task_p50_ms": 10.0,
                "task_p99_ms": 20.0, "send_lag_p99_ms": lag, "errors": {}}

    summary = {}
    for mode in modes:
        d = 0.3 if mode == "offline" else 1.1
        during = 1.0 if mode == "offline" else online_during
        summary[mode] = {"phases": [tph("before", 1.0, d), tph("during", during, d), tph("after", 1.0, d)],
                         "requests": [], "events": {}}
    args = {"scenario": scenario, "workload": "tasks", "fault_at": 2.0, "fault_for": 2.0, "cache_ttl": cache_ttl}
    (run / "meta.json").write_text(json.dumps({"run_id": run_id, "args": args}))
    (run / "summary.json").write_text(json.dumps(summary))


def test_task_runs_get_their_own_table_and_stay_out_of_the_paper_tables(tmp_path):
    results, out = tmp_path / "results", tmp_path / "tables"
    results.mkdir()
    make_run(results, "matrix-error-r1", online_during=0.1)
    for k, during in enumerate([0.0, 0.02, 0.01], 1):
        make_task_run(results, f"matrix-tasks-error-r{k}", online_during=during)
        make_task_run(results, f"matrix-tasks-error-ttl30-r{k}", modes=("online",), online_during=0.0,
                      cache_ttl=30)
    make_task_run(results, "matrix-tasks-error-r4", online_during=0.9, lag=40.0)  # generator fell behind

    assert main([], results, out) == 0
    phases = {r["config"] for r in _read(out / "phases.csv")}
    assert phases == {"error"}  # task runs never reach the outage / latency / slow tables
    assert "tasks" not in (out / "outage.tex").read_text()

    rows = {(r["config"], r["mode"], r["phase"]): r for r in _read(out / "tasks.csv")}
    online = rows[("tasks-error", "online", "during")]
    assert online["runs"] == "3"  # the invalid run is left out
    assert float(online["task_success_rate"]) == 0.01
    assert float(rows[("tasks-error", "offline", "before")]["delegate_p50_ms"]) == 0.3
    assert ("tasks-error-ttl30", "online", "during") in rows
    tex = (out / "tasks.tex").read_text()
    assert "error & offline & 100.0" in tex and r"error & online ($T{=}30$\,s) & 0.0" in tex
    assert tex.count(r"online ($T{=}30$\,s)") == 1  # one row per TTL, not one per phase
