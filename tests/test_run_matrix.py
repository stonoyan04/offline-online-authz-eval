"""Experiment matrix: matches the plan, valid flags, resumable."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "evaluation"))
from run_matrix import Config, is_done, plan, run_ids  # noqa: E402


def test_plan_covers_every_group_with_planned_repeats():
    configs = plan()
    groups = {}
    for c in configs:
        groups.setdefault(c.group, []).append(c)
    assert set(groups) == {"baseline", "baseline-warm", "delegation", "slow", "outage", "outage-cached",
                           "flapping", "revoke", "tasks"}
    assert [c.args["rate"] for c in groups["baseline"]] == [50, 100, 200, 400]
    assert [c.args["rate"] for c in groups["baseline-warm"]] == [50, 100, 200, 400]
    assert all(c.args["keep_warm"] > 0 for c in groups["baseline-warm"])
    assert all("keep_warm" not in c.args for c in configs if c.group not in ("baseline-warm", "delegation"))
    assert [c.args["chain_depth"] for c in groups["delegation"]] == [0, 1, 2, 3, 5]
    assert all(c.args["keep_warm"] == 4 and c.args["rate"] == 200 and c.args["scenario"] == "baseline"
               and "modes" not in c.args and c.repeats == 5 for c in groups["delegation"])
    assert {c.args["scenario"] for c in groups["outage"]} == {"error", "hang", "freeze"}
    assert all(c.repeats == 20 for c in groups["revoke"])
    assert len({c.name for c in configs}) == len(configs)


def test_outage_cached_runs_online_only_with_random_fault_start():
    cached = [c for c in plan() if c.group == "outage-cached"]
    assert sorted((c.args["scenario"], c.args["cache_ttl"]) for c in cached) == [
        ("error", 5), ("error", 30), ("freeze", 5), ("freeze", 30), ("hang", 5), ("hang", 30)]
    outage = next(c for c in plan() if c.name == "error")
    for c in cached:
        ttl = c.args["cache_ttl"]
        assert c.args["modes"] == "online" and c.args["rate"] == outage.args["rate"] and c.repeats == 5
        assert c.args.get("fault_for", 20) == 20 and "keep_warm" not in c.args
        for rid in run_ids(c):
            a = c.run_args(rid)
            assert 20 <= a["fault_at"] < 20 + ttl
            assert a["duration"] - (a["fault_at"] + 20) >= 20  # full 'after' phase, as in 'outage'
    # one mode per run, so roughly half the wall time of a two-mode run of the same length
    c = next(c for c in cached if c.args["cache_ttl"] == 5)
    assert c.seconds() < Config("x", "x", {**c.args, "modes": "offline,online"}, jitter=5).seconds() * 0.6


def test_revoke_runs_last_long_enough_to_see_the_lag():
    for c in plan():
        if c.group == "revoke":
            interval = max(c.args["refresh_seconds"], c.args["cache_ttl"])
            for rid in run_ids(c):
                a = c.run_args(rid)
                assert a["duration"] - a["fault_at"] > interval


def test_revocation_time_is_spread_over_one_interval_and_reproducible():
    c = next(c for c in plan() if c.name == "revoke-refresh5-ttl5")
    times = [c.run_args(rid)["fault_at"] for rid in run_ids(c)]
    assert all(20 <= t < 25 for t in times)
    assert max(times) - min(times) > 2.5  # 20 draws cover most of the 5 s interval
    assert times == [c.run_args(rid)["fault_at"] for rid in run_ids(c)]
    assert Config("x", "x", {"fault_at": 20}).run_args("any")["fault_at"] == 20  # no jitter


def test_argv_uses_run_experiment_flags():
    c = Config("x", "x", {"scenario": "slow", "delay_ms": 50, "cache_ttl": 5})
    assert c.argv() == ["--scenario", "slow", "--delay-ms", "50", "--cache-ttl", "5"]


def test_flags_exist_in_run_experiment():
    source = (Path(__file__).resolve().parents[1] / "evaluation" / "run_experiment.py").read_text()
    for c in plan():
        for flag in c.argv()[::2]:
            assert f'"{flag}"' in source, flag


def test_run_ids_are_stable_and_done_runs_are_skipped(tmp_path):
    c = Config("outage", "error", repeats=3)
    assert run_ids(c) == ["matrix-error-r1", "matrix-error-r2", "matrix-error-r3"]
    assert run_ids(c, 1) == ["matrix-error-r1"]
    (tmp_path / "matrix-error-r1").mkdir()
    assert not is_done("matrix-error-r1", tmp_path)  # started but not finished
    (tmp_path / "matrix-error-r1" / "summary.json").write_text("{}")
    assert is_done("matrix-error-r1", tmp_path)


def test_tasks_group_delegates_during_each_fault_with_and_without_cache():
    tasks = [c for c in plan() if c.group == "tasks"]
    assert sorted(c.name for c in tasks) == sorted(
        [f"tasks-{s}" for s in ("baseline", "error", "hang", "freeze")]
        + [f"tasks-{s}-ttl30" for s in ("baseline", "error", "hang", "freeze")])
    for c in tasks:
        a = c.args
        assert a["workload"] == "tasks" and a["rate"] * a["task_requests"] == 200  # same load as the faults
        assert c.repeats == 5 and c.jitter == 0 and "keep_warm" not in a
        if c.name.endswith("-ttl30"):
            assert a["modes"] == "online" and a["cache_ttl"] == 30
        else:
            assert "modes" not in a and "cache_ttl" not in a
