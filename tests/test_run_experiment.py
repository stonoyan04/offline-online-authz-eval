"""Experiment runner: output files are portable (LF endings, no local paths)."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "evaluation"))
from loadgen import Sample  # noqa: E402
from run_experiment import ROOT, git_commit, repo_relative, start_spinners, stop_procs, write_csv  # noqa: E402


def test_repo_relative_inside_and_outside_root(tmp_path):
    assert repo_relative(ROOT / "evaluation" / "results") == "evaluation/results"
    assert repo_relative(tmp_path) == str(tmp_path.resolve())


def test_write_csv_uses_lf_line_endings(tmp_path):
    path = tmp_path / "out.csv"
    samples = [Sample(i, i * 0.1, 0.0, 10.0, 200, 1.0, "") for i in range(3)]
    write_csv(path, samples, {"mode": "offline"})
    data = path.read_bytes()
    assert b"\r" not in data
    assert data.count(b"\n") == 5  # one meta line, header, three rows


def test_git_commit_is_a_sha():
    sha = git_commit().removesuffix("+dirty")
    assert len(sha) == 40 and int(sha, 16) >= 0


def test_spinners_start_busy_and_stop():
    assert start_spinners(0) == []
    procs = start_spinners(2)
    try:
        assert len(procs) == 2 and all(p.poll() is None for p in procs)
    finally:
        stop_procs(procs)
    assert all(p.poll() is not None for p in procs)


def test_mode_result_for_tasks_keeps_task_phases_and_request_phases():
    from run_experiment import mode_result
    from tasks import TaskSample

    tasks = [TaskSample(i, i * 0.1, 0.2, 1.0, "", 2, 5.0, "") for i in range(10)]
    samples = [Sample(i, i * 0.05, 0.0, 2.0, 200, 0.2, "") for i in range(20)]
    result = mode_result(samples, tasks, [("all", 0, 1)], {"chain_depth": 0})
    assert result["phases"][0]["tasks"] == 10  # validity (gen lag) is judged on task starts
    assert result["phases"][0]["send_lag_p99_ms"] == 0.2
    assert result["requests"][0]["requests"] == 20
    assert result["events"] == {"chain_depth": 0}


def test_mode_result_for_requests_is_unchanged():
    from run_experiment import mode_result

    samples = [Sample(i, i * 0.1, 0.3, 2.0, 200, 0.2, "") for i in range(10)]
    result = mode_result(samples, None, [("all", 0, 1)], {})
    assert set(result) == {"phases", "events"}
    assert result["phases"][0]["requests"] == 10


def test_write_csv_with_no_rows_keeps_the_metadata(tmp_path):
    # Every delegation can fail (e.g. the server hangs for the whole run): no requests.
    path = tmp_path / "out.csv"
    write_csv(path, [], {"mode": "online"})
    assert path.read_text() == "# mode: online\n"
