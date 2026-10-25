"""Capacity ramp: stops at the first rate the generator cannot hold."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "evaluation"))
from find_max_rate import gateway_ok, ramp  # noqa: E402


def summary(lag, success=1.0, p50=2.0):
    phase = {"success_rate": success, "p50_ms": p50, "p99_ms": p50 * 2, "send_lag_p99_ms": lag}
    return {"offline": {"phases": [phase]}, "online": {"phases": [dict(phase)]}}


def test_ramp_stops_after_first_generator_overload():
    seen = []

    def run_one(rate):
        seen.append(rate)
        return summary(lag=1.0 if rate < 1000 else 40.0)

    rows = ramp([400, 800, 1000, 2000], run_one)
    assert seen == [400, 800, 1000]  # 2000 never runs
    assert [r["generator_ok"] for r in rows] == [True, True, False]


def test_gateway_ok_needs_success_and_no_queue():
    assert gateway_ok({"success_rate": 1.0, "p50_ms": 2.0})
    assert not gateway_ok({"success_rate": 0.98, "p50_ms": 2.0})
    assert not gateway_ok({"success_rate": 1.0, "p50_ms": 250.0})
    rows = ramp([400], lambda r: {"offline": summary(1.0)["offline"], "online": summary(1.0, p50=80.0)["online"]})
    assert rows[0]["offline"]["gateway_ok"] and not rows[0]["online"]["gateway_ok"]


def test_collapsed_gateway_does_not_count_against_the_generator():
    # capacity-600 on the Mac: offline held (lag 0.1 ms), the online gateway
    # collapsed and the generator fell behind only in that mode.
    def run_one(rate):
        if rate < 800:
            healthy = summary(0.1)["offline"]
            collapsed = summary(900.0, success=0.3, p50=2.4)["online"]
            return {"offline": healthy, "online": collapsed}
        return summary(40.0)

    rows = ramp([400, 600, 800, 1000], run_one)
    assert [r["rate"] for r in rows] == [400, 600, 800]
    assert [r["generator_ok"] for r in rows] == [True, True, False]
    assert rows[1]["offline"]["gateway_ok"] and not rows[1]["online"]["gateway_ok"]


def test_gateway_counts_only_while_its_own_generator_lag_is_ok():
    offline = summary(1.0)["offline"]
    online = summary(40.0)["online"]  # answered fine, but sent late: numbers invalid
    rows = ramp([400], lambda r: {"offline": offline, "online": online})
    assert rows[0]["generator_ok"]
    assert rows[0]["offline"]["valid"] and not rows[0]["online"]["valid"]
    assert not rows[0]["online"]["gateway_ok"]
