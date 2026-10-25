"""Run CSVs: gzipped and plain files are written and read the same way."""

import gzip
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "evaluation"))
from aggregate import recovery_s  # noqa: E402
from loadgen import Sample  # noqa: E402
from plot import read_samples  # noqa: E402
from run_experiment import write_csv  # noqa: E402
from samples_io import samples_path  # noqa: E402

SAMPLES = [Sample(i, i / 10, 0.1, 2.0, 503 if 20 <= i < 25 else 200, 0.4, "") for i in range(40)]


def test_write_csv_gz_is_gzip_with_lf_endings(tmp_path):
    path = tmp_path / "online.csv.gz"
    write_csv(path, SAMPLES, {"mode": "online"})
    data = gzip.decompress(path.read_bytes())
    assert b"\r" not in data
    assert data.count(b"\n") == 42  # one meta line, header, 40 rows


def test_gz_and_plain_read_the_same(tmp_path):
    write_csv(tmp_path / "a.csv", SAMPLES, {"mode": "online"})
    write_csv(tmp_path / "b.csv.gz", SAMPLES, {"mode": "online"})
    assert read_samples(tmp_path / "a.csv") == read_samples(tmp_path / "b.csv.gz")
    assert recovery_s(tmp_path / "b.csv.gz", 2.0) == recovery_s(tmp_path / "a.csv", 2.0) == 0.4


def test_samples_path_prefers_gz_and_falls_back_to_plain(tmp_path):
    assert samples_path(tmp_path, "online") == tmp_path / "online.csv.gz"  # neither exists
    (tmp_path / "online.csv").write_text("")
    assert samples_path(tmp_path, "online") == tmp_path / "online.csv"
    (tmp_path / "online.csv.gz").write_bytes(b"")
    assert samples_path(tmp_path, "online") == tmp_path / "online.csv.gz"
