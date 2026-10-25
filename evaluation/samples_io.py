"""Per-request run CSVs, stored gzipped (`<mode>.csv.gz`) to keep the repository small.

Older result folders hold plain `<mode>.csv`; readers accept both.
"""

from __future__ import annotations

import gzip
from pathlib import Path
from typing import IO


def open_text(path: Path, mode: str = "r") -> IO[str]:
    """Open a run CSV as text, through gzip if the name ends in .gz."""
    if Path(path).suffix == ".gz":
        return gzip.open(path, mode + "t", newline="")
    return open(path, mode, newline="")


def samples_path(run: Path, mode: str) -> Path:
    """The CSV of one gateway mode in a result folder: gzipped if present, else plain."""
    plain = run / f"{mode}.csv"
    return plain if plain.exists() and not (run / f"{mode}.csv.gz").exists() else run / f"{mode}.csv.gz"
