"""CSV ingestion for the CICIDS2017 dataset.

Loads every CSV under ``data/raw/``, concatenates them into a single
``DataFrame``, and normalizes column names to snake_case. The raw CICIDS2017
headers contain leading spaces (e.g. ``" Label"``) and mixed casing, so
normalization is essential before any downstream selection by name.
"""
from __future__ import annotations

import re
from pathlib import Path

import pandas as pd

from src.config import Paths


def to_snake_case(name: str) -> str:
    """Convert a raw CICIDS2017 column header to a canonical snake_case token.

    Handles the dataset's quirks: leading/trailing whitespace, ``/s`` rate
    suffixes (``"Flow Bytes/s"`` -> ``"flow_bytes_per_s"``), and arbitrary
    punctuation.

    Args:
        name: Raw column header.

    Returns:
        Normalized snake_case column name.
    """
    text = name.strip().lower()
    # Preserve the semantic of per-second rate columns before stripping slashes.
    text = text.replace("/s", "_per_s")
    # Replace any remaining run of non-alphanumeric characters with a single "_".
    text = re.sub(r"[^0-9a-z]+", "_", text)
    # Collapse duplicate underscores and trim leading/trailing ones.
    text = re.sub(r"_+", "_", text).strip("_")
    return text


def normalize_columns(df: pd.DataFrame) -> pd.DataFrame:
    """Return ``df`` with all column names converted to snake_case."""
    df = df.rename(columns={col: to_snake_case(str(col)) for col in df.columns})
    return df


def load_raw_data(data_dir: Path | str | None = None) -> pd.DataFrame:
    """Load and concatenate all CICIDS2017 CSV files from ``data_dir``.

    Args:
        data_dir: Directory containing the raw CSV files. Defaults to
            ``data/raw/`` relative to the project root.

    Returns:
        A single concatenated ``DataFrame`` with snake_case column names.

    Raises:
        FileNotFoundError: If the directory does not exist or contains no CSVs.
    """
    directory = Path(data_dir) if data_dir is not None else Paths.data_raw
    if not directory.exists():
        raise FileNotFoundError(f"Data directory does not exist: {directory}")

    csv_files = sorted(directory.glob("*.csv"))
    if not csv_files:
        raise FileNotFoundError(
            f"No CSV files found in {directory}. Download the CICIDS2017 CSVs "
            "into this directory (see README.md)."
        )

    frames: list[pd.DataFrame] = []
    for csv_path in csv_files:
        print(f"[loader] Reading {csv_path.name} ...")
        # low_memory=False avoids dtype-guessing warnings on the wide, mixed
        # columns; encoding_errors tolerates the occasional non-UTF8 byte.
        frame = pd.read_csv(csv_path, low_memory=False, encoding_errors="replace")
        frame = normalize_columns(frame)
        frames.append(frame)
        print(f"[loader]   -> {frame.shape[0]:,} rows, {frame.shape[1]} columns")

    combined = pd.concat(frames, ignore_index=True)
    print(
        f"[loader] Combined dataset: {combined.shape[0]:,} rows, "
        f"{combined.shape[1]} columns from {len(csv_files)} file(s)."
    )
    return combined
