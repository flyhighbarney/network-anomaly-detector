"""Cleaning and validation for the concatenated CICIDS2017 DataFrame.

Responsibilities:
    * Replace +/-inf with NaN across numeric columns.
    * Drop rows with a missing label; median-fill remaining feature NaNs.
    * Encode a binary label (0 = BENIGN, 1 = any attack) and keep the original
      multi-class label for the dashboard's detailed breakdown.
    * Deduplicate exact rows.
    * Validate the result (no inf/NaN, labels in {0, 1}) and log class balance.
"""
from __future__ import annotations

import numpy as np
import pandas as pd

from src.config import (
    BINARY_LABEL_COLUMN,
    LABEL_COLUMN,
    MULTICLASS_LABEL_COLUMN,
)

BENIGN_LABEL = "BENIGN"


def _replace_infinities(df: pd.DataFrame) -> pd.DataFrame:
    """Replace ``+inf``/``-inf`` with ``NaN`` in numeric columns."""
    numeric_cols = df.select_dtypes(include=[np.number]).columns
    df[numeric_cols] = df[numeric_cols].replace([np.inf, -np.inf], np.nan)
    return df


def _encode_labels(df: pd.DataFrame) -> pd.DataFrame:
    """Create binary and multi-class label columns from the raw ``label``.

    The raw label is normalized (stripped/upper-cased) so casing or stray
    whitespace variants of ``BENIGN`` are treated consistently.
    """
    if LABEL_COLUMN not in df.columns:
        raise KeyError(
            f"Expected a '{LABEL_COLUMN}' column after normalization; "
            f"found columns: {list(df.columns)[:10]}..."
        )

    multiclass = df[LABEL_COLUMN].astype(str).str.strip().str.upper()
    df[MULTICLASS_LABEL_COLUMN] = multiclass
    df[BINARY_LABEL_COLUMN] = (multiclass != BENIGN_LABEL).astype(np.int64)
    return df


def _median_fill(df: pd.DataFrame, feature_cols: list[str]) -> pd.DataFrame:
    """Fill NaNs in ``feature_cols`` with each column's median.

    Medians are computed on the pre-fill data so that the fill values are not
    biased by the imputation itself.
    """
    medians = df[feature_cols].median(numeric_only=True)
    df[feature_cols] = df[feature_cols].fillna(medians)
    # A column that was entirely NaN has no median; fall back to 0 so the
    # downstream inf/NaN assertion cannot trip.
    df[feature_cols] = df[feature_cols].fillna(0.0)
    return df


def clean_data(df: pd.DataFrame) -> pd.DataFrame:
    """Run the full cleaning pipeline and return a validated DataFrame.

    Args:
        df: Raw concatenated DataFrame with snake_case columns.

    Returns:
        Cleaned DataFrame with ``label_binary`` and ``label_multiclass`` columns,
        no inf/NaN in features, and no duplicate rows.
    """
    start_rows = len(df)

    # 1. Infinities -> NaN so they are handled uniformly with other NaNs.
    df = _replace_infinities(df)

    # 2. Encode labels, then drop rows whose raw label was missing.
    df = _encode_labels(df)
    missing_label = df[LABEL_COLUMN].isna()
    if missing_label.any():
        print(f"[cleaner] Dropping {int(missing_label.sum()):,} rows with NaN label.")
        df = df.loc[~missing_label].copy()

    # 3. Median-fill numeric feature NaNs (exclude the encoded label columns).
    numeric_cols = df.select_dtypes(include=[np.number]).columns.tolist()
    feature_cols = [c for c in numeric_cols if c != BINARY_LABEL_COLUMN]
    df = _median_fill(df, feature_cols)

    # 4. Deduplicate exact rows.
    before_dedup = len(df)
    df = df.drop_duplicates().reset_index(drop=True)
    print(
        f"[cleaner] Dropped {before_dedup - len(df):,} duplicate rows "
        f"({len(df):,} remain)."
    )

    # 5. Validate.
    validate_clean(df, feature_cols)

    # 6. Log class distribution.
    log_class_distribution(df)

    print(f"[cleaner] Cleaning complete: {start_rows:,} -> {len(df):,} rows.")
    return df


def validate_clean(df: pd.DataFrame, feature_cols: list[str]) -> None:
    """Assert the cleaned frame has no inf/NaN features and binary labels."""
    feature_block = df[feature_cols]
    assert not np.isinf(feature_block.to_numpy()).any(), "Inf values remain in features."
    assert not feature_block.isna().any().any(), "NaN values remain in features."

    unique_labels = set(df[BINARY_LABEL_COLUMN].unique().tolist())
    assert unique_labels.issubset({0, 1}), (
        f"Binary label must be in {{0, 1}}; found {unique_labels}."
    )
    print("[cleaner] Validation passed: no inf/NaN, labels in {0, 1}.")


def log_class_distribution(df: pd.DataFrame) -> None:
    """Print the benign vs. attack counts and percentages."""
    total = len(df)
    attack = int(df[BINARY_LABEL_COLUMN].sum())
    benign = total - attack
    print(
        "[cleaner] Class distribution: "
        f"benign={benign:,} ({benign / total:.2%}), "
        f"attack={attack:,} ({attack / total:.2%})."
    )
