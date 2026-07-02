"""Feature selection, engineering, splitting, and scaling.

Exposes a single reusable path so that training and prediction perform the
*identical* transformation (base selection -> derived features -> scaling),
which prevents train/serve skew. The scaler is always fit on training data only
and persisted for reuse at prediction time.
"""
from __future__ import annotations

from dataclasses import dataclass

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

from src.config import (
    ALL_FEATURES,
    BASE_FEATURES,
    BINARY_LABEL_COLUMN,
    DERIVED_FEATURES,
    MULTICLASS_LABEL_COLUMN,
    RANDOM_STATE,
)


@dataclass
class SplitData:
    """Container for the outputs of :func:`split_and_scale`."""

    X_train: np.ndarray
    X_test: np.ndarray
    y_train: np.ndarray
    y_test: np.ndarray
    multiclass_test: pd.Series
    scaler: StandardScaler
    # Unscaled training matrix, retained so the caller can verify that the
    # scaler was fit on training data only (scaler.mean_ == X_train_raw.mean()).
    X_train_raw: pd.DataFrame


def add_derived_features(df: pd.DataFrame) -> pd.DataFrame:
    """Append the three engineered features to a copy of ``df``.

    The base feature columns must already be present. A ``+1`` term is added to
    each denominator to avoid division by zero.

    Args:
        df: DataFrame containing the base CICIDS2017 features.

    Returns:
        A copy of ``df`` with ``packet_ratio``, ``bytes_per_packet`` and
        ``flow_asymmetry`` columns added.
    """
    df = df.copy()

    fwd_pkts = df["total_fwd_packets"]
    bwd_pkts = df["total_backward_packets"]
    fwd_len = df["total_length_of_fwd_packets"]
    bwd_len = df["total_length_of_bwd_packets"]

    df["packet_ratio"] = fwd_pkts / (bwd_pkts + 1)
    df["bytes_per_packet"] = (fwd_len + bwd_len) / (fwd_pkts + bwd_pkts + 1)
    df["flow_asymmetry"] = (fwd_len - bwd_len).abs() / (fwd_len + bwd_len + 1)

    return df


def select_features(df: pd.DataFrame) -> pd.DataFrame:
    """Return an ordered feature matrix (base + derived) from ``df``.

    Used by both the training pipeline and the prediction endpoint. Missing base
    columns raise a clear error; the derived features are computed here.

    Args:
        df: DataFrame with snake_case columns including all base features.

    Returns:
        DataFrame with exactly the columns in ``ALL_FEATURES``, in order.

    Raises:
        KeyError: If any required base feature column is absent.
    """
    missing = [c for c in BASE_FEATURES if c not in df.columns]
    if missing:
        raise KeyError(
            f"Input is missing {len(missing)} required feature column(s): {missing}"
        )

    engineered = add_derived_features(df)
    matrix = engineered[ALL_FEATURES].copy()

    # Guard against inf/NaN introduced by division in engineered features or by
    # unclean prediction input (median-fill is only applied during training).
    matrix = matrix.replace([np.inf, -np.inf], np.nan)
    matrix = matrix.fillna(matrix.median(numeric_only=True)).fillna(0.0)
    return matrix


def split_and_scale(df: pd.DataFrame, test_size: float = 0.20) -> SplitData:
    """Build features, split 80/20 stratified, and scale (fit on train only).

    Args:
        df: Cleaned DataFrame with feature columns and the binary label.
        test_size: Fraction of data held out for testing.

    Returns:
        A :class:`SplitData` bundle with scaled train/test matrices, labels,
        the fitted scaler, and the raw training matrix for leakage verification.
    """
    X = select_features(df)
    y = df[BINARY_LABEL_COLUMN].to_numpy()
    multiclass = df[MULTICLASS_LABEL_COLUMN]

    X_train_raw, X_test_raw, y_train, y_test, _, multiclass_test = train_test_split(
        X,
        y,
        multiclass,
        test_size=test_size,
        stratify=y,
        random_state=RANDOM_STATE,
    )

    # Fit ONLY on training data, then transform both sets — no leakage.
    scaler = StandardScaler()
    X_train = scaler.fit_transform(X_train_raw)
    X_test = scaler.transform(X_test_raw)

    print(
        f"[features] Split: train={len(y_train):,} rows, test={len(y_test):,} rows "
        f"({len(DERIVED_FEATURES)} derived + {len(BASE_FEATURES)} base features)."
    )

    return SplitData(
        X_train=X_train,
        X_test=X_test,
        y_train=y_train,
        y_test=y_test,
        multiclass_test=multiclass_test.reset_index(drop=True),
        scaler=scaler,
        X_train_raw=X_train_raw,
    )


def verify_no_leakage(split: SplitData, tolerance: float = 1e-6) -> None:
    """Assert the scaler statistics match the *training* data, not the full set.

    This is the concrete check the specification calls for: ``scaler.mean_``
    must equal ``X_train.mean()``.
    """
    train_means = split.X_train_raw.mean().to_numpy()
    if not np.allclose(split.scaler.mean_, train_means, atol=tolerance):
        raise AssertionError(
            "Data leakage detected: scaler.mean_ does not match X_train.mean(). "
            "The scaler must be fit on training data only."
        )
    print("[features] Leakage check passed: scaler fit on training data only.")
