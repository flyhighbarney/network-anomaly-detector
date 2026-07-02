"""Central configuration: project paths and shared constants.

Every path is derived from this file's location so the project is portable and
contains no hardcoded absolute paths. Import the ``Paths`` object rather than
reconstructing directories in each module.
"""
from __future__ import annotations

from pathlib import Path

# ---------------------------------------------------------------------------
# Project layout
# ---------------------------------------------------------------------------
# This file lives at <root>/src/config.py, so the project root is two parents up.
PROJECT_ROOT: Path = Path(__file__).resolve().parents[1]


class Paths:
    """Filesystem locations for data and model artifacts."""

    root: Path = PROJECT_ROOT
    data_raw: Path = PROJECT_ROOT / "data" / "raw"
    data_processed: Path = PROJECT_ROOT / "data" / "processed"
    models: Path = PROJECT_ROOT / "models"

    # Individual artifacts saved by the training pipeline.
    isolation_forest: Path = models / "isolation_forest.joblib"
    random_forest: Path = models / "random_forest.joblib"
    scaler: Path = models / "scaler.joblib"
    feature_names: Path = models / "feature_names.json"
    metrics: Path = models / "metrics.json"

    # Generated charts (PNG) consumed by the dashboard.
    cm_isolation_forest: Path = models / "cm_isolation_forest.png"
    cm_random_forest: Path = models / "cm_random_forest.png"
    roc_random_forest: Path = models / "roc_random_forest.png"
    feature_importance: Path = models / "feature_importance.png"
    attack_breakdown: Path = models / "attack_breakdown.png"

    @classmethod
    def ensure_dirs(cls) -> None:
        """Create the data/model output directories if they do not exist."""
        for directory in (cls.data_raw, cls.data_processed, cls.models):
            directory.mkdir(parents=True, exist_ok=True)


# ---------------------------------------------------------------------------
# Feature configuration (shared by training and prediction so the pipeline is
# identical in both paths — a common source of train/serve skew otherwise).
# ---------------------------------------------------------------------------

# The label column after snake_case normalization.
LABEL_COLUMN: str = "label"
BINARY_LABEL_COLUMN: str = "label_binary"
MULTICLASS_LABEL_COLUMN: str = "label_multiclass"

# 15 base features selected from CICIDS2017 (post snake_case normalization).
BASE_FEATURES: list[str] = [
    "flow_duration",
    "total_fwd_packets",
    "total_backward_packets",
    "total_length_of_fwd_packets",
    "total_length_of_bwd_packets",
    "fwd_packet_length_max",
    "fwd_packet_length_mean",
    "bwd_packet_length_max",
    "bwd_packet_length_mean",
    "flow_bytes_per_s",
    "flow_packets_per_s",
    "flow_iat_mean",
    "flow_iat_max",
    "fwd_iat_mean",
    "bwd_iat_mean",
]

# 3 engineered features, appended after the base features.
DERIVED_FEATURES: list[str] = [
    "packet_ratio",
    "bytes_per_packet",
    "flow_asymmetry",
]

# Full ordered feature list used to build the model input matrix.
ALL_FEATURES: list[str] = BASE_FEATURES + DERIVED_FEATURES

# Reproducibility seed used everywhere randomness appears.
RANDOM_STATE: int = 42
