"""Unsupervised anomaly detection with Isolation Forest.

Isolation Forest is trained without labels, but we set its ``contamination``
parameter to the observed attack ratio in the training labels so the decision
threshold matches the expected proportion of anomalies. Its native output
(-1 = anomaly, 1 = normal) is remapped to the project's label encoding
(1 = attack, 0 = benign).
"""
from __future__ import annotations

import numpy as np
from sklearn.ensemble import IsolationForest

from src.config import RANDOM_STATE


def train_isolation_forest(
    X_train: np.ndarray,
    y_train: np.ndarray,
    n_estimators: int = 200,
) -> IsolationForest:
    """Fit an Isolation Forest on the (scaled) training features.

    Args:
        X_train: Scaled training feature matrix.
        y_train: Binary training labels, used only to derive ``contamination``.
        n_estimators: Number of trees in the ensemble.

    Returns:
        The fitted :class:`~sklearn.ensemble.IsolationForest`.
    """
    contamination = float(np.clip(y_train.mean(), 1e-4, 0.5))
    print(
        f"[isolation_forest] Training with contamination={contamination:.4f}, "
        f"n_estimators={n_estimators} ..."
    )

    model = IsolationForest(
        n_estimators=n_estimators,
        contamination=contamination,
        random_state=RANDOM_STATE,
        n_jobs=-1,
    )
    model.fit(X_train)
    print("[isolation_forest] Training complete.")
    return model


def predict(model: IsolationForest, X: np.ndarray) -> np.ndarray:
    """Predict binary labels (1 = attack, 0 = benign) for ``X``.

    Maps Isolation Forest's native output: ``-1`` (anomaly) -> ``1`` (attack)
    and ``1`` (normal) -> ``0`` (benign).
    """
    raw = model.predict(X)
    return (raw == -1).astype(np.int64)
