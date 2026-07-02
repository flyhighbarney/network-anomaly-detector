"""Supervised classification with Random Forest.

A balanced Random Forest handles the benign-heavy class imbalance well and is
the project's primary detector (target: 97%+ macro F1 on CICIDS2017).
"""
from __future__ import annotations

import numpy as np
from sklearn.ensemble import RandomForestClassifier

from src.config import RANDOM_STATE


def train_random_forest(
    X_train: np.ndarray,
    y_train: np.ndarray,
    n_estimators: int = 200,
) -> RandomForestClassifier:
    """Fit a balanced Random Forest classifier on the training data.

    Args:
        X_train: Scaled training feature matrix.
        y_train: Binary training labels.
        n_estimators: Number of trees in the forest.

    Returns:
        The fitted :class:`~sklearn.ensemble.RandomForestClassifier`.
    """
    print(
        f"[random_forest] Training with n_estimators={n_estimators}, "
        "class_weight='balanced' ..."
    )
    model = RandomForestClassifier(
        n_estimators=n_estimators,
        class_weight="balanced",
        random_state=RANDOM_STATE,
        n_jobs=-1,
    )
    model.fit(X_train, y_train)
    print("[random_forest] Training complete.")
    return model


def predict(model: RandomForestClassifier, X: np.ndarray) -> np.ndarray:
    """Predict binary labels (1 = attack, 0 = benign) for ``X``."""
    return model.predict(X).astype(np.int64)


def predict_proba(model: RandomForestClassifier, X: np.ndarray) -> np.ndarray:
    """Return the predicted probability of the attack class (label 1)."""
    # Column index of class label 1 within model.classes_ (robust to ordering).
    attack_idx = list(model.classes_).index(1)
    return model.predict_proba(X)[:, attack_idx]
