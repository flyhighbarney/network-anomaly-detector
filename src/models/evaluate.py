"""Model evaluation: metrics computation, chart generation, and comparison.

All plots are written to the ``models/`` directory as PNGs so the Flask
dashboard can embed them with plain ``<img>`` tags. Matplotlib uses the
non-interactive Agg backend so this runs headless (CI, servers).
"""
from __future__ import annotations

from pathlib import Path
from typing import Optional

import matplotlib

matplotlib.use("Agg")  # Headless backend; must be set before pyplot import.

import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402
import seaborn as sns  # noqa: E402
from sklearn.metrics import (  # noqa: E402
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
    roc_curve,
)

CLASS_NAMES = ["BENIGN", "ATTACK"]


def evaluate_model(
    y_true: np.ndarray,
    y_pred: np.ndarray,
    y_proba: Optional[np.ndarray] = None,
    model_name: str = "model",
) -> dict:
    """Compute a standard metric bundle for a binary classifier.

    Args:
        y_true: Ground-truth binary labels.
        y_pred: Predicted binary labels.
        y_proba: Optional attack-class probabilities (enables ROC-AUC).
        model_name: Human-readable model name (stored in the result).

    Returns:
        Dictionary of metrics: accuracy, precision, recall, f1_macro,
        f1_per_class, confusion_matrix (as nested lists), and roc_auc.
    """
    metrics: dict = {
        "model_name": model_name,
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "precision": float(precision_score(y_true, y_pred, zero_division=0)),
        "recall": float(recall_score(y_true, y_pred, zero_division=0)),
        "f1_macro": float(f1_score(y_true, y_pred, average="macro", zero_division=0)),
        "f1_per_class": [
            float(v)
            for v in f1_score(y_true, y_pred, average=None, labels=[0, 1], zero_division=0)
        ],
        "confusion_matrix": confusion_matrix(y_true, y_pred, labels=[0, 1]).tolist(),
        "roc_auc": None,
    }
    if y_proba is not None:
        metrics["roc_auc"] = float(roc_auc_score(y_true, y_proba))

    _log_metrics(metrics)
    return metrics


def _log_metrics(m: dict) -> None:
    """Print a single model's metrics to stdout."""
    roc = f"{m['roc_auc']:.4f}" if m["roc_auc"] is not None else "n/a"
    print(
        f"[evaluate] {m['model_name']}: "
        f"acc={m['accuracy']:.4f} prec={m['precision']:.4f} "
        f"rec={m['recall']:.4f} f1_macro={m['f1_macro']:.4f} "
        f"f1[benign,attack]={[round(v, 4) for v in m['f1_per_class']]} roc_auc={roc}"
    )


# ---------------------------------------------------------------------------
# Charts
# ---------------------------------------------------------------------------


def plot_confusion_matrix(cm: list, model_name: str, out_path: Path) -> None:
    """Save an annotated confusion-matrix heatmap."""
    cm_arr = np.array(cm)
    fig, ax = plt.subplots(figsize=(5, 4))
    sns.heatmap(
        cm_arr,
        annot=True,
        fmt=",d",
        cmap="Blues",
        cbar=False,
        xticklabels=CLASS_NAMES,
        yticklabels=CLASS_NAMES,
        ax=ax,
    )
    ax.set_xlabel("Predicted")
    ax.set_ylabel("Actual")
    ax.set_title(f"Confusion Matrix — {model_name}")
    fig.tight_layout()
    fig.savefig(out_path, dpi=120)
    plt.close(fig)
    print(f"[evaluate] Saved confusion matrix -> {out_path.name}")


def plot_roc_curve(
    y_true: np.ndarray, y_proba: np.ndarray, model_name: str, out_path: Path
) -> None:
    """Save a ROC curve with the AUC annotated."""
    fpr, tpr, _ = roc_curve(y_true, y_proba)
    auc = roc_auc_score(y_true, y_proba)
    fig, ax = plt.subplots(figsize=(5, 4))
    ax.plot(fpr, tpr, color="#c0392b", lw=2, label=f"AUC = {auc:.4f}")
    ax.plot([0, 1], [0, 1], color="#7f8c8d", lw=1, linestyle="--", label="Random")
    ax.set_xlabel("False Positive Rate")
    ax.set_ylabel("True Positive Rate")
    ax.set_title(f"ROC Curve — {model_name}")
    ax.legend(loc="lower right")
    fig.tight_layout()
    fig.savefig(out_path, dpi=120)
    plt.close(fig)
    print(f"[evaluate] Saved ROC curve -> {out_path.name}")


def plot_feature_importance(
    importances: np.ndarray, feature_names: list, out_path: Path, top_n: int = 18
) -> None:
    """Save a horizontal bar chart of the top-N feature importances."""
    order = np.argsort(importances)[::-1][:top_n]
    names = [feature_names[i] for i in order]
    values = importances[order]

    fig, ax = plt.subplots(figsize=(7, 6))
    ax.barh(range(len(names)), values, color="#2980b9")
    ax.set_yticks(range(len(names)))
    ax.set_yticklabels(names)
    ax.invert_yaxis()  # Most important at the top.
    ax.set_xlabel("Importance")
    ax.set_title("Random Forest Feature Importance")
    fig.tight_layout()
    fig.savefig(out_path, dpi=120)
    plt.close(fig)
    print(f"[evaluate] Saved feature importance -> {out_path.name}")


def plot_attack_breakdown(
    multiclass_test: pd.Series,
    y_true: np.ndarray,
    y_pred: np.ndarray,
    out_path: Path,
) -> None:
    """Save a bar chart of attack-type counts with per-type detection rates.

    Detection rate for a type = fraction of that type's flows predicted as an
    attack. BENIGN is excluded from the detection-rate view.
    """
    df = pd.DataFrame(
        {"type": multiclass_test.to_numpy(), "true": y_true, "pred": y_pred}
    )
    attacks = df[df["type"] != "BENIGN"]
    if attacks.empty:
        print("[evaluate] No attack types present; skipping breakdown chart.")
        return

    grouped = attacks.groupby("type").agg(
        count=("pred", "size"),
        detected=("pred", "sum"),
    )
    grouped["detection_rate"] = grouped["detected"] / grouped["count"]
    grouped = grouped.sort_values("count", ascending=True)

    fig, ax = plt.subplots(figsize=(8, max(4, 0.4 * len(grouped) + 2)))
    bars = ax.barh(grouped.index, grouped["count"], color="#8e44ad")
    ax.set_xlabel("Flow count (test set)")
    ax.set_title("Attack Type Breakdown & Detection Rate")
    for bar, rate in zip(bars, grouped["detection_rate"]):
        ax.text(
            bar.get_width(),
            bar.get_y() + bar.get_height() / 2,
            f"  {rate:.1%} detected",
            va="center",
            fontsize=8,
        )
    fig.tight_layout()
    fig.savefig(out_path, dpi=120)
    plt.close(fig)
    print(f"[evaluate] Saved attack breakdown -> {out_path.name}")


# ---------------------------------------------------------------------------
# Comparison
# ---------------------------------------------------------------------------


def _sample_curve(xs: np.ndarray, ys: np.ndarray, max_points: int = 140) -> tuple:
    """Downsample paired arrays to at most ``max_points`` (keeping endpoints)."""
    n = len(xs)
    if n <= max_points:
        idx = range(n)
    else:
        step = n / max_points
        idx = sorted({int(i * step) for i in range(max_points)} | {0, n - 1})
    return [round(float(xs[i]), 5) for i in idx], [round(float(ys[i]), 5) for i in idx]


def roc_curve_data(y_true: np.ndarray, y_proba: np.ndarray) -> dict:
    """Return sampled ROC-curve points and AUC for client-side rendering."""
    fpr, tpr, _ = roc_curve(y_true, y_proba)
    fx, tx = _sample_curve(fpr, tpr)
    return {"fpr": fx, "tpr": tx, "auc": float(roc_auc_score(y_true, y_proba))}


def feature_importance_data(importances: np.ndarray, feature_names: list) -> list:
    """Return feature-importance pairs sorted descending."""
    pairs = sorted(
        zip(feature_names, importances), key=lambda p: p[1], reverse=True
    )
    return [{"name": n, "importance": round(float(v), 6)} for n, v in pairs]


def attack_breakdown_data(
    multiclass_test: pd.Series, y_pred: np.ndarray, top_n: int = 14
) -> list:
    """Return per-attack-type counts and detection rates (RF predictions)."""
    df = pd.DataFrame({"type": multiclass_test.to_numpy(), "pred": y_pred})
    attacks = df[df["type"] != "BENIGN"]
    if attacks.empty:
        return []
    grouped = attacks.groupby("type").agg(
        count=("pred", "size"), detected=("pred", "sum")
    )
    grouped["rate"] = grouped["detected"] / grouped["count"]
    grouped = grouped.sort_values("count", ascending=False).head(top_n)
    return [
        {
            "type": str(t),
            "count": int(r["count"]),
            "detected": int(r["detected"]),
            "detection_rate": round(float(r["rate"]), 4),
        }
        for t, r in grouped.iterrows()
    ]


def print_comparison(metrics_list: list) -> None:
    """Print a side-by-side comparison table of model metrics to stdout."""
    headers = ["Metric"] + [m["model_name"] for m in metrics_list]
    rows = [
        ("Accuracy", "accuracy"),
        ("Precision", "precision"),
        ("Recall", "recall"),
        ("F1 (macro)", "f1_macro"),
        ("ROC-AUC", "roc_auc"),
    ]

    col_w = 22
    line = "".join(h.ljust(col_w) for h in headers)
    print("\n" + "=" * len(line))
    print("MODEL COMPARISON")
    print("=" * len(line))
    print(line)
    print("-" * len(line))
    for label, key in rows:
        cells = [label]
        for m in metrics_list:
            val = m.get(key)
            cells.append("n/a" if val is None else f"{val:.4f}")
        print("".join(c.ljust(col_w) for c in cells))
    print("=" * len(line) + "\n")
