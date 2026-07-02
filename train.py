"""Training entrypoint for the network anomaly detection pipeline.

Runs the full pipeline end to end:

    load -> clean -> engineer features -> split -> scale -> train -> evaluate
    -> save artifacts (models, scaler, feature names, metrics, charts).

Usage:
    python train.py                       # full run on data/raw/
    python train.py --data-dir path/      # custom data directory
    python train.py --model rf            # train only the Random Forest
    python train.py --skip-training       # re-evaluate saved models

Every stochastic component is seeded with random_state=42 for reproducibility.
"""
from __future__ import annotations

import argparse
import json

import joblib

from src.config import ALL_FEATURES, Paths
from src.data.cleaner import clean_data
from src.data.features import SplitData, split_and_scale, verify_no_leakage
from src.data.loader import load_raw_data
from src.models import evaluate, isolation_forest, random_forest


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--data-dir",
        default=str(Paths.data_raw),
        help="Directory containing the raw CICIDS2017 CSV files.",
    )
    parser.add_argument(
        "--skip-training",
        action="store_true",
        help="Load existing saved models and only re-evaluate.",
    )
    parser.add_argument(
        "--model",
        choices=["rf", "if", "both"],
        default="both",
        help="Which model(s) to train: Random Forest, Isolation Forest, or both.",
    )
    return parser.parse_args()


def build_split(data_dir: str) -> SplitData:
    """Load, clean, and split/scale the dataset."""
    df = load_raw_data(data_dir)
    df = clean_data(df)
    split = split_and_scale(df)
    verify_no_leakage(split)
    return split


def run_random_forest(split: SplitData, skip_training: bool) -> dict:
    """Train (or load) and evaluate the Random Forest; save artifacts."""
    if skip_training and Paths.random_forest.exists():
        print("[train] Loading existing Random Forest ...")
        model = joblib.load(Paths.random_forest)
    else:
        model = random_forest.train_random_forest(split.X_train, split.y_train)
        joblib.dump(model, Paths.random_forest)
        print(f"[train] Saved Random Forest -> {Paths.random_forest.name}")

    y_pred = random_forest.predict(model, split.X_test)
    y_proba = random_forest.predict_proba(model, split.X_test)
    metrics = evaluate.evaluate_model(
        split.y_test, y_pred, y_proba, model_name="Random Forest"
    )

    # Charts specific to the supervised model.
    evaluate.plot_confusion_matrix(
        metrics["confusion_matrix"], "Random Forest", Paths.cm_random_forest
    )
    evaluate.plot_roc_curve(
        split.y_test, y_proba, "Random Forest", Paths.roc_random_forest
    )
    evaluate.plot_feature_importance(
        model.feature_importances_, ALL_FEATURES, Paths.feature_importance
    )
    evaluate.plot_attack_breakdown(
        split.multiclass_test, split.y_test, y_pred, Paths.attack_breakdown
    )

    if metrics["f1_macro"] < 0.97:
        print(
            f"[train] WARNING: Random Forest macro F1 {metrics['f1_macro']:.4f} "
            "is below the 0.97 target. Check for feature/data issues."
        )

    # Structured chart data for the dashboard's native (in-browser) charts.
    chart_data = {
        "roc": evaluate.roc_curve_data(split.y_test, y_proba),
        "feature_importance": evaluate.feature_importance_data(
            model.feature_importances_, ALL_FEATURES
        ),
        "attack_breakdown": evaluate.attack_breakdown_data(
            split.multiclass_test, y_pred
        ),
        "confusion": metrics["confusion_matrix"],
    }
    return metrics, chart_data


def run_isolation_forest(split: SplitData, skip_training: bool) -> dict:
    """Train (or load) and evaluate the Isolation Forest; save artifacts."""
    if skip_training and Paths.isolation_forest.exists():
        print("[train] Loading existing Isolation Forest ...")
        model = joblib.load(Paths.isolation_forest)
    else:
        model = isolation_forest.train_isolation_forest(split.X_train, split.y_train)
        joblib.dump(model, Paths.isolation_forest)
        print(f"[train] Saved Isolation Forest -> {Paths.isolation_forest.name}")

    y_pred = isolation_forest.predict(model, split.X_test)
    metrics = evaluate.evaluate_model(
        split.y_test, y_pred, y_proba=None, model_name="Isolation Forest"
    )
    evaluate.plot_confusion_matrix(
        metrics["confusion_matrix"], "Isolation Forest", Paths.cm_isolation_forest
    )
    return metrics, {"confusion": metrics["confusion_matrix"]}


def save_shared_artifacts(split: SplitData, all_metrics: dict, charts: dict) -> None:
    """Persist the scaler, feature names, and dataset/metrics summary."""
    joblib.dump(split.scaler, Paths.scaler)
    print(f"[train] Saved scaler -> {Paths.scaler.name}")

    Paths.feature_names.write_text(json.dumps(ALL_FEATURES, indent=2))
    print(f"[train] Saved feature names -> {Paths.feature_names.name}")

    # Dataset statistics for the dashboard overview page.
    n_test = int(len(split.y_test))
    n_train = int(len(split.y_train))
    total = n_train + n_test
    attack = int(split.y_train.sum() + split.y_test.sum())
    summary = {
        "dataset": {
            "total_records": total,
            "train_records": n_train,
            "test_records": n_test,
            "attack_count": attack,
            "benign_count": total - attack,
            "attack_ratio": attack / total if total else 0.0,
        },
        "models": all_metrics,
        "charts": charts,
    }
    Paths.metrics.write_text(json.dumps(summary, indent=2))
    print(f"[train] Saved metrics summary -> {Paths.metrics.name}")


def main() -> None:
    """Orchestrate the full pipeline."""
    args = parse_args()
    Paths.ensure_dirs()

    split = build_split(args.data_dir)

    all_metrics: dict = {}
    charts: dict = {"confusion": {}}
    if args.model in ("rf", "both"):
        metrics, rf_charts = run_random_forest(split, args.skip_training)
        all_metrics["random_forest"] = metrics
        charts["roc"] = rf_charts["roc"]
        charts["feature_importance"] = rf_charts["feature_importance"]
        charts["attack_breakdown"] = rf_charts["attack_breakdown"]
        charts["confusion"]["random_forest"] = rf_charts["confusion"]
    if args.model in ("if", "both"):
        metrics, if_charts = run_isolation_forest(split, args.skip_training)
        all_metrics["isolation_forest"] = metrics
        charts["confusion"]["isolation_forest"] = if_charts["confusion"]

    save_shared_artifacts(split, all_metrics, charts)

    metrics_list = [m for m in all_metrics.values()]
    if len(metrics_list) > 1:
        evaluate.print_comparison(metrics_list)

    print("[train] Pipeline complete.")


if __name__ == "__main__":
    main()
