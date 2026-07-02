"""Flask web dashboard for the network anomaly detection system.

Three pages:
    /          Model metrics overview and dataset statistics.
    /predict   Upload a CSV of network flows and get per-flow predictions.
    /insights  Confusion matrices, ROC curve, feature importance, attack mix.

Run from the project root with either:
    python -m src.dashboard.app
    flask --app src.dashboard.app run

NOTE: This module is deliberately a straightforward, un-hardened Flask app so
that ``security_audit/audit_report.md`` can document the real vulnerabilities
that such an application contains. Do not deploy it as-is; see the audit report
for the remediations.
"""
from __future__ import annotations

import json
from pathlib import Path

import joblib
import pandas as pd
from flask import Flask, flash, redirect, render_template, request, send_file, url_for

from src.config import Paths
from src.data.features import select_features
from src.data.loader import normalize_columns

app = Flask(__name__)
app.secret_key = "dev-secret-key-change-me"  # noqa: S105  (flagged in audit V-02)

UPLOAD_DIR = Path(__file__).resolve().parent / "uploads"
UPLOAD_DIR.mkdir(exist_ok=True)


# ---------------------------------------------------------------------------
# Artifact loading
# ---------------------------------------------------------------------------


def load_artifacts() -> dict:
    """Load trained models, scaler, and metrics from ``models/`` if present.

    Returns a dict with whatever is available; the dashboard degrades
    gracefully (showing a "train first" notice) when artifacts are missing.
    """
    artifacts: dict = {"trained": False}
    if Paths.metrics.exists():
        artifacts["metrics"] = json.loads(Paths.metrics.read_text())
    if Paths.random_forest.exists():
        artifacts["rf"] = joblib.load(Paths.random_forest)
    if Paths.isolation_forest.exists():
        artifacts["if"] = joblib.load(Paths.isolation_forest)
    if Paths.scaler.exists():
        artifacts["scaler"] = joblib.load(Paths.scaler)
    artifacts["trained"] = all(
        k in artifacts for k in ("metrics", "rf", "if", "scaler")
    )
    return artifacts


ARTIFACTS = load_artifacts()


# ---------------------------------------------------------------------------
# Chart serving (PNGs live in models/, outside the Flask static folder)
# ---------------------------------------------------------------------------

CHART_FILES = {
    "cm_random_forest": Paths.cm_random_forest,
    "cm_isolation_forest": Paths.cm_isolation_forest,
    "roc_random_forest": Paths.roc_random_forest,
    "feature_importance": Paths.feature_importance,
    "attack_breakdown": Paths.attack_breakdown,
}


@app.route("/chart/<name>")
def chart(name: str):
    """Serve a generated chart PNG by whitelisted name."""
    path = CHART_FILES.get(name)
    if path is None or not path.exists():
        return "Chart not found", 404
    return send_file(path, mimetype="image/png")


# ---------------------------------------------------------------------------
# Page 1: overview
# ---------------------------------------------------------------------------


@app.route("/")
def index():
    """Model metrics overview and dataset statistics."""
    metrics = ARTIFACTS.get("metrics")
    return render_template(
        "index.html",
        trained=ARTIFACTS["trained"],
        metrics=metrics,
        charts_available=CHART_FILES,
    )


# ---------------------------------------------------------------------------
# Page 2: prediction
# ---------------------------------------------------------------------------


def _predict_dataframe(df: pd.DataFrame) -> dict:
    """Run both models on an uploaded dataframe and build a result payload."""
    df = normalize_columns(df)
    X = select_features(df)
    X_scaled = ARTIFACTS["scaler"].transform(X)

    rf_pred = ARTIFACTS["rf"].predict(X_scaled).astype(int)
    if_raw = ARTIFACTS["if"].predict(X_scaled)
    if_pred = (if_raw == -1).astype(int)

    rows = []
    for i in range(len(X)):
        rows.append(
            {
                "index": i,
                "rf": "ATTACK" if rf_pred[i] == 1 else "BENIGN",
                "if": "ATTACK" if if_pred[i] == 1 else "BENIGN",
                "features": {k: round(float(v), 4) for k, v in X.iloc[i].items()},
            }
        )

    return {
        "rows": rows,
        "total": len(X),
        "rf_flagged": int(rf_pred.sum()),
        "if_flagged": int(if_pred.sum()),
    }


@app.route("/predict", methods=["GET", "POST"])
def predict():
    """CSV upload and real-time prediction with both models."""
    if not ARTIFACTS["trained"]:
        flash("Models are not trained yet. Run train.py first.")
        return render_template("predict.html", trained=False, result=None)

    if request.method == "GET":
        return render_template("predict.html", trained=True, result=None)

    # --- POST: handle the uploaded CSV ---
    if "file" not in request.files or request.files["file"].filename == "":
        flash("No file selected.")
        return redirect(url_for("predict"))

    upload = request.files["file"]
    saved_path = UPLOAD_DIR / upload.filename  # audit V-03: unsanitized filename
    upload.save(saved_path)

    try:
        df = pd.read_csv(saved_path)
        if df.empty:
            flash("Uploaded file contains no rows.")
            return redirect(url_for("predict"))
        result = _predict_dataframe(df)
    except KeyError as exc:
        flash(f"Missing required columns: {exc}")  # audit V-08: verbose errors
        return redirect(url_for("predict"))
    except Exception as exc:  # noqa: BLE001
        flash(f"Could not process file: {exc}")  # audit V-08: verbose errors
        return redirect(url_for("predict"))

    return render_template(
        "predict.html", trained=True, result=result, filename=upload.filename
    )


# ---------------------------------------------------------------------------
# Page 3: insights
# ---------------------------------------------------------------------------


@app.route("/insights")
def insights():
    """Confusion matrices, ROC curve, feature importance, attack breakdown."""
    metrics = ARTIFACTS.get("metrics")
    return render_template(
        "insights.html",
        trained=ARTIFACTS["trained"],
        metrics=metrics,
        charts_available=CHART_FILES,
    )


if __name__ == "__main__":
    # audit V-01 (debug), V-04 (no auth), V-11 (bind all interfaces)
    app.run(host="0.0.0.0", port=5000, debug=True)  # noqa: S104,S201
