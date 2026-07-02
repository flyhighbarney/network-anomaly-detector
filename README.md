# AI-Powered Network Anomaly Detection System

An end-to-end machine-learning pipeline that ingests CICIDS2017 network-flow
records, trains two complementary classifiers — a supervised **Random Forest**
and an unsupervised **Isolation Forest** — to distinguish benign traffic from
intrusions, and serves predictions and diagnostic insights through a Flask web
dashboard. The repository also ships a documented **security audit** of the
dashboard's own codebase.

---

## Dataset

**CICIDS2017** (Canadian Institute for Cybersecurity Intrusion Detection
Evaluation Dataset) — ~2.8 million labeled flow records across 8 CSV files
covering five days (Monday–Friday) of traffic, with benign flows plus 14 attack
types including DDoS, PortScan, Bot, Brute Force, Web Attack, Infiltration, and
Heartbleed. This project collapses the multi-class labels into a **binary**
target (`0` = BENIGN, `1` = any attack) while retaining the original labels for
the dashboard's attack-type breakdown.

### Download

The dataset is not bundled (it is large and `data/raw/` is gitignored). Get the
`MachineLearningCSV` files from either source and place all `.csv` files
directly in `data/raw/`:

- **UNB (official):** https://www.unb.ca/cic/datasets/ids-2017.html
- **Kaggle mirror:** search for "CICIDS2017" (the `MachineLearningCVE` folder).

```
data/raw/
  Monday-WorkingHours.pcap_ISCX.csv
  Tuesday-WorkingHours.pcap_ISCX.csv
  ... (8 files total)
```

The loader normalizes the CSVs' quirky headers (leading spaces, `Bytes/s`
suffixes) to snake_case automatically, so no manual header cleanup is needed.

---

## Setup

Requires Python 3.10+.

```bash
# 1. Install dependencies
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt

# 2. Download the CICIDS2017 CSVs into data/raw/ (see above)

# 3. Train models + generate charts and metrics
python train.py

# 4. Launch the dashboard (from the project root)
python -m src.dashboard.app
#   then open http://127.0.0.1:5000
```

### Training options

```bash
python train.py --data-dir path/to/csvs   # custom raw-data directory
python train.py --model rf                 # train only the Random Forest
python train.py --model if                 # train only the Isolation Forest
python train.py --skip-training            # reload saved models, re-evaluate only
```

Training writes all artifacts to `models/`:
`random_forest.joblib`, `isolation_forest.joblib`, `scaler.joblib`,
`feature_names.json`, `metrics.json`, and the chart PNGs the dashboard embeds.

---

## Project structure

```
network-anomaly-detector/
  data/
    raw/                     # CICIDS2017 CSVs (gitignored)
    processed/               # reserved for cleaned/feature-engineered data
  src/
    config.py                # paths + shared feature/label constants
    data/
      loader.py              # CSV ingestion, concat, snake_case columns
      cleaner.py             # inf/NaN handling, label encoding, dedup, validation
      features.py            # 15 base + 3 derived features, split, scaling
    models/
      isolation_forest.py    # unsupervised anomaly detector
      random_forest.py       # supervised classifier
      evaluate.py            # metrics + matplotlib/seaborn charts
    dashboard/
      app.py                 # Flask application
      templates/             # base / index / predict / insights (Jinja2)
      static/style.css
  security_audit/
    audit_report.md          # 15 findings mapped to CWE / OWASP Top 10
  models/                    # saved artifacts + charts (gitignored)
  train.py                   # training entrypoint
  requirements.txt
  README.md
```

---

## Pipeline overview

1. **Load** — concatenate all `data/raw/*.csv`, normalize headers to snake_case.
2. **Clean** — replace ±inf with NaN, drop NaN-label rows, median-fill feature
   NaNs, encode binary + multi-class labels, drop exact duplicates, validate.
3. **Engineer features** — 15 base flow features + 3 derived
   (`packet_ratio`, `bytes_per_packet`, `flow_asymmetry`).
4. **Split** — 80/20 **stratified** train/test split.
5. **Scale** — `StandardScaler` **fit on the training set only**, then applied to
   both sets. The pipeline asserts `scaler.mean_ == X_train.mean()` to prove no
   leakage.
6. **Train** — Random Forest (`class_weight='balanced'`) and Isolation Forest
   (`contamination` = training attack ratio), both `n_estimators=200`,
   `random_state=42`, `n_jobs=-1`.
7. **Evaluate** — precision/recall/F1 (macro + per class), confusion matrices,
   ROC-AUC and ROC curve (RF), feature importance, attack-type breakdown.
8. **Persist** — models, scaler, feature names, metrics summary, chart PNGs.

---

## Model performance

Run `python train.py` on the real CICIDS2017 data and paste your output here.
On CICIDS2017 the Random Forest comfortably clears the **97%+ macro-F1** target
(typically ~0.99), while the Isolation Forest — being unsupervised — trails it.

Example comparison table (format produced by `evaluate.print_comparison`):

```
==================================================================
MODEL COMPARISON
==================================================================
Metric                Random Forest         Isolation Forest
------------------------------------------------------------------
Accuracy              0.99xx                0.9x xx
Precision             0.99xx                0.9x xx
Recall                0.99xx                0.9x xx
F1 (macro)            0.99xx                0.9x xx
ROC-AUC               0.99xx                n/a
==================================================================
```

> The pipeline has been smoke-tested end to end on a synthetic CICIDS2017-shaped
> dataset (correct headers, injected inf/NaN/duplicates) to validate loading,
> cleaning, leakage-free scaling, training, evaluation, chart generation, and all
> dashboard routes. Replace the numbers above with your real run.

---

## Dashboard

Three pages, plain HTML/CSS/Jinja2 (no JS frameworks); a dark sidebar with a
white content area, monospace metrics, and green/yellow/red color coding
(F1 > 0.95 good, 0.90–0.95 acceptable, < 0.90 needs attention).

- **Overview (`/`)** — per-model metric cards (accuracy, precision, recall, F1,
  ROC-AUC), dataset statistics (total / benign / attack / attack ratio), a
  best-per-metric comparison table, and side-by-side confusion matrices.
- **Predict (`/predict`)** — upload a CSV of flows; the app applies the identical
  feature engineering, loads the saved scaler and both models, and returns a
  color-coded per-row table (green BENIGN / red ATTACK) plus a summary of how
  many flows each model flagged. Wrong columns, empty files, and non-numeric
  data are handled gracefully.
- **Insights (`/insights`)** — confusion matrices, the Random Forest ROC curve,
  the ranked feature-importance chart, and an attack-type breakdown with
  per-type detection rates.

If you open the dashboard before training, each page shows a "no trained models
found — run `train.py`" notice.

---

## Security audit

The dashboard is intentionally a straightforward, **un-hardened** Flask app so
that the audit reflects the real issues such applications carry. See
**[`security_audit/audit_report.md`](security_audit/audit_report.md)** for the
full write-up: 15 findings mapped to CWE IDs and the OWASP Top 10 (2021), each
with description, root cause, and remediation.

Highest-severity findings: Werkzeug **debug mode** enabled (RCE), **path
traversal** via unsanitized upload filename, **no authentication** on the
prediction endpoint, **insecure joblib/pickle deserialization**, and a
**hard-coded secret key**. Do not deploy the dashboard as-is — apply the
remediations first.

---

## Limitations

- **Dataset age (2017):** attack signatures and traffic patterns have shifted;
  models trained here will not reflect current threats without retraining on
  fresh data.
- **Binary simplification:** all 14 attack types are collapsed into a single
  "attack" class, so the models detect *that* traffic is anomalous, not *which*
  attack it is. The multi-class labels are retained only for the dashboard
  breakdown.
- **No live capture:** the system scores pre-extracted flow features (CICFlowMeter
  style) from CSV files; it does not sniff or featurize packets in real time.
- **Not production-hardened:** by design (see the security audit).
