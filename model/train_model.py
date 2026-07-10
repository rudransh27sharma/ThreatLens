"""Train PhishGuard's CPU-only phishing classifiers (v4).

Changes vs v3:
  - URL feature order expanded: +domain_entropy, +digit_ratio_in_domain,
    +hyphen_count_in_domain  (14 features total)
  - Text feature order expanded: +uppercase_ratio, +exclamation_count,
    +url_count_in_text, +keyword_density, +suspicious_tld_in_body
    (11 features total)
  - RandomizedSearchCV hyperparameter tuning for Random Forest
    (n_estimators, max_depth, min_samples_split, min_samples_leaf,
     max_features) — maximises F1 over 5-fold stratified CV.
  - Full metrics report: Accuracy, Precision, Recall, F1, ROC-AUC,
    Confusion Matrix, Cross-Validation F1 mean ± std.
  - Best model (RF vs LR by test-F1) saved as production artifact.
  - feature_importances JSON updated after every run.
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import (
    RandomizedSearchCV,
    StratifiedKFold,
    cross_val_score,
    train_test_split,
)
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from model.features import extract_all_features, sender_domain_mismatch

DATASET_PATH = ROOT / "data" / "phishing_dataset.csv"
MODEL_DIR    = ROOT / "model"

# ---------------------------------------------------------------------------
# Feature orders — must match extract_all_features() output keys exactly.
# domain_age_days is intentionally excluded (runtime-only / WHOIS-dependent).
# ---------------------------------------------------------------------------

URL_FEATURE_ORDER = [
    "url_length",
    "num_subdomains",
    "has_ip_address",
    "uses_url_shortener",
    "has_https",
    "count_special_chars",
    "has_suspicious_keywords_in_domain",
    "has_at_symbol",
    "path_depth",
    "query_param_count",
    "tld_suspicious",
    "domain_entropy",
    "digit_ratio_in_domain",
    "hyphen_count_in_domain",
]

TEXT_FEATURE_ORDER = [
    "urgency_score",
    "requests_sensitive_info",
    "generic_greeting",
    "link_text_mismatch",
    "grammar_error_density",
    "sender_domain_mismatch",
    "uppercase_ratio",
    "exclamation_count",
    "url_count_in_text",
    "keyword_density",
    "suspicious_tld_in_body",
]

# ---------------------------------------------------------------------------
# Hyperparameter search space for Random Forest
# ---------------------------------------------------------------------------

RF_PARAM_DIST = {
    "n_estimators":      [200, 300, 400, 500, 600],
    "max_depth":         [8, 10, 12, 15, 20, None],
    "min_samples_split": [2, 4, 6, 8, 10],
    "min_samples_leaf":  [1, 2, 3, 4],
    "max_features":      ["sqrt", "log2", 0.5, 0.7],
    "class_weight":      [None, "balanced"],
}

RF_SEARCH_ITERS  = 30   # number of random combinations to try
RF_CV_FOLDS      = 5    # folds for both search and final CV report

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _numeric(value: Any) -> float:
    if value is None:
        return 0.0
    if isinstance(value, bool):
        return 1.0 if value else 0.0
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def build_url_matrix(df: pd.DataFrame) -> pd.DataFrame:
    rows = []
    for _, row in df.iterrows():
        extracted = extract_all_features(str(row["content"]), "url")
        rows.append({name: _numeric(extracted.get(name, 0)) for name in URL_FEATURE_ORDER})
    return pd.DataFrame(rows, columns=URL_FEATURE_ORDER)


def build_text_matrix(df: pd.DataFrame) -> pd.DataFrame:
    rows = []
    for _, row in df.iterrows():
        content    = str(row["content"])
        ct         = str(row["content_type"])
        extracted  = extract_all_features(content, ct)
        claimed    = row.get("claimed_brand", "") or ""
        sender     = row.get("sender_domain",  "") or ""
        extracted["sender_domain_mismatch"] = sender_domain_mismatch(content, claimed, sender)
        rows.append({name: _numeric(extracted.get(name, 0)) for name in TEXT_FEATURE_ORDER})
    return pd.DataFrame(rows, columns=TEXT_FEATURE_ORDER)


def _rf_importances(model: RandomForestClassifier, feature_order: list[str]) -> dict[str, float]:
    total = float(np.sum(model.feature_importances_))
    if total == 0:
        return {name: 0.0 for name in feature_order}
    return {name: float(w / total) for name, w in zip(feature_order, model.feature_importances_)}


def _lr_importances(pipeline: Pipeline, feature_order: list[str]) -> dict[str, float]:
    lr: LogisticRegression = pipeline.named_steps["lr"]
    weights = np.abs(lr.coef_[0])
    total = float(weights.sum())
    if total == 0:
        return {name: 0.0 for name in feature_order}
    return {name: float(w / total) for name, w in zip(feature_order, weights)}

# ---------------------------------------------------------------------------
# Metrics printer
# ---------------------------------------------------------------------------

def _print_metrics(tag: str, y_true, y_pred, y_proba=None) -> dict[str, float]:
    acc  = accuracy_score(y_true, y_pred)
    prec = precision_score(y_true, y_pred, zero_division=0)
    rec  = recall_score(y_true, y_pred, zero_division=0)
    f1   = f1_score(y_true, y_pred, zero_division=0)
    auc  = roc_auc_score(y_true, y_proba) if y_proba is not None else float("nan")
    cm   = confusion_matrix(y_true, y_pred)

    bar = "─" * 56
    print(f"\n{bar}")
    print(f"  {tag}")
    print(bar)
    print(f"  Accuracy   : {acc:.4f}")
    print(f"  Precision  : {prec:.4f}")
    print(f"  Recall     : {rec:.4f}")
    print(f"  F1-score   : {f1:.4f}")
    if not np.isnan(auc):
        print(f"  ROC-AUC    : {auc:.4f}")
    print(f"  Confusion matrix (rows=actual, cols=predicted):")
    print(f"    TN={cm[0,0]:5d}  FP={cm[0,1]:5d}")
    print(f"    FN={cm[1,0]:5d}  TP={cm[1,1]:5d}")
    return {"accuracy": acc, "precision": prec, "recall": rec, "f1": f1, "auc": auc}


# ---------------------------------------------------------------------------
# Core training routine
# ---------------------------------------------------------------------------

def train_one(
    name: str,
    x: pd.DataFrame,
    y: pd.Series,
    feature_order: list[str],
):
    sep = "═" * 70
    print(f"\n{sep}")
    print(f"  Training: {name}   n={len(x)}   features={len(feature_order)}")
    print(sep)

    x_tr, x_te, y_tr, y_te = train_test_split(
        x, y, test_size=0.20, stratify=y, random_state=42
    )

    # ── Random Forest with RandomizedSearchCV ────────────────────────────
    print(f"\n  [RF] RandomizedSearchCV  iters={RF_SEARCH_ITERS}  cv={RF_CV_FOLDS}  scoring=f1")
    t0 = time.perf_counter()

    base_rf = RandomForestClassifier(random_state=42, n_jobs=-1)
    cv_split = StratifiedKFold(n_splits=RF_CV_FOLDS, shuffle=True, random_state=42)

    search = RandomizedSearchCV(
        estimator=base_rf,
        param_distributions=RF_PARAM_DIST,
        n_iter=RF_SEARCH_ITERS,
        scoring="f1",
        cv=cv_split,
        n_jobs=-1,
        random_state=42,
        refit=True,
        verbose=0,
    )
    search.fit(x_tr, y_tr)
    rf: RandomForestClassifier = search.best_estimator_

    elapsed = time.perf_counter() - t0
    print(f"  Best params ({elapsed:.1f}s):")
    for k, v in sorted(search.best_params_.items()):
        print(f"    {k}: {v}")
    print(f"  CV F1 (search best): {search.best_score_:.4f}")

    # ── Logistic Regression baseline ────────────────────────────────────
    print(f"\n  [LR] Logistic Regression baseline")
    lr_pipe = Pipeline([
        ("scaler", StandardScaler()),
        ("lr", LogisticRegression(max_iter=2000, C=1.0, random_state=42)),
    ])
    lr_pipe.fit(x_tr, y_tr)

    # ── Evaluation on held-out test set ─────────────────────────────────
    rf_proba = rf.predict_proba(x_te)[:, 1]
    lr_proba = lr_pipe.predict_proba(x_te)[:, 1]

    rf_metrics = _print_metrics(f"{name} / RandomForest  (80/20 split)", y_te, rf.predict(x_te), rf_proba)
    lr_metrics = _print_metrics(f"{name} / LogisticRegression  (80/20 split)", y_te, lr_pipe.predict(x_te), lr_proba)

    # ── 5-fold CV on full dataset with best RF params ────────────────────
    print(f"\n  [RF] 5-fold stratified CV on full dataset …")
    rf_cv = cross_val_score(
        RandomForestClassifier(**search.best_params_, random_state=42, n_jobs=-1),
        x, y, cv=cv_split, scoring="f1",
    )
    print(f"  CV F1 scores : {np.round(rf_cv, 4)}")
    print(f"  CV mean ± std: {rf_cv.mean():.4f} ± {rf_cv.std():.4f}")

    # ── Select winner ────────────────────────────────────────────────────
    if rf_metrics["f1"] >= lr_metrics["f1"]:
        winner_name, winner = "RandomForestClassifier", rf
        importances = _rf_importances(rf, feature_order)
    else:
        winner_name, winner = "LogisticRegression", lr_pipe
        importances = _lr_importances(lr_pipe, feature_order)

    print(f"\n  ✓ Selected model: {winner_name}")
    return winner, winner_name, importances, rf_cv.mean(), rf_cv.std()

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    print(f"\n{'═'*70}")
    print("  PhishGuard v4 — Model Training")
    print(f"{'═'*70}")

    df = pd.read_csv(DATASET_PATH)
    df["claimed_brand"] = df["claimed_brand"].fillna("")
    df["sender_domain"] = df["sender_domain"].fillna("")

    print(f"\n  Dataset : {DATASET_PATH}")
    print(f"  Rows    : {df.shape[0]}")
    print(f"\n  Label distribution:")
    print(df["label"].value_counts().sort_index().rename({0: "Safe (0)", 1: "Phishing (1)"}).to_string(header=False))
    print(f"\n  Content type distribution:")
    print(df["content_type"].value_counts().to_string(header=False))

    y = df["label"].astype(int)

    url_mask  = df["content_type"] == "url"
    text_mask = df["content_type"].isin(["email", "sms"])

    print(f"\n  Building URL feature matrix  ({url_mask.sum()} rows) …")
    t0 = time.perf_counter()
    url_x = build_url_matrix(df[url_mask]).reset_index(drop=True)
    url_y = y[url_mask].reset_index(drop=True)
    print(f"  Done in {time.perf_counter()-t0:.1f}s")

    print(f"  Building TEXT feature matrix ({text_mask.sum()} rows) …")
    t0 = time.perf_counter()
    text_x = build_text_matrix(df[text_mask]).reset_index(drop=True)
    text_y = y[text_mask].reset_index(drop=True)
    print(f"  Done in {time.perf_counter()-t0:.1f}s")

    print(f"\n  sender_domain_mismatch unique values: "
          f"{sorted(text_x['sender_domain_mismatch'].unique())}")

    # ── Train ────────────────────────────────────────────────────────────
    url_model,  url_name,  url_imp,  url_cv_mean,  url_cv_std  = train_one("URL",  url_x,  url_y,  URL_FEATURE_ORDER)
    text_model, text_name, text_imp, text_cv_mean, text_cv_std = train_one("TEXT", text_x, text_y, TEXT_FEATURE_ORDER)

    # ── Persist artifacts ────────────────────────────────────────────────
    joblib.dump(url_model,  MODEL_DIR / "model_url.pkl")
    joblib.dump(text_model, MODEL_DIR / "model_text.pkl")

    (MODEL_DIR / "feature_order_url.json").write_text(
        json.dumps(URL_FEATURE_ORDER, indent=2), encoding="utf-8")
    (MODEL_DIR / "feature_order_text.json").write_text(
        json.dumps(TEXT_FEATURE_ORDER, indent=2), encoding="utf-8")
    (MODEL_DIR / "feature_importances_url.json").write_text(
        json.dumps(url_imp, indent=2), encoding="utf-8")
    (MODEL_DIR / "feature_importances_text.json").write_text(
        json.dumps(text_imp, indent=2), encoding="utf-8")

    # ── Summary ──────────────────────────────────────────────────────────
    sep = "═" * 70
    print(f"\n{sep}")
    print("  TRAINING COMPLETE — SUMMARY")
    print(sep)
    print(f"  URL  model : {url_name:<30s}  CV F1 = {url_cv_mean:.4f} ± {url_cv_std:.4f}")
    print(f"  TEXT model : {text_name:<30s}  CV F1 = {text_cv_mean:.4f} ± {text_cv_std:.4f}")
    print(f"\n  URL  features ({len(URL_FEATURE_ORDER)})  : {', '.join(URL_FEATURE_ORDER)}")
    print(f"  TEXT features ({len(TEXT_FEATURE_ORDER)}) : {', '.join(TEXT_FEATURE_ORDER)}")
    print(f"\n  Artifacts saved to: {MODEL_DIR}")
    print(sep)


if __name__ == "__main__":
    main()
