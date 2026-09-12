"""
Model Training and Selection Pipeline for Network Intrusion Detection System (NIDS).
Trains and compares Logistic Regression, Random Forest, and Gradient Boosting Classifiers
using stratified validation. Exports the best pipeline and metrics via joblib.
"""

import json
import os
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import GradientBoostingClassifier, RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.model_selection import train_test_split

from preprocessing import (
    CONSTANT_FEATURES,
    LABEL_MAP,
    REVERSE_LABEL_MAP,
    TARGET_COL,
    create_full_pipeline,
    preprocess_data,
)


def train_and_evaluate(
    data_path: str = "data/Train_data.csv",
    model_save_path: str = "models/nids_pipeline.joblib",
    metrics_save_path: str = "models/metrics.json",
):
    print(f"[*] Loading training data from {data_path}...")
    df = pd.read_csv(data_path)

    X, y, feature_cols, num_cols, cat_cols = preprocess_data(df)
    print(f"[*] Total features used: {len(feature_cols)} (Numerical: {len(num_cols)}, Categorical: {len(cat_cols)})")
    print(f"[*] Removed constant features: {CONSTANT_FEATURES}")

    # Stratified Train-Validation Split (80-20)
    X_train, X_val, y_train, y_val = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )
    print(f"[*] Train set size: {X_train.shape[0]}, Validation set size: {X_val.shape[0]}")

    # Candidates for comparison
    candidate_models = {
        "Logistic Regression": LogisticRegression(max_iter=1000, random_state=42),
        "Random Forest": RandomForestClassifier(n_estimators=100, max_depth=15, random_state=42, n_jobs=-1),
        "Gradient Boosting": GradientBoostingClassifier(n_estimators=100, max_depth=5, random_state=42),
    }

    results = {}
    best_model_name = None
    best_f1 = -1.0
    best_pipeline = None

    print("\n" + "=" * 60)
    print(" MODEL TRAINING AND COMPARISON METRICS ")
    print("=" * 60)

    for name, clf in candidate_models.items():
        print(f"\n[+] Training {name}...")
        pipeline = create_full_pipeline(clf, num_cols, cat_cols)
        pipeline.fit(X_train, y_train)

        # Predictions on validation set
        y_pred = pipeline.predict(X_val)
        y_prob = pipeline.predict_proba(X_val)[:, 1] if hasattr(pipeline, "predict_proba") else None

        acc = float(accuracy_score(y_val, y_pred))
        prec = float(precision_score(y_val, y_pred))
        rec = float(recall_score(y_val, y_pred))
        f1 = float(f1_score(y_val, y_pred))
        cm = confusion_matrix(y_val, y_pred).tolist()

        results[name] = {
            "accuracy": round(acc, 4),
            "precision": round(prec, 4),
            "recall": round(rec, 4),
            "f1_score": round(f1, 4),
            "confusion_matrix": cm,
        }

        print(f"    - Accuracy:  {acc:.4f}")
        print(f"    - Precision: {prec:.4f}")
        print(f"    - Recall:    {rec:.4f}")
        print(f"    - F1-Score:  {f1:.4f}")
        print(f"    - Confusion Matrix (TN, FP, FN, TP):\n      {cm}")

        if f1 > best_f1:
            best_f1 = f1
            best_model_name = name
            best_pipeline = pipeline

    print("\n" + "=" * 60)
    print(f"[*] BEST MODEL SELECTED: {best_model_name} (F1-Score: {best_f1:.4f})")
    print("=" * 60)

    # Retrain best pipeline on full training dataset for maximum robustness
    print(f"\n[*] Retraining {best_model_name} on complete training dataset ({X.shape[0]} samples)...")
    best_pipeline.fit(X, y)

    # Ensure output directory exists
    os.makedirs(os.path.dirname(model_save_path), exist_ok=True)

    # Save pipeline object via joblib
    joblib.dump(best_pipeline, model_save_path)
    print(f"[+] Best pipeline saved successfully to {model_save_path}")

    # Prepare sample records for API testing / UI pre-fill
    normal_sample = df[df[TARGET_COL] == "normal"].drop(columns=[TARGET_COL]).iloc[0].to_dict()
    anomaly_sample = df[df[TARGET_COL] == "anomaly"].drop(columns=[TARGET_COL]).iloc[0].to_dict()

    # Save metrics metadata
    metrics_data = {
        "best_model": best_model_name,
        "best_f1_score": round(best_f1, 4),
        "comparison": results,
        "feature_columns": feature_cols,
        "numerical_columns": num_cols,
        "categorical_columns": cat_cols,
        "constant_features": CONSTANT_FEATURES,
        "categorical_options": {
            "protocol_type": sorted(df["protocol_type"].unique().tolist()),
            "service": sorted(df["service"].unique().tolist()),
            "flag": sorted(df["flag"].unique().tolist()),
        },
        "sample_records": {
            "normal": normal_sample,
            "anomaly": anomaly_sample,
        },
    }

    with open(metrics_save_path, "w", encoding="utf-8") as f:
        json.dump(metrics_data, f, indent=2)

    print(f"[+] Model evaluation metrics saved to {metrics_save_path}")
    return metrics_data


if __name__ == "__main__":
    train_and_evaluate()
