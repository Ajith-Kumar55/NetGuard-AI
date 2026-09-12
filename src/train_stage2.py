"""
Stage 2 Machine Learning Training & Evaluation Pipeline for NetGuard AI.
Trains a supervised multi-class RandomForestClassifier to classify anomalous network
connections into 4 attack families: DoS, Probe, R2L, and U2R.
"""

import json
import os
import joblib
import numpy as np
import pandas as pd
import sklearn
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder, StandardScaler

ATTACK_FAMILY_MAP = {
    "normal": "normal",
    # DoS
    "neptune": "DoS",
    "smurf": "DoS",
    "pod": "DoS",
    "teardrop": "DoS",
    "land": "DoS",
    "back": "DoS",
    # Probe
    "satan": "Probe",
    "ipsweep": "Probe",
    "nmap": "Probe",
    "portsweep": "Probe",
    # R2L
    "guess_passwd": "R2L",
    "ftp_write": "R2L",
    "imap": "R2L",
    "phf": "R2L",
    "warezclient": "R2L",
    "warezmaster": "R2L",
    "spy": "R2L",
    "multihop": "R2L",
    # U2R
    "buffer_overflow": "U2R",
    "rootkit": "U2R",
    "loadmodule": "U2R",
}

CONSTANT_FEATURES = ["num_outbound_cmds", "is_host_login"]
CATEGORICAL_FEATURES = ["protocol_type", "service", "flag"]


def prepare_granular_dataset(
    train_data_path: str = "data/Train_data.csv",
    kdd_data_path: str = "data/KDDTrain+_20Percent.txt",
    granular_save_path: str = "data/Train_data_granular.csv",
    report_save_path: str = "reports/stage2_dataset_report.json",
):
    print(f"[*] Loading datasets for verification...")
    df_train = pd.read_csv(train_data_path)
    df_kdd = pd.read_csv(kdd_data_path, header=None)

    assert len(df_train) == len(df_kdd), "Row count mismatch between Train_data.csv and KDDTrain+_20Percent.txt"

    attack_labels = df_kdd.iloc[:, 41].str.strip()
    unrecognized = set(attack_labels.unique()) - set(ATTACK_FAMILY_MAP.keys())
    if unrecognized:
        raise ValueError(f"Unrecognized attack labels found in KDDTrain+: {unrecognized}")

    df_train["attack_label"] = attack_labels
    df_train["attack_family"] = df_train["attack_label"].map(ATTACK_FAMILY_MAP)

    df_train.to_csv(granular_save_path, index=False)
    print(f"[+] Saved granular dataset to {granular_save_path}")

    family_counts = df_train["attack_family"].value_counts().to_dict()
    attack_counts = df_train["attack_label"].value_counts().to_dict()
    total_rows = len(df_train)

    report_data = {
        "total_rows": total_rows,
        "normal_count": family_counts.get("normal", 0),
        "DoS_count": family_counts.get("DoS", 0),
        "Probe_count": family_counts.get("Probe", 0),
        "R2L_count": family_counts.get("R2L", 0),
        "U2R_count": family_counts.get("U2R", 0),
        "family_distribution": family_counts,
        "family_percentages": {k: round((v / total_rows) * 100, 2) for k, v in family_counts.items()},
        "original_attack_counts": attack_counts,
        "missing_values": int(df_train.isnull().sum().sum()),
        "duplicate_rows": int(df_train.duplicated().sum()),
    }

    os.makedirs(os.path.dirname(report_save_path), exist_ok=True)
    with open(report_save_path, "w", encoding="utf-8") as f:
        json.dump(report_data, f, indent=2)

    return df_train, report_data


def train_stage2_model(
    granular_path: str = "data/Train_data_granular.csv",
    model_save_path: str = "models/stage2_pipeline.joblib",
    metadata_save_path: str = "models/stage2_metadata.json",
    metrics_save_path: str = "reports/stage2_metrics.json",
    confusion_save_path: str = "reports/stage2_confusion_matrix.json",
):
    if not os.path.exists(granular_path):
        df_granular, _ = prepare_granular_dataset()
    else:
        df_granular = pd.read_csv(granular_path)

    # Stage 2 operates on anomalous traffic flows
    df_anom = df_granular[df_granular["class"] == "anomaly"].copy()

    target_col = "attack_family"
    feature_cols = [
        c
        for c in df_anom.columns
        if c not in ["class", "attack_label", "attack_family"] and c not in CONSTANT_FEATURES
    ]

    cat_cols = [c for c in feature_cols if c in CATEGORICAL_FEATURES]
    num_cols = [c for c in feature_cols if c not in cat_cols]

    X = df_anom[feature_cols]
    y = df_anom[target_col]

    # Stratified Train/Validation Split (80/20)
    X_train, X_val, y_train, y_val = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )

    preprocessor = ColumnTransformer(
        transformers=[
            ("num", StandardScaler(), num_cols),
            ("cat", OneHotEncoder(handle_unknown="ignore", sparse_output=False), cat_cols),
        ]
    )

    classifier = RandomForestClassifier(n_estimators=100, max_depth=15, random_state=42, n_jobs=-1)

    stage2_pipeline = Pipeline(
        steps=[
            ("preprocessor", preprocessor),
            ("classifier", classifier),
        ]
    )

    print(f"[*] Training Stage 2 RandomForestClassifier on {X_train.shape[0]} anomalous training samples...")
    stage2_pipeline.fit(X_train, y_train)

    # Evaluate on validation set
    y_pred = stage2_pipeline.predict(X_val)
    classes = sorted(y.unique().tolist())

    acc = float(accuracy_score(y_val, y_pred))
    macro_prec = float(precision_score(y_val, y_pred, average="macro"))
    macro_rec = float(recall_score(y_val, y_pred, average="macro"))
    macro_f1 = float(f1_score(y_val, y_pred, average="macro"))

    w_prec = float(precision_score(y_val, y_pred, average="weighted"))
    w_rec = float(recall_score(y_val, y_pred, average="weighted"))
    w_f1 = float(f1_score(y_val, y_pred, average="weighted"))

    cm = confusion_matrix(y_val, y_pred, labels=classes).tolist()
    cls_report = classification_report(y_val, y_pred, labels=classes, output_dict=True)

    print("\n" + "=" * 60)
    print(" STAGE 2 MULTI-CLASS ML EVALUATION METRICS ")
    print("=" * 60)
    print(f"[*] Validation Accuracy:  {acc:.4f}")
    print(f"[*] Macro F1-Score:       {macro_f1:.4f}")
    print(f"[*] Weighted F1-Score:    {w_f1:.4f}")

    # Retrain pipeline on complete anomalous dataset for max robustness
    stage2_pipeline.fit(X, y)

    os.makedirs(os.path.dirname(model_save_path), exist_ok=True)
    os.makedirs(os.path.dirname(metrics_save_path), exist_ok=True)

    joblib.dump(stage2_pipeline, model_save_path)

    metrics_data = {
        "model_name": "RandomForestClassifier",
        "target_classes": classes,
        "train_samples": int(X_train.shape[0]),
        "val_samples": int(X_val.shape[0]),
        "total_anomaly_samples": int(X.shape[0]),
        "accuracy": round(acc, 4),
        "macro_precision": round(macro_prec, 4),
        "macro_recall": round(macro_rec, 4),
        "macro_f1": round(macro_f1, 4),
        "weighted_precision": round(w_prec, 4),
        "weighted_recall": round(w_rec, 4),
        "weighted_f1": round(w_f1, 4),
        "classification_report": cls_report,
        "confusion_matrix": cm,
        "labels": classes,
    }

    metadata = {
        "model_type": "RandomForestClassifier",
        "sklearn_version": sklearn.__version__,
        "training_dataset": granular_path,
        "feature_list": feature_cols,
        "numerical_columns": num_cols,
        "categorical_columns": cat_cols,
        "target_classes": classes,
        "training_row_count": int(X_train.shape[0]),
        "validation_row_count": int(X_val.shape[0]),
        "random_state": 42,
        "metrics": {
            "accuracy": round(acc, 4),
            "macro_f1": round(macro_f1, 4),
            "weighted_f1": round(w_f1, 4),
        },
    }

    with open(metrics_save_path, "w", encoding="utf-8") as f:
        json.dump(metrics_data, f, indent=2)

    with open(confusion_save_path, "w", encoding="utf-8") as f:
        json.dump({"classes": classes, "matrix": cm}, f, indent=2)

    with open(metadata_save_path, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)

    print(f"[+] Saved Stage 2 model pipeline to {model_save_path}")
    print(f"[+] Saved Stage 2 metadata to {metadata_save_path}")


if __name__ == "__main__":
    train_stage2_model()
