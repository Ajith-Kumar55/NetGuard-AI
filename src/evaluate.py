"""
Evaluation module for Network Intrusion Detection System (NIDS).
Generates detailed classification reports, confusion matrix figures,
and evaluation metrics saved under reports/.
"""

import json
import os
import joblib
import pandas as pd
from sklearn.metrics import classification_report, confusion_matrix

from preprocessing import LABEL_MAP, REVERSE_LABEL_MAP, TARGET_COL, preprocess_data


def run_evaluation(
    data_path: str = "data/Train_data.csv",
    model_path: str = "models/nids_pipeline.joblib",
    report_output: str = "reports/evaluation_report.json",
):
    print(f"[*] Loading evaluation dataset from {data_path}...")
    df = pd.read_csv(data_path)

    X, y, feature_cols, num_cols, cat_cols = preprocess_data(df)

    print(f"[*] Loading saved NIDS model pipeline from {model_path}...")
    pipeline = joblib.load(model_path)

    y_pred = pipeline.predict(X)
    y_prob = pipeline.predict_proba(X)[:, 1] if hasattr(pipeline, "predict_proba") else None

    # Classification report as dict
    report_dict = classification_report(
        y, y_pred, target_names=["normal", "anomaly"], output_dict=True
    )

    cm = confusion_matrix(y, y_pred).tolist()

    summary = {
        "note": "Full dataset evaluation. Official model selection metric is 99.68% Stratified Validation Accuracy (20% split) stored in models/metrics.json.",
        "dataset": data_path,
        "total_samples": len(df),
        "confusion_matrix": cm,
        "confusion_matrix_legend": {
            "TN": cm[0][0],
            "FP": cm[0][1],
            "FN": cm[1][0],
            "TP": cm[1][1],
        },
        "classification_report": report_dict,
    }

    os.makedirs(os.path.dirname(report_output), exist_ok=True)
    with open(report_output, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)

    print(f"[+] Evaluation completed. Detailed report saved to {report_output}")
    print("\nConfusion Matrix:")
    print(f"  TN (Normal correctly predicted):   {cm[0][0]}")
    print(f"  FP (Normal predicted as Anomaly): {cm[0][1]}")
    print(f"  FN (Anomaly predicted as Normal): {cm[1][0]}")
    print(f"  TP (Anomaly correctly predicted):  {cm[1][1]}")
    return summary


if __name__ == "__main__":
    run_evaluation()
