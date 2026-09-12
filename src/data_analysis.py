"""
Data Analysis & Exploratory Data Analysis (EDA) module for NIDS.
Inspects the training and testing network traffic dataset programmatically
and generates an analytical summary saved to reports/eda_summary.json.
"""

import json
import os
import pandas as pd


def analyze_dataset(train_path: str = "data/Train_data.csv", test_path: str = "data/Test_data.csv", output_report: str = "reports/eda_summary.json"):
    print(f"[*] Loading training data from {train_path}...")
    train_df = pd.read_csv(train_path)

    print(f"[*] Loading testing data from {test_path}...")
    test_df = pd.read_csv(test_path)

    # Basic shape and columns
    train_shape = list(train_df.shape)
    test_shape = list(test_df.shape)

    target_col = "class"
    if target_col in train_df.columns:
        target_counts = train_df[target_col].value_counts().to_dict()
        target_distribution = train_df[target_col].value_counts(normalize=True).to_dict()
    else:
        target_counts = {}
        target_distribution = {}

    categorical_cols = list(train_df.select_dtypes(include=["object", "string"]).columns)
    if target_col in categorical_cols:
        categorical_cols.remove(target_col)

    numerical_cols = list(train_df.select_dtypes(include=["int64", "float64"]).columns)

    # Check for missing values
    missing_train = int(train_df.isnull().sum().sum())
    missing_test = int(test_df.isnull().sum().sum())

    # Check constant features (nunique == 1)
    constant_features = [col for col in train_df.columns if train_df[col].nunique() <= 1]

    # Summarize categorical unique values
    cat_summary = {}
    for col in categorical_cols:
        cat_summary[col] = {
            "train_unique_count": int(train_df[col].nunique()),
            "test_unique_count": int(test_df[col].nunique()) if col in test_df.columns else 0,
            "train_categories": [str(c) for c in train_df[col].unique()[:10]]  # first 10
        }

    summary = {
        "train_shape": train_shape,
        "test_shape": test_shape,
        "target_col": target_col,
        "target_counts": target_counts,
        "target_distribution": target_distribution,
        "total_features": train_shape[1] - 1,
        "numerical_feature_count": len(numerical_cols),
        "categorical_feature_count": len(categorical_cols),
        "categorical_features": categorical_cols,
        "constant_features": constant_features,
        "missing_values_train": missing_train,
        "missing_values_test": missing_test,
        "categorical_summary": cat_summary
    }

    os.makedirs(os.path.dirname(output_report), exist_ok=True)
    with open(output_report, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)

    print(f"[+] EDA analysis completed successfully. Report saved to {output_report}")
    print(f"    Train shape: {train_shape}, Test shape: {test_shape}")
    print(f"    Target counts: {target_counts}")
    print(f"    Constant features to drop: {constant_features}")
    return summary


if __name__ == "__main__":
    analyze_dataset()
