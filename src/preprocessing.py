"""
Preprocessing pipeline for Network Intrusion Detection System (NIDS).
Handles numerical scaling, categorical encoding, constant feature removal,
data leakage prevention, and input payload formatting for real-time inference.
"""

import numpy as np
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder, StandardScaler

# Target mapping
TARGET_COL = "class"
LABEL_MAP = {"normal": 0, "anomaly": 1}
REVERSE_LABEL_MAP = {0: "normal", 1: "anomaly"}

# Constant features identified during EDA that carry zero variance
CONSTANT_FEATURES = ["num_outbound_cmds", "is_host_login"]

CATEGORICAL_FEATURES = ["protocol_type", "service", "flag"]


def get_feature_lists(df: pd.DataFrame):
    """
    Identifies numerical and categorical features from dataframe, excluding target
    and constant features.
    """
    feature_cols = [col for col in df.columns if col != TARGET_COL and col not in CONSTANT_FEATURES]
    cat_cols = [col for col in feature_cols if col in CATEGORICAL_FEATURES or df[col].dtype == "object"]
    num_cols = [col for col in feature_cols if col not in cat_cols]
    return feature_cols, num_cols, cat_cols


def build_preprocessor(num_cols: list, cat_cols: list) -> ColumnTransformer:
    """
    Creates a Scikit-Learn ColumnTransformer for numeric scaling and one-hot encoding.
    """
    numeric_transformer = Pipeline(
        steps=[
            ("scaler", StandardScaler())
        ]
    )

    categorical_transformer = Pipeline(
        steps=[
            ("onehot", OneHotEncoder(handle_unknown="ignore", sparse_output=False))
        ]
    )

    preprocessor = ColumnTransformer(
        transformers=[
            ("num", numeric_transformer, num_cols),
            ("cat", categorical_transformer, cat_cols),
        ]
    )

    return preprocessor


def create_full_pipeline(classifier, num_cols: list, cat_cols: list) -> Pipeline:
    """
    Constructs an end-to-end Scikit-Learn Pipeline incorporating preprocessing and classification.
    """
    preprocessor = build_preprocessor(num_cols, cat_cols)
    full_pipeline = Pipeline(
        steps=[
            ("preprocessor", preprocessor),
            ("classifier", classifier)
        ]
    )
    return full_pipeline


def preprocess_data(train_df: pd.DataFrame):
    """
    Extracts features X and target y from the training dataset.
    Converts string target labels to binary integers (normal=0, anomaly=1).
    """
    feature_cols, num_cols, cat_cols = get_feature_lists(train_df)
    X = train_df[feature_cols].copy()

    if TARGET_COL in train_df.columns:
        y = train_df[TARGET_COL].map(LABEL_MAP).values
    else:
        y = None

    return X, y, feature_cols, num_cols, cat_cols
