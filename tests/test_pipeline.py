"""
Unit tests for data preprocessing, pipeline construction, and model inference.
"""

import os
import sys
import joblib
import pandas as pd
import pytest

# Add src to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))

from preprocessing import (
    CONSTANT_FEATURES,
    LABEL_MAP,
    REVERSE_LABEL_MAP,
    build_preprocessor,
    get_feature_lists,
    preprocess_data,
)
from predict import predict_single


def test_preprocessing_feature_lists():
    sample_df = pd.DataFrame(
        {
            "duration": [0, 1],
            "protocol_type": ["tcp", "udp"],
            "service": ["http", "private"],
            "flag": ["SF", "S0"],
            "src_bytes": [100, 200],
            "num_outbound_cmds": [0, 0],
            "is_host_login": [0, 0],
            "class": ["normal", "anomaly"],
        }
    )

    feature_cols, num_cols, cat_cols = get_feature_lists(sample_df)

    assert "class" not in feature_cols
    assert "num_outbound_cmds" not in feature_cols
    assert "is_host_login" not in feature_cols
    assert "protocol_type" in cat_cols
    assert "src_bytes" in num_cols


def test_model_artifact_exists():
    model_path = "models/nids_pipeline.joblib"
    assert os.path.exists(model_path), f"Model pipeline artifact missing at {model_path}"

    pipeline = joblib.load(model_path)
    assert hasattr(pipeline, "predict")
    assert hasattr(pipeline, "predict_proba")


def test_predict_single_normal():
    sample_normal = {
        "duration": 0,
        "protocol_type": "tcp",
        "service": "http",
        "flag": "SF",
        "src_bytes": 215,
        "dst_bytes": 450,
        "count": 10,
        "srv_count": 10,
        "same_srv_rate": 1.0,
        "diff_srv_rate": 0.0,
        "dst_host_count": 255,
        "dst_host_srv_count": 255,
    }
    res = predict_single(sample_normal)
    assert "prediction" in res
    assert "probability" in res
    assert "status" in res
    assert res["prediction"] in ["normal", "anomaly"]
    assert res["status"] in ["NORMAL", "ALERT"]


def test_predict_single_anomaly():
    sample_anomaly = {
        "duration": 0,
        "protocol_type": "tcp",
        "service": "private",
        "flag": "S0",
        "src_bytes": 0,
        "dst_bytes": 0,
        "count": 123,
        "srv_count": 6,
        "serror_rate": 1.0,
        "rerror_rate": 0.0,
        "same_srv_rate": 0.05,
        "diff_srv_rate": 0.07,
        "dst_host_count": 255,
        "dst_host_srv_count": 6,
        "dst_host_same_srv_rate": 0.02,
        "dst_host_diff_srv_rate": 0.07,
    }
    res = predict_single(sample_anomaly)
    assert res["prediction"] == "anomaly"
    assert res["status"] == "ALERT"
    assert res["probability"] > 0.5
