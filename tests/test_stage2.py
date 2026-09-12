"""
Unit tests for Stage 2 Multi-Class Machine Learning Pipeline and Runtime Integration.
"""

import os
import joblib
import pytest
from src.predict import predict_single, load_stage2_model


def test_stage2_model_artifact_exists():
    model_path = os.path.abspath("models/stage2_pipeline.joblib")
    assert os.path.exists(model_path), "models/stage2_pipeline.joblib does not exist."


def test_stage2_model_loading_and_classes():
    stage2_model = load_stage2_model()
    assert stage2_model is not None, "Stage 2 model failed to load."
    classes = list(stage2_model.classes_)
    expected_classes = ["DoS", "Probe", "R2L", "U2R"]
    for c in expected_classes:
        assert c in classes, f"Expected class {c} missing from Stage 2 model classes: {classes}"


def test_stage2_inference_and_probabilities():
    stage2_model = load_stage2_model()
    sample_anomaly = {
        "duration": 0,
        "protocol_type": "tcp",
        "service": "private",
        "flag": "S0",
        "src_bytes": 0,
        "dst_bytes": 0,
        "count": 250,
        "srv_count": 250,
        "serror_rate": 1.0,
        "srv_serror_rate": 1.0,
        "same_srv_rate": 1.0,
        "diff_srv_rate": 0.0,
        "dst_host_count": 255,
        "dst_host_srv_count": 255,
        "dst_host_same_srv_rate": 1.0,
        "dst_host_diff_srv_rate": 0.0,
        "dst_host_serror_rate": 1.0,
        "dst_host_srv_serror_rate": 1.0,
    }

    import pandas as pd
    df = pd.DataFrame([sample_anomaly])
    from src.predict import _ensure_all_columns
    df_clean = _ensure_all_columns(df)

    pred = stage2_model.predict(df_clean)[0]
    probs = stage2_model.predict_proba(df_clean)[0]

    assert pred in ["DoS", "Probe", "R2L", "U2R"]
    assert len(probs) == 4
    assert abs(sum(probs) - 1.0) < 1e-3


def test_predict_single_anomaly_invokes_stage2():
    sample_anomaly = {
        "duration": 0,
        "protocol_type": "tcp",
        "service": "private",
        "flag": "S0",
        "src_bytes": 0,
        "dst_bytes": 0,
        "count": 250,
        "srv_count": 250,
        "serror_rate": 1.0,
        "srv_serror_rate": 1.0,
        "same_srv_rate": 1.0,
        "diff_srv_rate": 0.0,
        "dst_host_count": 255,
        "dst_host_srv_count": 255,
        "dst_host_same_srv_rate": 1.0,
        "dst_host_diff_srv_rate": 0.0,
        "dst_host_serror_rate": 1.0,
        "dst_host_srv_serror_rate": 1.0,
    }

    result = predict_single(sample_anomaly)
    assert result["prediction"] == "anomaly"
    assert result["attack_family"] in ["DoS", "Probe", "R2L", "U2R"]
    assert result["classifier_type"] == "stage2_ml"
    assert isinstance(result["stage2_confidence"], float)
    assert result["stage2_confidence"] > 0.0
    assert isinstance(result["stage2_probabilities"], dict)


def test_predict_single_normal_does_not_invoke_stage2():
    sample_normal = {
        "duration": 0,
        "protocol_type": "tcp",
        "service": "http",
        "flag": "SF",
        "src_bytes": 215,
        "dst_bytes": 450,
        "count": 1,
        "srv_count": 1,
        "serror_rate": 0.0,
        "same_srv_rate": 1.0,
        "diff_srv_rate": 0.0,
        "dst_host_count": 1,
        "dst_host_srv_count": 1,
        "dst_host_same_srv_rate": 1.0,
        "dst_host_diff_srv_rate": 0.0,
    }

    result = predict_single(sample_normal)
    assert result["prediction"] == "normal"
    assert result["attack_family"] is None
    assert result["classifier_type"] is None
    assert result["stage2_probabilities"] is None
