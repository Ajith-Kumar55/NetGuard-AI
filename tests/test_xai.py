"""
Unit tests for Explainable AI (SHAP) feature attributions and defensive mitigation lookup.
"""

import pandas as pd
import pytest
from backend.services.mitigation_service import get_mitigation_recommendations
from backend.services.xai_service import _heuristic_fallback_explanations


def test_mitigation_rules_lookup():
    dos_mitigation = get_mitigation_recommendations("DoS")
    assert isinstance(dos_mitigation, list)
    assert len(dos_mitigation) > 0
    assert any("SYN" in rule or "flood" in rule or "rate limiting" in rule for rule in dos_mitigation)

    u2r_mitigation = get_mitigation_recommendations("U2R")
    assert any("privilege escalation" in rule or "isolate" in rule for rule in u2r_mitigation)

    unknown_mitigation = get_mitigation_recommendations("UnknownFamily")
    assert isinstance(unknown_mitigation, list)
    assert len(unknown_mitigation) > 0


def test_heuristic_fallback_explanations():
    df = pd.DataFrame([{
        "duration": 0,
        "protocol_type": "tcp",
        "service": "private",
        "flag": "S0",
        "serror_rate": 1.0,
        "count": 150,
        "diff_srv_rate": 0.05
    }])
    explanations = _heuristic_fallback_explanations(df, top_k=5)
    assert isinstance(explanations, list)
    assert len(explanations) > 0
    assert "feature" in explanations[0]
    assert "impact" in explanations[0]
    assert "direction" in explanations[0]


def test_compute_shap_explanations_with_anomaly_row():
    import joblib
    from backend.services.xai_service import compute_shap_explanations
    from src.preprocessing import CONSTANT_FEATURES

    p1 = joblib.load("models/nids_pipeline.joblib")
    df = pd.read_csv("data/Test_data.csv").head(1)
    for c in CONSTANT_FEATURES:
        if c not in df.columns:
            df[c] = 0

    explanations = compute_shap_explanations(p1, df, top_k=5)
    assert isinstance(explanations, list)
    assert len(explanations) == 5
    for item in explanations:
        assert "feature" in item
        assert "value" in item
        assert "impact" in item
        assert "direction" in item
        assert item["value"] != "N/A"
        assert item["impact"] >= 0.0
