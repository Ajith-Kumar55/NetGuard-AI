"""
Inference module for Network Intrusion Detection System (NIDS).
Loads pre-trained Stage 1 binary classifier and Stage 2 attack family classifier.
Computes 2-stage predictions, risk scores, SHAP explanations, and defensive mitigation.
"""

from datetime import datetime
import json
import logging
import os
import sys
import time
import joblib
import pandas as pd

# Ensure parent and src directory are on sys.path
sys.path.append(os.path.dirname(__file__))
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

try:
    from preprocessing import CONSTANT_FEATURES, REVERSE_LABEL_MAP
    from attack_mapping import heuristic_attack_family
except ImportError:
    from src.preprocessing import CONSTANT_FEATURES, REVERSE_LABEL_MAP
    from src.attack_mapping import heuristic_attack_family

from backend.services.xai_service import compute_shap_explanations
from backend.services.mitigation_service import get_mitigation_recommendations

logger = logging.getLogger("nids_backend")

MODEL_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "models", "nids_pipeline.joblib"))
STAGE2_MODEL_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "models", "stage2_pipeline.joblib"))
METRICS_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "models", "metrics.json"))

_PIPELINE = None
_STAGE2_PIPELINE = None
_METRICS = None


def load_model_and_metadata():
    global _PIPELINE, _METRICS
    if _PIPELINE is None:
        if not os.path.exists(MODEL_PATH):
            raise FileNotFoundError(f"Model file not found at {MODEL_PATH}")
        _PIPELINE = joblib.load(MODEL_PATH)
    if _METRICS is None:
        try:
            with open(METRICS_PATH, "r", encoding="utf-8") as f:
                _METRICS = json.load(f)
        except Exception:
            _METRICS = {}
    return _PIPELINE, _METRICS


def load_stage2_model():
    global _STAGE2_PIPELINE
    if _STAGE2_PIPELINE is None:
        if os.path.exists(STAGE2_MODEL_PATH):
            try:
                _STAGE2_PIPELINE = joblib.load(STAGE2_MODEL_PATH)
            except Exception as e:
                logger.warning(f"Failed to load Stage 2 ML model: {str(e)}")
                _STAGE2_PIPELINE = None
    return _STAGE2_PIPELINE


def _ensure_all_columns(df: pd.DataFrame) -> pd.DataFrame:
    """
    Ensures dataframe contains all 41 feature columns with sensible default values.
    """
    _, metrics = load_model_and_metadata()
    feature_cols = metrics.get("feature_columns", [])
    cat_cols = metrics.get("categorical_columns", ["protocol_type", "service", "flag"])

    defaults = {
        "protocol_type": "tcp",
        "service": "http",
        "flag": "SF",
    }

    df_out = df.copy()

    for col in feature_cols:
        if col not in df_out.columns:
            if col in cat_cols or col in defaults:
                df_out[col] = defaults.get(col, "other")
            else:
                df_out[col] = 0

    for c in CONSTANT_FEATURES:
        if c not in df_out.columns:
            df_out[c] = 0

    return df_out


def _sanitize_native_types(data_dict: dict) -> dict:
    """Converts numpy data types to native Python types for JSON compatibility."""
    clean = {}
    for k, v in data_dict.items():
        if hasattr(v, "item"):
            clean[k] = v.item()
        elif isinstance(v, float) and (v != v):  # NaN check
            clean[k] = 0.0
        else:
            clean[k] = v
    return clean


def predict_single(data_dict: dict) -> dict:
    """
    Executes hierarchical 2-stage detection for a single 41-feature payload.
    Returns comprehensive AnalysisResult dictionary with high-resolution latency metrics.
    """
    t_start = time.perf_counter()
    pipeline, _ = load_model_and_metadata()

    # Sanitize input dictionary
    sanitized_input = _sanitize_native_types(data_dict)

    source_ip = str(sanitized_input.get("_source_ip", sanitized_input.get("source_ip", "127.0.0.1")))
    destination_ip = str(sanitized_input.get("_destination_ip", sanitized_input.get("destination_ip", "127.0.0.1")))
    protocol = str(sanitized_input.get("protocol_type", "tcp")).upper()

    df = pd.DataFrame([sanitized_input])
    df_clean = _ensure_all_columns(df)
    t_parse = time.perf_counter()

    # Stage 1: Binary classification
    pred_idx = pipeline.predict(df_clean)[0]
    prob = float(pipeline.predict_proba(df_clean)[0][1]) if hasattr(pipeline, "predict_proba") else 0.0

    prediction_label = REVERSE_LABEL_MAP.get(int(pred_idx), "unknown")
    status = "ALERT" if prediction_label == "anomaly" else "NORMAL"

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Base Risk Score calculation (0 to 100)
    risk_score = round(prob * 100.0, 2)

    attack_family = None
    stage2_conf = None
    classifier_type = None
    stage2_probabilities = None
    top_features = None
    mitigation = None

    if prediction_label == "anomaly":
        # Stage 2: Attack family categorization via genuine ML classifier
        stage2_model = load_stage2_model()
        if stage2_model is not None:
            try:
                s2_pred = stage2_model.predict(df_clean)[0]
                s2_probs = stage2_model.predict_proba(df_clean)[0]
                classes = list(stage2_model.classes_)

                prob_dict = {str(cls): float(round(p, 4)) for cls, p in zip(classes, s2_probs)}
                max_prob = float(round(max(s2_probs), 4))

                attack_family = str(s2_pred)
                stage2_conf = max_prob
                stage2_probabilities = prob_dict
                classifier_type = "stage2_ml"
            except Exception as e:
                logger.warning(f"Stage 2 ML inference error, using fallback: {str(e)}")
                attack_family, stage2_conf = heuristic_attack_family(sanitized_input)
                classifier_type = "heuristic_fallback"
        else:
            attack_family, stage2_conf = heuristic_attack_family(sanitized_input)
            classifier_type = "heuristic_fallback"

        # Risk score policy adjustments for critical attack families
        if attack_family in ["U2R", "R2L"]:
            risk_score = max(risk_score, 88.0)
        elif attack_family == "DoS":
            risk_score = max(risk_score, 75.0)

        # Compute SHAP feature attributions for Stage 1 model
        raw_top = compute_shap_explanations(pipeline, df_clean, top_k=5)
        top_features = []
        for tf in raw_top:
            val = tf.get("value")
            top_features.append({
                "feature": str(tf.get("feature")),
                "value": val.item() if hasattr(val, "item") else val,
                "impact": float(tf.get("impact", 0.0)),
                "direction": str(tf.get("direction")),
            })

        # Retrieve defensive mitigation rules
        mitigation = get_mitigation_recommendations(attack_family)

    # Determine risk level
    if risk_score >= 90.0:
        risk_level = "Critical"
    elif risk_score >= 75.0:
        risk_level = "High"
    elif risk_score >= 60.0:
        risk_level = "Medium"
    elif risk_score >= 40.0:
        risk_level = "Low"
    else:
        risk_level = "Normal"

    t_end = time.perf_counter()
    parsing_latency_ms = round((t_parse - t_start) * 1000.0, 3)
    inference_latency_ms = round((t_end - t_parse) * 1000.0, 3)
    total_processing_time_ms = round((t_end - t_start) * 1000.0, 3)

    return {
        "prediction": prediction_label,
        "status": status,
        "probability": round(prob, 4),
        "risk_score": risk_score,
        "risk_level": risk_level,
        "attack_family": attack_family,
        "stage2_confidence": stage2_conf,
        "classifier_type": classifier_type,
        "stage2_probabilities": stage2_probabilities,
        "top_features": top_features,
        "mitigation": mitigation,
        "timestamp": timestamp,
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "protocol": protocol,
        "parsing_latency_ms": parsing_latency_ms,
        "inference_latency_ms": inference_latency_ms,
        "total_processing_time_ms": total_processing_time_ms,
    }
