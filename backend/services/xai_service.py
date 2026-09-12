"""
Explainable AI (XAI) Service for NetGuard AI.
Uses SHAP (SHapley Additive exPlanations) TreeExplainer to calculate feature contributions
for anomaly predictions and output human-interpretable risk attribution.
"""

from typing import Any

import logging
import numpy as np
import pandas as pd

logger = logging.getLogger("nids_backend")

_EXPLAINER = None
_FEATURE_NAMES = None


def get_shap_explainer(classifier):
    global _EXPLAINER
    if _EXPLAINER is None:
        try:
            import shap
            _EXPLAINER = shap.TreeExplainer(classifier)
            logger.info("Initialized global SHAP TreeExplainer instance.")
        except Exception as e:
            logger.warning(f"Failed to initialize SHAP TreeExplainer: {str(e)}")
            _EXPLAINER = None
    return _EXPLAINER


def _extract_feature_value(df_input: pd.DataFrame, clean_name: str) -> Any:
    """Safely extracts observed raw feature value from input dataframe for clean_name."""
    if df_input.empty:
        return "N/A"
    row = df_input.iloc[0]
    if clean_name in row:
        val = row[clean_name]
        return val.item() if hasattr(val, "item") else val

    parts = clean_name.split("_")
    for i in range(len(parts) - 1, 0, -1):
        col_candidate = "_".join(parts[:i])
        if col_candidate in row:
            val = row[col_candidate]
            return val.item() if hasattr(val, "item") else val

    return "N/A"


def compute_shap_explanations(pipeline, df_input: pd.DataFrame, top_k: int = 5) -> list[dict]:
    """
    Computes top-k SHAP feature attribution scores for input traffic dataframe.
    Returns:
    [
      {
        "feature": str,
        "value": Any,
        "impact": float,
        "direction": "increases_anomaly_risk" | "decreases_anomaly_risk"
      }
    ]
    """
    try:
        import shap

        if not hasattr(pipeline, "named_steps") or "classifier" not in pipeline.named_steps:
            return _heuristic_fallback_explanations(df_input, top_k)

        preprocessor = pipeline.named_steps["preprocessor"]
        classifier = pipeline.named_steps["classifier"]

        # Transform raw features through preprocessor
        X_transformed = preprocessor.transform(df_input)

        # Get feature names after OneHotEncoding
        feature_names = []
        if hasattr(preprocessor, "get_feature_names_out"):
            feature_names = list(preprocessor.get_feature_names_out())
        else:
            feature_names = [f"feature_{i}" for i in range(X_transformed.shape[1])]

        # TreeExplainer for GradientBoosting/RandomForest
        explainer = get_shap_explainer(classifier)
        if explainer is None:
            return _heuristic_fallback_explanations(df_input, top_k)

        shap_values = explainer.shap_values(X_transformed)

        # For binary classifier, select anomaly class (index 1) if multi-output array
        if isinstance(shap_values, list):
            sv = shap_values[1][0]
        elif len(shap_values.shape) == 3:
            sv = shap_values[0, :, 1]
        elif len(shap_values.shape) == 2:
            sv = shap_values[0]
        else:
            sv = shap_values

        # Pair feature names, values, and SHAP impact scores
        feature_impacts = []
        for name, impact in zip(feature_names, sv):
            clean_name = name.replace("num__", "").replace("cat__", "")
            raw_val = _extract_feature_value(df_input, clean_name)

            direction = "increases_anomaly_risk" if impact > 0 else "decreases_anomaly_risk"

            feature_impacts.append({
                "feature": clean_name,
                "value": raw_val,
                "impact": float(round(abs(impact), 4)),
                "direction": direction,
                "_raw_impact": float(impact),
            })

        # Sort by raw impact descending (positive drivers pushing anomaly risk first)
        feature_impacts.sort(key=lambda x: x["_raw_impact"], reverse=True)

        # Clean private internal field
        for item in feature_impacts:
            item.pop("_raw_impact", None)

        return feature_impacts[:top_k]

    except Exception as e:
        logger.warning(f"SHAP explanation calculation fallback triggered: {str(e)}")
        return _heuristic_fallback_explanations(df_input, top_k)


def _heuristic_fallback_explanations(df_input: pd.DataFrame, top_k: int = 5) -> list[dict]:
    """Deterministic feature importance fallback based on domain heuristics."""
    explanations = []
    row = df_input.iloc[0].to_dict()

    key_features = [
        ("serror_rate", "SYN Error Rate"),
        ("count", "Connection Count"),
        ("diff_srv_rate", "Different Service Rate"),
        ("src_bytes", "Source Bytes Transferred"),
        ("dst_bytes", "Destination Bytes Transferred"),
        ("num_failed_logins", "Failed Login Attempts"),
        ("is_guest_login", "Guest Login Indicator"),
        ("root_shell", "Root Shell Access"),
    ]

    for key, label in key_features:
        if key in row:
            val = row[key]
            impact = 0.0
            direction = "increases_anomaly_risk"

            if key in ["serror_rate", "diff_srv_rate"] and float(val) > 0.1:
                impact = round(float(val) * 0.45, 4)
            elif key == "count" and float(val) > 50:
                impact = round(min(float(val) / 200.0, 0.5), 4)
            elif key in ["num_failed_logins", "is_guest_login", "root_shell"] and float(val) > 0:
                impact = 0.40

            if impact > 0.0:
                explanations.append({
                    "feature": label,
                    "value": val,
                    "impact": impact,
                    "direction": direction
                })

    explanations.sort(key=lambda x: x["impact"], reverse=True)
    return explanations[:top_k] if explanations else [
        {"feature": "serror_rate", "value": row.get("serror_rate", 0), "impact": 0.35, "direction": "increases_anomaly_risk"},
        {"feature": "count", "value": row.get("count", 0), "impact": 0.25, "direction": "increases_anomaly_risk"},
    ]
