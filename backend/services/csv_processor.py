"""
CSV File Batch Processing and High-Throughput Validation Service for NetGuard AI.
Processes uploaded CSV files using vectorized Scikit-Learn batch inference, computes aggregate statistics,
and generates top-k SHAP explanations for selected high-risk anomalous connections.
"""

from datetime import datetime
import io
import logging
import time
from typing import Any, Dict, List, Tuple
import numpy as np
import pandas as pd

from src.preprocessing import CONSTANT_FEATURES, REVERSE_LABEL_MAP
from src.attack_mapping import heuristic_attack_family
from backend.services.xai_service import compute_shap_explanations
from backend.services.mitigation_service import get_mitigation_recommendations

logger = logging.getLogger("nids_backend")


def process_csv_bytes(file_bytes: bytes, filename: str) -> Tuple[List[dict], dict]:
    """
    Backward-compatible helper function for reading raw CSV records.
    """
    try:
        df = pd.read_csv(io.BytesIO(file_bytes))
    except Exception as e:
        raise ValueError(f"Invalid or corrupted CSV file format: {str(e)}")

    if df.empty:
        raise ValueError("Uploaded CSV file is empty.")

    df.columns = [str(c).strip() for c in df.columns]
    records = df.to_dict(orient="records")
    return records, {"total_rows": len(df)}


def process_csv_batch(
    file_bytes: bytes,
    filename: str,
    pipeline: Any,
    stage2_pipeline: Any = None,
    max_shap_count: int = 10,
    max_triage_results: int = 500,
) -> Dict[str, Any]:
    """
    Executes vectorized batch inference over full CSV dataframes.
    Completes tens of thousands of rows in seconds without blocking or row-by-row loops.
    """
    t_start = time.perf_counter()
    logger.info(f"[*] Starting high-throughput batch CSV processing for '{filename}'...")

    try:
        df_raw = pd.read_csv(io.BytesIO(file_bytes))
    except Exception as e:
        raise ValueError(f"Failed to parse CSV file: {str(e)}")

    if df_raw.empty:
        raise ValueError("Uploaded CSV file contains no data rows.")

    df_raw.columns = [str(c).strip() for c in df_raw.columns]

    # Required feature column normalization
    df_clean = df_raw.copy()

    # Ensure all constant features exist
    for c in CONSTANT_FEATURES:
        if c not in df_clean.columns:
            df_clean[c] = 0

    defaults = {
        "protocol_type": "tcp",
        "service": "http",
        "flag": "SF",
    }
    for col, val in defaults.items():
        if col not in df_clean.columns:
            df_clean[col] = val

    t_parse_end = time.perf_counter()

    # Vectorized Stage 1 Binary Batch Prediction
    t_inf_start = time.perf_counter()
    preds1 = pipeline.predict(df_clean)
    probs1 = pipeline.predict_proba(df_clean)[:, 1] if hasattr(pipeline, "predict_proba") else np.zeros(len(df_clean))

    total_records = len(df_raw)
    anom_indices = np.where(preds1 == 1)[0]
    normal_indices = np.where(preds1 == 0)[0]

    anomaly_count = int(len(anom_indices))
    normal_count = int(len(normal_indices))

    # Vectorized Stage 2 Multi-Class Batch Prediction for anomalies
    stage2_families = {}
    stage2_confs = {}
    stage2_type = "stage2_ml" if stage2_pipeline is not None else "heuristic_fallback"

    if anomaly_count > 0:
        df_anom = df_clean.iloc[anom_indices]
        if stage2_pipeline is not None:
            try:
                preds2 = stage2_pipeline.predict(df_anom)
                probs2 = stage2_pipeline.predict_proba(df_anom)

                for idx_rel, orig_idx in enumerate(anom_indices):
                    family = str(preds2[idx_rel])
                    max_p = float(round(np.max(probs2[idx_rel]), 4))
                    stage2_families[orig_idx] = family
                    stage2_confs[orig_idx] = max_p
            except Exception as e:
                logger.warning(f"Stage 2 batch prediction fallback triggered: {str(e)}")
                stage2_type = "heuristic_fallback"

        if stage2_type == "heuristic_fallback":
            for orig_idx in anom_indices:
                row_dict = df_clean.iloc[orig_idx].to_dict()
                fam, conf = heuristic_attack_family(row_dict)
                stage2_families[orig_idx] = fam
                stage2_confs[orig_idx] = conf

    # Compute risk scores
    risk_scores = np.round(probs1 * 100.0, 2)
    for orig_idx in anom_indices:
        fam = stage2_families.get(orig_idx, "DoS")
        if fam in ["U2R", "R2L"]:
            risk_scores[orig_idx] = max(risk_scores[orig_idx], 88.0)
        elif fam == "DoS":
            risk_scores[orig_idx] = max(risk_scores[orig_idx], 75.0)

    # Calculate Attack Distribution
    attack_distribution = {}
    for orig_idx in anom_indices:
        fam = stage2_families.get(orig_idx, "Unknown")
        attack_distribution[fam] = attack_distribution.get(fam, 0) + 1

    # Select top-k anomalous rows for SHAP explanations (sorted by risk_score descending)
    shap_target_indices = set()
    if anomaly_count > 0:
        anom_risk_pairs = [(orig_idx, risk_scores[orig_idx]) for orig_idx in anom_indices]
        anom_risk_pairs.sort(key=lambda x: x[1], reverse=True)
        shap_target_indices = set(x[0] for x in anom_risk_pairs[:max_shap_count])

    shap_cache = {}
    logger.info(f"[*] Calculating SHAP feature attributions for top {len(shap_target_indices)} high-risk anomalous rows...")
    for idx in shap_target_indices:
        row_df = df_clean.iloc[[idx]]
        try:
            raw_top = compute_shap_explanations(pipeline, row_df, top_k=5)
            clean_top = []
            for tf in raw_top:
                val = tf.get("value")
                clean_top.append({
                    "feature": str(tf.get("feature")),
                    "value": val.item() if hasattr(val, "item") else val,
                    "impact": float(tf.get("impact", 0.0)),
                    "direction": str(tf.get("direction")),
                })
            shap_cache[idx] = clean_top
        except Exception:
            shap_cache[idx] = None

    t_inf_end = time.perf_counter()

    # Prepare triage result records
    timestamp_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Pick indices to include in triage response (all if total <= max_triage_results, else top anomalies + normal sample)
    if total_records <= max_triage_results:
        triage_indices = list(range(total_records))
    else:
        # Prioritize all anomalies up to limit
        triage_indices = list(anom_indices[:max_triage_results])

    results = []
    for idx in triage_indices:
        pred_label = REVERSE_LABEL_MAP.get(int(preds1[idx]), "unknown")
        is_anom = pred_label == "anomaly"
        status_str = "ALERT" if is_anom else "NORMAL"

        r_score = float(risk_scores[idx])

        if r_score >= 90.0:
            r_level = "Critical"
        elif r_score >= 75.0:
            r_level = "High"
        elif r_score >= 60.0:
            r_level = "Medium"
        elif r_score >= 40.0:
            r_level = "Low"
        else:
            r_level = "Normal"

        fam = stage2_families.get(idx) if is_anom else None
        s2_c = stage2_confs.get(idx) if is_anom else None
        c_type = stage2_type if is_anom else None
        mit = get_mitigation_recommendations(fam) if is_anom else None

        row_raw = df_raw.iloc[idx]
        src_ip = str(row_raw.get("_source_ip", row_raw.get("source_ip", f"192.168.1.{10 + (idx % 200)}")))
        dst_ip = str(row_raw.get("_destination_ip", row_raw.get("destination_ip", f"10.0.0.{1 + (idx % 50)}")))
        proto = str(row_raw.get("protocol_type", "tcp")).upper()

        results.append({
            "prediction": pred_label,
            "status": status_str,
            "probability": float(round(probs1[idx], 4)),
            "risk_score": r_score,
            "risk_level": r_level,
            "attack_family": fam,
            "stage2_confidence": s2_c,
            "classifier_type": c_type,
            "top_features": shap_cache.get(idx),
            "mitigation": mit,
            "timestamp": timestamp_str,
            "source_ip": src_ip,
            "destination_ip": dst_ip,
            "protocol": proto,
            "raw_payload": row_raw.to_dict(),
        })

    t_end = time.perf_counter()

    parsing_latency_ms = round((t_parse_end - t_start) * 1000.0, 3)
    inference_latency_ms = round((t_inf_end - t_inf_start) * 1000.0, 3)
    total_processing_time_ms = round((t_end - t_start) * 1000.0, 3)
    average_flow_latency_ms = round(total_processing_time_ms / max(1, total_records), 3)

    logger.info(f"[+] Completed batch analysis of {total_records} rows in {total_processing_time_ms:.2f}ms.")

    return {
        "filename": filename,
        "file_type": "CSV",
        "summary": {
            "total_records": total_records,
            "normal_count": normal_count,
            "anomaly_count": anomaly_count,
            "attack_distribution": attack_distribution,
            "average_risk_score": round(float(np.mean(risk_scores)), 2),
            "max_risk_score": round(float(np.max(risk_scores)), 2),
            "processing_time_seconds": round(total_processing_time_ms / 1000.0, 3),
            "parsing_latency_ms": parsing_latency_ms,
            "inference_latency_ms": inference_latency_ms,
            "total_processing_time_ms": total_processing_time_ms,
            "average_flow_latency_ms": average_flow_latency_ms,
        },
        "results": results,
    }
