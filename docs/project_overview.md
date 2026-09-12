# NetGuard AI — Project Overview

## Project Objective
NetGuard AI is designed as a Machine Learning based Network Intrusion Detection System (NIDS). Its primary objective is to analyze pre-recorded network connection features, accurately distinguish normal network traffic from anomalous network activity, and issue immediate early warning alerts to security analysts.

## Problem & Motivation
Network infrastructure in modern organizations produces high volumes of connection records. Manually reviewing connection logs to discover subtle intrusion attempts is slow and error-prone. NetGuard AI provides automated, high-precision detection using supervised machine learning algorithms.

## Solution Architecture Summary
- **Data Layer:** Kaggle Network Intrusion Detection dataset (`Train_data.csv`, `Test_data.csv`).
- **Preprocessing Layer:** Standardized scaling for 36 numerical attributes and One-Hot Encoding for 3 categorical attributes (`protocol_type`, `service`, `flag`), with zero-variance constant feature removal.
- **Model Layer:** Gradient Boosting Classifier serialized via Joblib pipeline achieving **99.68% Stratified Validation Accuracy**.
- **API Layer:** FastAPI server providing asynchronous `/predict` and `/health` REST endpoints with strict 41-feature Pydantic validation.
- **UI Layer:** Web-based security dashboard with quick sample preset loaders and early warning alert notifications.

## Key Features & Model Results
- **Binary Classification:** Classifies traffic records as `normal` or `anomaly`.
- **Validation Accuracy:** 99.68% Stratified Validation Accuracy.
- **Validation F1-Score:** 0.9966.
- **Early Warning Alert:** High-contrast alert banner triggering `⚠ ANOMALOUS NETWORK ACTIVITY DETECTED`.

## Scope & Limitations
- **Binary Scope:** The model performs binary normal vs anomaly classification based on the supplied dataset annotations.
- **Dataset Attack Labels:** While DoS, Probe, R2L, and U2R are mentioned in the original problem statement description, the supplied dataset provides binary labels (`normal` and `anomaly`). Therefore, four-class attack categorization is not claimed.
- **Offline Payloads:** Processes pre-recorded network feature vectors rather than raw socket packet sniffing.
- **No Auto-Blocking:** Designed for SOC analyst alerting rather than automated network firewall socket termination.

## Future Work
- Integration with live packet sniffing engines (Scapy/PyShark).
- Streaming pipeline integration (Kafka/Redis).
- Multi-class attack classification using extended datasets.
- Explainable AI (XAI) feature attribution with SHAP/LIME.
