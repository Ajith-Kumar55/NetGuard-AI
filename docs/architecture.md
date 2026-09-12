# NetGuard AI — System Architecture & Data Flow

## System Overview

NetGuard AI connects data preprocessing, model inference, REST API backend, and web frontend UI into a unified machine learning system.

```
+-------------------------------------------------------------------------------+
|                               NETGUARD AI SYSTEM                              |
+-------------------------------------------------------------------------------+

[ Raw Network Data (Train_data.csv) ]
                  │
                  ▼
[ Data Analysis & Feature Selection (src/data_analysis.py) ]
  • Remove zero-variance constant columns (num_outbound_cmds, is_host_login)
  • Separate 36 Numerical & 3 Categorical Features
                  │
                  ▼
[ Preprocessing Pipeline (src/preprocessing.py) ]
  • StandardScaler for Numerical Features
  • OneHotEncoder(handle_unknown='ignore') for Categorical Features
                  │
                  ▼
[ Machine Learning Model Training (src/train.py) ]
  • Stratified Train/Val Split (80/20)
  • Model Comparison: Logistic Regression vs Random Forest vs Gradient Boosting
  • Final Model Selection: Gradient Boosting Classifier (99.68% Validation Accuracy)
                  │
                  ▼
[ Model Pipeline Serialization (models/nids_pipeline.joblib) ]
                  │
                  ▼
[ FastAPI Backend Application (backend/main.py) ]
  • Startup lifespan pre-loading of model pipeline
  • Pydantic Payload Validation (TrafficFeatureInput for 41 features)
  • Endpoints: GET /health, POST /predict, GET /api/metrics, GET /api/samples
  • Safe Error Handling & Traceback Masking
                  │
                  ▼
[ Web Frontend Dashboard (frontend/) ]
  • Header with dynamic "Model Loaded" status indicator via GET /health
  • Traffic Input Form (41 attributes organized in 4 logical sections)
  • Preset loaders (🟢 Load Normal Sample, 🔴 Load Anomaly Sample)
  • Results Card displaying Model Probability (probability * 100)
  • Early Warning Alert Banner (⚠️ Early Warning: Potential malicious network activity detected)
```

## Detailed Data Processing Flow

1. **User Interaction:** Analyst enters network traffic attributes or clicks sample preset buttons on the Web Dashboard (`frontend/index.html`).
2. **HTTP API Request:** The browser submits a `POST /predict` request to the FastAPI server containing JSON formatted 41-feature dictionary.
3. **Pydantic Validation:** `TrafficFeatureInput` verifies feature types. Invalid data types trigger a safe `422 Unprocessable Entity` response without exposing internal tracebacks.
4. **Pipeline Transformation:** `predict_single()` passes the record into the loaded Scikit-Learn `Pipeline`. `ColumnTransformer` standardizes numerical fields and encodes categorical variables.
5. **Model Inference:** `GradientBoostingClassifier` computes class prediction (`normal`=0, `anomaly`=1) and prediction probability.
6. **Response Payload:** Backend returns:
   ```json
   {
     "prediction": "normal or anomaly",
     "probability": 0.9995,
     "status": "NORMAL or ALERT",
     "timestamp": "2026-09-11 22:03:55"
   }
   ```
7. **Early Warning Banner:** Frontend formats `probability` as a percentage (e.g. `99.95%`) and renders the Early Warning banner if `prediction == "anomaly"`.
