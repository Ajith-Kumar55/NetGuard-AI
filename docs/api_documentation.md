# NetGuard AI — API Documentation

The FastAPI backend provides REST endpoints for real-time intrusion classification, health monitoring, and metrics extraction.

---

## Base URL
Local Development: `http://127.0.0.1:8080`

---

## 1. Health Check Endpoint

### `GET /health`

Verifies that the server is active and the pre-trained machine learning model pipeline is successfully loaded into memory.

#### Response Example (`200 OK`)
```json
{
  "status": "healthy",
  "model_loaded": true,
  "service": "Network Intrusion Detection System (NIDS)",
  "timestamp": "2026-09-11T22:03:54.962551"
}
```

---

## 2. Prediction Endpoint

### `POST /predict`

Accepts network traffic features and returns intrusion classification, model probability score, alert status, and timestamp.

#### Headers
`Content-Type: application/json`

#### Request Body Example (41 Features)
```json
{
  "duration": 0,
  "protocol_type": "tcp",
  "service": "private",
  "flag": "S0",
  "src_bytes": 0,
  "dst_bytes": 0,
  "land": 0,
  "wrong_fragment": 0,
  "urgent": 0,
  "hot": 0,
  "num_failed_logins": 0,
  "logged_in": 0,
  "num_compromised": 0,
  "root_shell": 0,
  "su_attempted": 0,
  "num_root": 0,
  "num_file_creations": 0,
  "num_shells": 0,
  "num_access_files": 0,
  "num_outbound_cmds": 0,
  "is_host_login": 0,
  "is_guest_login": 0,
  "count": 123,
  "srv_count": 6,
  "serror_rate": 1.0,
  "srv_serror_rate": 1.0,
  "rerror_rate": 0.0,
  "srv_rerror_rate": 0.0,
  "same_srv_rate": 0.05,
  "diff_srv_rate": 0.07,
  "srv_diff_host_rate": 0.0,
  "dst_host_count": 255,
  "dst_host_srv_count": 6,
  "dst_host_same_srv_rate": 0.02,
  "dst_host_diff_srv_rate": 0.07,
  "dst_host_same_src_port_rate": 0.0,
  "dst_host_srv_diff_host_rate": 0.0,
  "dst_host_serror_rate": 1.0,
  "dst_host_srv_serror_rate": 1.0,
  "dst_host_rerror_rate": 0.0,
  "dst_host_srv_rerror_rate": 0.0
}
```

#### Response Example (`200 OK` - Anomaly Detected)
```json
{
  "prediction": "anomaly",
  "probability": 0.9995,
  "status": "ALERT",
  "timestamp": "2026-09-11 22:03:55"
}
```

#### Response Example (`200 OK` - Normal Traffic)
```json
{
  "prediction": "normal",
  "probability": 0.0010,
  "status": "NORMAL",
  "timestamp": "2026-09-11 22:03:55"
}
```

#### Response Example (`422 Unprocessable Entity` - Invalid Data Format)
```json
{
  "detail": "Invalid input features format or missing required payload data."
}
```

---

## 3. Metrics Endpoint

### `GET /api/metrics`

Returns trained model performance comparison benchmarks and confusion matrix metadata.

#### Response Example (`200 OK`)
```json
{
  "metrics": {
    "best_model": "Gradient Boosting",
    "best_f1_score": 0.9966,
    "comparison": {
      "Gradient Boosting": {
        "accuracy": 0.9968,
        "precision": 0.9983,
        "recall": 0.9949,
        "f1_score": 0.9966,
        "confusion_matrix": [[2686, 4], [12, 2337]]
      }
    }
  }
}
```

---

## 4. Sample Presets Endpoint

### `GET /api/samples`

Returns sample feature payloads for `normal` and `anomaly` traffic records for fast testing.

#### Response Example (`200 OK`)
```json
{
  "normal": { "duration": 0, "protocol_type": "tcp", "service": "http", ... },
  "anomaly": { "duration": 0, "protocol_type": "tcp", "service": "private", ... }
}
```
