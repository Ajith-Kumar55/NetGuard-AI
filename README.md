# NetGuard AI — AI-Powered Network Intrusion Detection System (NIDS)

**Artificial Intelligence • Cybersecurity • Explainable AI (XAI) • Network Operations**

---

## Metadata

- **Technology:** Python, FastAPI, Scikit-learn, Pandas, NumPy, Scapy, SHAP, SQLAlchemy, SQLite, PyJWT, Passlib, HTML5, CSS3, Chart.js, Docker
- **Domain:** Artificial Intelligence + Cybersecurity
- **Project Type:** Production-Grade Capstone NIDS & Threat Triage SOC Dashboard

---

## 1. Overview

**NetGuard AI** is an advanced, production-grade Network Intrusion Detection System (NIDS) and Threat Triage Security Operations Center (SOC) dashboard. It combines 2-Stage Hierarchical Machine Learning classification, Scapy-powered packet/flow ingestion, SHAP (SHapley Additive exPlanations) Explainable AI, automated rule-based threat mitigation, and persistent database audit trails.

The system processes network connection logs and PCAP/PCAPNG network packet captures, providing:
1. **Stage 1 Binary Classification:** `normal` (safe) vs `anomaly` (suspicious).
2. **Stage 2 Attack Taxonomy Classification:** Classifies anomalous flows into recognized attack families:
   - **DoS (Denial of Service):** High-volume resource exhaustion attacks (e.g., `neptune`, `smurf`, `back`).
   - **Probe:** Reconnaissance and port scanning activities (e.g., `satan`, `ipsweep`, `nmap`).
   - **R2L (Remote to Local):** Unauthorized remote access attempts (e.g., `warezclient`, `guess_passwd`).
   - **U2R (User to Root):** Privilege escalation attacks (e.g., `buffer_overflow`, `rootkit`).
3. **Explainable AI (SHAP XAI):** Computes feature attributions using SHAP `TreeExplainer` to explain *why* a connection was flagged.
4. **Actionable Mitigation Guidance:** Provides rule-based defense recommendations tailored to the specific attack family.

---

## 2. Key Features

- **OAuth2 JWT Authentication & PBKDF2 Password Hashing:** User registration, secure login, role-based analyst access (`GET /api/auth/me`).
- **SQLite & SQLAlchemy Data Persistence:** Stores user records and prediction logs with indexed timestamps.
- **Scapy PCAP / PCAPNG & CSV File Ingestion:** Ingests raw network packet captures (`.pcap`, `.pcapng`) and CSV flow logs, reconstructing 5-tuple flows into 41-feature vectors.
- **2-Stage Hierarchical ML Classification:**
  - **Stage 1:** Gradient Boosting model trained on 25,192 network connection records achieving **99.68% validation accuracy**.
  - **Stage 2:** Domain-engineered attack taxonomy mapping into `DoS`, `Probe`, `R2L`, and `U2R`.
- **Explainable AI (SHAP TreeExplainer):** Calculates local feature importances and positive/negative push values.
- **Threat Mitigation Engine:** Rule-based security recommendations for firewalls, rate limiting, and access controls.
- **SOC Analyst Web Dashboard:** Dark-themed responsive interface with:
  - **OAuth2 Login Modal:** Registration and authentication.
  - **Threat Triage Table:** Real-time log view with color-coded risk levels (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `NORMAL`).
  - **File Ingestion Dropzone:** Drag-and-drop support for `.pcap`, `.pcapng`, and `.csv`.
  - **SHAP Modal:** Interactive visual breakdown of feature contributions.
  - **Collapsible Debug Accordion:** Raw JSON request payload and response inspector for technical auditing.
- **Automated Test Suite:** 28/28 passing pytest automated tests covering API, Auth, DB, PCAP parsing, ML, Stage 2, SHAP, Latency, and CSV Audit Export.
- **Docker Containerization:** Ready for `python:3.11-slim` single-stage container build.

---

## 3. System Architecture

```
                               ┌──────────────────────────────────────────────┐
                               │        SOC Analyst Web Dashboard             │
                               │ (HTML5 / CSS3 / JavaScript / Chart.js / UI) │
                               └──────────────────────┬───────────────────────┘
                                                      │ (JWT Token Bearer)
                                                      ▼
                               ┌──────────────────────────────────────────────┐
                               │           FastAPI REST Backend               │
                               │        (backend/main.py & Endpoints)         │
                               └───────┬──────────────┬───────────────┬───────┘
                                       │              │               │
            ┌──────────────────────────┘              │               └──────────────────────────┐
            ▼                                         ▼                                          ▼
┌───────────────────────┐         ┌───────────────────────┐                  ┌───────────────────────┐
│ Database Persistence  │         │ File & Payload Ingestion│                  │  ML & XAI Engine      │
│  (SQLite/SQLAlchemy)  │         │   (CSV & Scapy PCAP)  │                  │(Joblib / SHAP / Rules)│
└───────────────────────┘         └───────────────────────┘                  └───────────────────────┘
```

---

## 4. API Specification

### Authentication
- `POST /api/auth/register` — Register new security analyst user.
- `POST /api/auth/login` — OAuth2 Password Request Form endpoint returning JWT Bearer token.
- `GET /api/auth/me` — Return authenticated user session info.

### Detection & Analysis
- `POST /predict` — Analyze single 41-feature network traffic payload. Returns prediction, confidence score, attack family, SHAP feature importances, and mitigation strategy.
- `POST /api/analyze/file` — Multipart upload for PCAP (`.pcap`, `.pcapng`) or CSV (`.csv`) files. Automatically parses flows, runs inference, and returns batch results.

### History & Auditing
- `GET /api/history` — Fetch paginated prediction log from SQLite database.
- `DELETE /api/history` — Clear history records.

### System & Metrics
- `GET /health` — Health check endpoint (`status: ok`, `database: connected`, `model_loaded: true`).
- `GET /api/metrics` — ML model evaluation metrics and confusion matrix metadata.
- `GET /api/samples` — Verified preset samples (`normal` and `anomaly`).

---

## 5. Machine Learning & Explainable AI (SHAP)

### Model Benchmarks
Three candidate models were evaluated on the stratified validation dataset:

| Model Architecture | Validation Accuracy | Precision | Recall | F1-Score | Status |
| :--- | :---: | :---: | :---: | :---: | :--- |
| **Gradient Boosting Classifier** | **99.68%** | **99.83%** | **99.49%** | **0.9966** | **🏆 Selected Final Model** |
| Random Forest Classifier | 99.66% | 99.87% | 99.40% | 0.9964 | Benchmark Runner-Up |
| Logistic Regression | 97.14% | 97.79% | 96.04% | 0.9691 | Baseline Model |

### Explainable AI (SHAP)
SHAP `TreeExplainer` computes exact Shapley values for input features, identifying the top drivers for anomaly classification (e.g., `count`, `serror_rate`, `same_srv_rate`, `src_bytes`, `service_http`).

---

## 6. Installation & Local Setup

### Prerequisites
- Python 3.10+
- Git

### Setup Steps (Windows PowerShell)

```powershell
# Clone repository
git clone <repository-url>
cd network-intrusion-detection

# Create and activate Python virtual environment
python -m venv venv
.\venv\Scripts\Activate.ps1

# Install required dependencies
pip install -r requirements.txt
```

### Environment Configuration (Optional)
Copy `.env.example` to `.env` to configure environment variables:

```env
DATABASE_URL=sqlite:///./netguard.db
JWT_SECRET_KEY=replace-with-a-long-random-secret
JWT_ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=1440
CORS_ORIGINS=http://127.0.0.1:8080
UPLOAD_MAX_SIZE_MB=50
```

> **Security Note**: `JWT_SECRET_KEY` must be changed to a strong, randomly generated secret value before deploying to production.

---

## 7. Running the Application

Launch the FastAPI backend server:

```powershell
python -m uvicorn backend.main:app --host 127.0.0.1 --port 8080
```

Open your browser and navigate to:
**`http://127.0.0.1:8080/`**

### Quick Demo Credentials
- **Username:** `admin`
- **Password:** `admin123`

---

## 8. Automated Testing

Execute the automated pytest suite:

```powershell
python -m pytest tests/ -v
```

**Current Test Results:** **28/28 tests passing** (100% pass rate).

Test breakdown:
- `tests/test_api.py` — API endpoints, health, predict, batch CSV, auth.
- `tests/test_auth.py` — Password hashing, JWT token generation & verification.
- `tests/test_database.py` — SQLAlchemy models & DB CRUD operations.
- `tests/test_pcap.py` — Scapy PCAP flow extraction & 41-feature generation.
- `tests/test_pipeline.py` — Preprocessing & ML inference pipeline.
- `tests/test_stage2.py` — Stage 2 multi-class ML attack-family classifier.
- `tests/test_xai.py` — SHAP explainability & rule-based mitigations.

---

## 9. Docker Deployment

Build and run using Docker:

```bash
# Build Docker image
docker build -t netguard-ai-nids .

# Run container listening on port 8000
docker run -p 8000:8000 netguard-ai-nids
```

---

## 10. License

This project is licensed under the [MIT License](LICENSE).
