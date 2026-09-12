"""
FastAPI Backend Server for NetGuard AI — AI-Powered Network Intrusion Detection System.
Provides JWT OAuth2 authentication, SQLite persistence, file ingestion (.csv, .pcap, .pcapng),
2-stage ML inference, SHAP XAI explanations, rule-based mitigation, and history management.
"""

from contextlib import asynccontextmanager
import csv
from datetime import datetime
import io
import logging
import os
import sys
import time
from typing import Any, Dict, List, Optional

from fastapi import Depends, FastAPI, File, Form, HTTPException, Query, Request, UploadFile, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.staticfiles import StaticFiles
from sqlalchemy.orm import Session

# Add src and backend directories to sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))

from backend.auth import (
    create_access_token,
    get_password_hash,
    verify_password,
)
from backend.database import SessionLocal, init_db
from backend.dependencies import get_current_active_user, get_current_user, get_db
from backend.models import DetectionLog, User
from backend.schemas import (
    AnalysisResult,
    DetectionLogResponse,
    PaginatedHistoryResponse,
    Token,
    TrafficFeatureInput,
    UserCreate,
    UserResponse,
)
from backend.services.csv_processor import process_csv_batch, process_csv_bytes
from backend.services.pcap_processor import process_pcap_bytes
from src.predict import load_model_and_metadata, load_stage2_model, predict_single

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("nids_backend")

_MODEL_LOADED = False
MAX_UPLOAD_SIZE_MB = int(os.getenv("UPLOAD_MAX_SIZE_MB", "50"))


def _ensure_model_and_db_loaded():
    global _MODEL_LOADED
    try:
        init_db()
        load_model_and_metadata()
        _MODEL_LOADED = True
        logger.info("NIDS database and ML pipeline loaded successfully into memory.")
        _seed_initial_admin()
    except Exception as e:
        logger.error(f"Failed during application initialization: {str(e)}")
        _MODEL_LOADED = False
    return _MODEL_LOADED


def _seed_initial_admin():
    """Seeds default admin user (admin / admin123) if database is empty."""
    db = SessionLocal()
    try:
        admin_user = db.query(User).filter(User.username == "admin").first()
        if not admin_user:
            hashed_pw = get_password_hash("admin123")
            new_admin = User(username="admin", hashed_password=hashed_pw, role="admin")
            db.add(new_admin)
            db.commit()
            logger.info("Seeded initial default admin user (admin / admin123).")
    except Exception as e:
        logger.error(f"Failed to seed admin user: {str(e)}")
        db.rollback()
    finally:
        db.close()


@asynccontextmanager
async def lifespan(app: FastAPI):
    _ensure_model_and_db_loaded()
    yield
    logger.info("Shutting down NetGuard AI application...")


app = FastAPI(
    title="NetGuard AI — Network Intrusion Detection System API",
    description="Capstone-Level Machine Learning NIDS REST API Service with Scapy PCAP parsing & SHAP XAI",
    version="1.0.0",
    lifespan=lifespan,
)

_ensure_model_and_db_loaded()

# Enable CORS for frontend integration
origins = os.getenv("CORS_ORIGINS", "*").split(",")
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins if origins != ["*"] else ["*"],
    allow_credentials=False,
    allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)


# Exception Handlers
@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    logger.warning(f"Validation error: {exc}")
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={"detail": "Invalid input schema or missing required request data."},
    )


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error(f"Internal server exception: {exc}")
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "An internal server error occurred while processing the request."},
    )


# System Health
@app.get("/health")
def health_check():
    """Health check endpoint verifying model load status."""
    is_loaded = _ensure_model_and_db_loaded()
    return {
        "status": "healthy",
        "model_loaded": is_loaded,
        "service": "NetGuard AI Network Intrusion Detection System",
        "timestamp": datetime.now().isoformat(),
    }


# Authentication Endpoints
@app.post("/api/auth/login", response_model=Token)
def login_for_access_token(
    form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)
):
    """OAuth2 password bearer login endpoint."""
    user = db.query(User).filter(User.username == form_data.username).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token = create_access_token(data={"sub": user.username})
    return {"access_token": access_token, "token_type": "bearer"}


@app.post("/api/auth/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
def register_user(user_data: UserCreate, db: Session = Depends(get_db)):
    """User registration endpoint."""
    existing_user = db.query(User).filter(User.username == user_data.username).first()
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already registered.",
        )
    hashed_pw = get_password_hash(user_data.password)
    new_user = User(username=user_data.username, hashed_password=hashed_pw, role=user_data.role or "admin")
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return new_user


@app.get("/api/auth/me", response_model=UserResponse)
def read_current_user_profile(current_user: User = Depends(get_current_active_user)):
    """Returns authenticated user profile information."""
    return current_user


# Single Feature Payload Prediction Endpoint
@app.post("/predict")
def predict_traffic(payload: TrafficFeatureInput, db: Session = Depends(get_db), current_user: Optional[User] = Depends(get_current_user)):
    """
    Manual 41-feature analysis endpoint.
    Accepts 41 network traffic features, executes 2-stage ML inference, and logs to SQLite database.
    """
    if not _ensure_model_and_db_loaded():
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="NetGuard AI Model is currently loading or unavailable.",
        )

    try:
        input_data = payload.model_dump()
        result = predict_single(input_data)

        # Save to SQLite database
        log_entry = DetectionLog(
            timestamp=datetime.strptime(result["timestamp"], "%Y-%m-%d %H:%M:%S"),
            source_ip=result["source_ip"],
            destination_ip=result["destination_ip"],
            protocol=result["protocol"],
            classification=result["prediction"],
            attack_family=result.get("attack_family"),
            risk_score=result["risk_score"],
            confidence=result["probability"],
            top_features=result.get("top_features"),
            raw_payload=input_data,
            user_id=current_user.id if current_user else None,
        )
        db.add(log_entry)
        db.commit()

        return result

    except Exception as e:
        logger.error(f"Prediction execution failed: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to generate network intrusion prediction.",
        )


# File Analysis Endpoint (.csv, .pcap, .pcapng)
@app.post("/api/analyze/file")
async def analyze_file(
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_current_user)
):
    """
    Primary File Ingestion API Endpoint.
    Accepts CSV or PCAP/PCAPNG file uploads, validates format, extracts feature vectors,
    executes batch 2-stage ML analysis, persists detections in SQLite DB, and returns triage summary.
    """
    if not file or not file.filename:
        raise HTTPException(status_code=400, detail="No file uploaded.")

    filename = file.filename
    ext = os.path.splitext(filename)[1].lower()

    if ext not in [".csv", ".pcap", ".pcapng"]:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported file extension '{ext}'. Only .csv, .pcap, and .pcapng files are supported."
        )

    contents = await file.read()
    size_mb = len(contents) / (1024 * 1024)
    if size_mb > MAX_UPLOAD_SIZE_MB:
        raise HTTPException(
            status_code=413,
            detail=f"Uploaded file size ({size_mb:.2f} MB) exceeds maximum allowed size ({MAX_UPLOAD_SIZE_MB} MB)."
        )

    try:
        if ext == ".csv":
            pipeline, _ = load_model_and_metadata()
            stage2_pipeline = load_stage2_model()
            analysis_data = process_csv_batch(contents, filename, pipeline, stage2_pipeline, max_shap_count=10)

            db_logs = []
            for res in analysis_data["results"]:
                db_logs.append(
                    DetectionLog(
                        timestamp=datetime.strptime(res["timestamp"], "%Y-%m-%d %H:%M:%S"),
                        source_ip=res["source_ip"],
                        destination_ip=res["destination_ip"],
                        protocol=res["protocol"],
                        classification=res["prediction"],
                        attack_family=res.get("attack_family"),
                        risk_score=res["risk_score"],
                        confidence=res["probability"],
                        top_features=res.get("top_features"),
                        raw_payload=res.get("raw_payload"),
                        user_id=current_user.id if current_user else None,
                    )
                )
            if db_logs:
                db.bulk_save_objects(db_logs)
                db.commit()

            return analysis_data
        else:
            t_file_start = time.perf_counter()
            t_parse_start = time.perf_counter()
            records, file_summary = process_pcap_bytes(contents, filename)
            t_parse_end = time.perf_counter()
            parsing_latency_ms = round((t_parse_end - t_parse_start) * 1000.0, 3)

            t_inf_start = time.perf_counter()
            results = []
            normal_count = 0
            anomaly_count = 0
            attack_distribution = {}
            total_risk = 0.0
            max_risk = 0.0

            db_logs = []
            for rec in records:
                res = predict_single(rec)
                results.append(res)

                if res["prediction"] == "anomaly":
                    anomaly_count += 1
                    family = res.get("attack_family", "Unknown")
                    attack_distribution[family] = attack_distribution.get(family, 0) + 1
                else:
                    normal_count += 1

                risk = res["risk_score"]
                total_risk += risk
                if risk > max_risk:
                    max_risk = risk

                db_logs.append(
                    DetectionLog(
                        timestamp=datetime.strptime(res["timestamp"], "%Y-%m-%d %H:%M:%S"),
                        source_ip=res["source_ip"],
                        destination_ip=res["destination_ip"],
                        protocol=res["protocol"],
                        classification=res["prediction"],
                        attack_family=res.get("attack_family"),
                        risk_score=res["risk_score"],
                        confidence=res["probability"],
                        top_features=res.get("top_features"),
                        raw_payload=rec,
                        user_id=current_user.id if current_user else None,
                    )
                )

            t_inf_end = time.perf_counter()
            inference_latency_ms = round((t_inf_end - t_inf_start) * 1000.0, 3)

            db.bulk_save_objects(db_logs)
            db.commit()

            t_file_end = time.perf_counter()
            total_processing_time_ms = round((t_file_end - t_file_start) * 1000.0, 3)
            avg_flow_latency_ms = round(total_processing_time_ms / max(1, len(results)), 3)
            avg_risk = round(total_risk / max(1, len(results)), 2)

            return {
                "filename": filename,
                "file_type": ext[1:].upper(),
                "summary": {
                    "total_records": len(results),
                    "normal_count": normal_count,
                    "anomaly_count": anomaly_count,
                    "attack_distribution": attack_distribution,
                    "average_risk_score": avg_risk,
                    "max_risk_score": max_risk,
                    "parsing_latency_ms": parsing_latency_ms,
                    "inference_latency_ms": inference_latency_ms,
                    "total_processing_time_ms": total_processing_time_ms,
                    "average_flow_latency_ms": avg_flow_latency_ms,
                },
                "results": results,
            }

    except ValueError as ve:
        raise HTTPException(status_code=400, detail=str(ve))
    except Exception as e:
        logger.error(f"File analysis execution failed: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to analyze uploaded file: {str(e)}")


# Database History Endpoints
@app.get("/api/history", response_model=PaginatedHistoryResponse)
def get_detection_history(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Authenticated Detection History Endpoint.
    Returns paginated detection log audit trail and summary statistics from SQLite database.
    """
    from sqlalchemy import func
    total = db.query(DetectionLog).count()
    normal_count = db.query(DetectionLog).filter(DetectionLog.classification == "normal").count()
    anomaly_count = db.query(DetectionLog).filter(DetectionLog.classification == "anomaly").count()

    attack_dist_query = (
        db.query(DetectionLog.attack_family, func.count(DetectionLog.id))
        .filter(DetectionLog.classification == "anomaly")
        .group_by(DetectionLog.attack_family)
        .all()
    )
    attack_distribution = {fam: count for fam, count in attack_dist_query if fam}

    summary = {
        "total_records": total,
        "normal_count": normal_count,
        "anomaly_count": anomaly_count,
        "attack_distribution": attack_distribution,
        "average_risk_score": 0.0,
        "max_risk_score": 0.0,
    }

    offset = (page - 1) * page_size
    logs = (
        db.query(DetectionLog)
        .order_by(DetectionLog.timestamp.desc())
        .offset(offset)
        .limit(page_size)
        .all()
    )

    return {
        "total": total,
        "page": page,
        "page_size": page_size,
        "summary": summary,
        "results": logs,
    }


def sanitize_csv_value(val: Any) -> str:
    """Sanitizes CSV cell value to prevent spreadsheet formula injection attacks (=, +, -, @)."""
    if val is None:
        return ""
    val_str = str(val)
    if val_str and val_str[0] in ("=", "+", "-", "@"):
        return "'" + val_str
    return val_str


@app.get("/api/history/export")
def export_detection_history_csv(
    format: str = Query("csv"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Authenticated Threat Triage Audit Log Export Endpoint.
    Exports ONLY the authenticated user's detection history as a sanitized CSV file.
    """
    if format.lower() != "csv":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported format '{format}'. Only 'csv' format is supported for export."
        )

    logs = (
        db.query(DetectionLog)
        .filter(DetectionLog.user_id == current_user.id)
        .order_by(DetectionLog.timestamp.desc())
        .all()
    )

    output = io.StringIO()
    writer = csv.writer(output)

    writer.writerow([
        "ID",
        "Timestamp",
        "Source IP",
        "Destination IP",
        "Protocol",
        "Classification",
        "Risk Score",
        "Risk Level",
        "Attack Family",
        "Confidence"
    ])

    for log in logs:
        risk_score = float(log.risk_score or 0.0)
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

        timestamp_str = log.timestamp.strftime("%Y-%m-%d %H:%M:%S") if isinstance(log.timestamp, datetime) else str(log.timestamp)

        writer.writerow([
            sanitize_csv_value(log.id),
            sanitize_csv_value(timestamp_str),
            sanitize_csv_value(log.source_ip),
            sanitize_csv_value(log.destination_ip),
            sanitize_csv_value(log.protocol),
            sanitize_csv_value(log.classification),
            sanitize_csv_value(f"{risk_score:.2f}"),
            sanitize_csv_value(risk_level),
            sanitize_csv_value(log.attack_family or "N/A"),
            sanitize_csv_value(f"{float(log.confidence or 0.0):.4f}"),
        ])

    csv_content = output.getvalue()
    filename = f"netguard_threat_triage_audit_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"

    return Response(
        content=csv_content,
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'}
    )


@app.delete("/api/history")
def delete_detection_history(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Authenticated History Clear Endpoint.
    Deletes detection history logs from SQLite database.
    """
    count = db.query(DetectionLog).delete()
    db.commit()
    return {"message": f"Successfully deleted {count} detection history records.", "deleted_count": count}


# Metrics & Samples
@app.get("/api/metrics")
def get_metrics():
    """Returns trained model performance metrics and dataset statistics."""
    try:
        _, metrics = load_model_and_metadata()
        return {"metrics": metrics}
    except Exception as e:
        raise HTTPException(status_code=500, detail="Failed to fetch metrics.")


@app.get("/api/samples")
def get_sample_inputs():
    """Returns sample pre-filled payloads for Normal and Anomaly traffic."""
    try:
        _, metrics = load_model_and_metadata()
        sample_records = metrics.get("sample_records", {})
        return {
            "normal": sample_records.get("normal", {}),
            "anomaly": sample_records.get("anomaly", {}),
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail="Failed to fetch samples.")


# Serve static frontend files
frontend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "frontend"))
if os.path.exists(frontend_dir):
    app.mount("/static", StaticFiles(directory=frontend_dir), name="static")

    @app.get("/")
    def serve_frontend_index():
        index_file = os.path.join(frontend_dir, "index.html")
        if os.path.exists(index_file):
            return FileResponse(index_file)
        return {"message": "Frontend index.html not found."}


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8080))
    host = os.getenv("HOST", "127.0.0.1")
    uvicorn.run(app, host=host, port=port)
