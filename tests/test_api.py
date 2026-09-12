"""
Integration unit tests for FastAPI backend routes including authentication, file analysis, and database history.
"""

import io
import os
import sys
import pandas as pd
import pytest
from fastapi.testclient import TestClient

# Add backend and src to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))

from main import app

client = TestClient(app)


def test_health_endpoint():
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["model_loaded"] is True
    assert "service" in data
    assert "timestamp" in data


def test_auth_login_and_me_endpoints():
    # Login with default admin credentials
    response = client.post("/api/auth/login", data={"username": "admin", "password": "admin123"})
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    token = data["access_token"]

    # Access protected /api/auth/me with bearer token
    headers = {"Authorization": f"Bearer {token}"}
    me_resp = client.get("/api/auth/me", headers=headers)
    assert me_resp.status_code == 200
    me_data = me_resp.json()
    assert me_data["username"] == "admin"


def test_predict_endpoint_with_test_dataset_row():
    test_df = pd.read_csv("data/Test_data.csv")
    sample_row = test_df.iloc[0].to_dict()

    response = client.post("/predict", json=sample_row)
    assert response.status_code == 200
    data = response.json()

    assert "prediction" in data
    assert "probability" in data
    assert "status" in data
    assert "timestamp" in data

    assert data["prediction"] in ["normal", "anomaly"]
    assert isinstance(data["probability"], float)
    if data["prediction"] == "anomaly":
        assert data["status"] == "ALERT"
    else:
        assert data["status"] == "NORMAL"


def test_predict_endpoint_valid_normal_input():
    payload = {
        "duration": 0,
        "protocol_type": "tcp",
        "service": "http",
        "flag": "SF",
        "src_bytes": 215,
        "dst_bytes": 450,
        "count": 10,
        "srv_count": 10,
        "same_srv_rate": 1.0,
        "diff_srv_rate": 0.0,
        "dst_host_count": 255,
        "dst_host_srv_count": 255,
    }
    response = client.post("/predict", json=payload)
    assert response.status_code == 200
    data = response.json()

    assert data["prediction"] == "normal"
    assert data["status"] == "NORMAL"
    assert data["probability"] < 0.5


def test_csv_file_analysis_endpoint():
    test_df = pd.read_csv("data/Test_data.csv").head(5)
    csv_bytes = test_df.to_csv(index=False).encode("utf-8")

    files = {"file": ("test_traffic.csv", io.BytesIO(csv_bytes), "text/csv")}
    response = client.post("/api/analyze/file", files=files)
    assert response.status_code == 200
    data = response.json()

    assert "summary" in data
    assert data["summary"]["total_records"] == 5
    assert "results" in data
    assert len(data["results"]) == 5


def test_authenticated_history_endpoints():
    # Login to get token
    login_resp = client.post("/api/auth/login", data={"username": "admin", "password": "admin123"})
    token = login_resp.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # Fetch paginated DB history
    hist_resp = client.get("/api/history?page=1&page_size=10", headers=headers)
    assert hist_resp.status_code == 200
    hist_data = hist_resp.json()
    assert "total" in hist_data
    assert "results" in hist_data
    assert "summary" in hist_data
    assert "total_records" in hist_data["summary"]
    assert "normal_count" in hist_data["summary"]
    assert "anomaly_count" in hist_data["summary"]
    assert "attack_distribution" in hist_data["summary"]


def test_csv_large_batch_analysis_endpoint():
    test_df = pd.read_csv("data/Test_data.csv").head(100)
    csv_bytes = test_df.to_csv(index=False).encode("utf-8")

    files = {"file": ("test_traffic_100.csv", io.BytesIO(csv_bytes), "text/csv")}
    response = client.post("/api/analyze/file", files=files)
    assert response.status_code == 200
    data = response.json()

    assert "summary" in data
    assert data["summary"]["total_records"] == 100
    assert "processing_time_seconds" in data["summary"]
    assert "parsing_latency_ms" in data["summary"]
    assert "inference_latency_ms" in data["summary"]
    assert "total_processing_time_ms" in data["summary"]
    assert "average_flow_latency_ms" in data["summary"]
    assert data["summary"]["processing_time_seconds"] < 10.0
    assert data["summary"]["average_flow_latency_ms"] > 0.0
    assert "results" in data
    assert len(data["results"]) == 100


def test_empty_or_invalid_csv_analysis_endpoint():
    # Empty CSV
    empty_bytes = b""
    files = {"file": ("empty.csv", io.BytesIO(empty_bytes), "text/csv")}
    response = client.post("/api/analyze/file", files=files)
    assert response.status_code == 400
    assert "detail" in response.json()

    # Invalid extension
    files_bad = {"file": ("test.txt", io.BytesIO(b"some,data\n1,2\n"), "text/plain")}
    response_bad = client.post("/api/analyze/file", files=files_bad)
    assert response_bad.status_code == 400
    assert "Unsupported file extension" in response_bad.json()["detail"]


def test_latency_kpi_response_fields():
    # Test single predict endpoint latency fields
    payload = {
        "duration": 0,
        "protocol_type": "tcp",
        "service": "http",
        "flag": "SF",
        "src_bytes": 215,
        "dst_bytes": 450,
        "count": 1,
        "srv_count": 1,
    }
    pred_resp = client.post("/predict", json=payload)
    assert pred_resp.status_code == 200
    pred_data = pred_resp.json()
    assert "parsing_latency_ms" in pred_data
    assert "inference_latency_ms" in pred_data
    assert "total_processing_time_ms" in pred_data
    assert isinstance(pred_data["parsing_latency_ms"], float)
    assert isinstance(pred_data["inference_latency_ms"], float)
    assert isinstance(pred_data["total_processing_time_ms"], float)
    assert pred_data["total_processing_time_ms"] >= 0.0

    # Test file analysis endpoint latency summary fields for PCAP
    if os.path.exists("netguard_test.pcap"):
        with open("netguard_test.pcap", "rb") as f:
            pcap_bytes = f.read()
        pcap_files = {"file": ("netguard_test.pcap", io.BytesIO(pcap_bytes), "application/vnd.tcpdump.pcap")}
        pcap_resp = client.post("/api/analyze/file", files=pcap_files)
        assert pcap_resp.status_code == 200
        pcap_summary = pcap_resp.json()["summary"]
        assert "parsing_latency_ms" in pcap_summary
        assert "inference_latency_ms" in pcap_summary
        assert "total_processing_time_ms" in pcap_summary
        assert "average_flow_latency_ms" in pcap_summary
        assert pcap_summary["average_flow_latency_ms"] >= 0.0


def test_export_audit_log_csv():
    # 1. Unauthenticated export rejection
    unauth_resp = client.get("/api/history/export?format=csv")
    assert unauth_resp.status_code == 401

    # 2. Login as admin (User 1)
    login_resp = client.post("/api/auth/login", data={"username": "admin", "password": "admin123"})
    assert login_resp.status_code == 200
    token1 = login_resp.json()["access_token"]
    headers1 = {"Authorization": f"Bearer {token1}"}

    # 3. Create a detection log with a formula-injection payload for User 1
    payload1 = {
        "duration": 0,
        "protocol_type": "=SUM(1,2)",  # Formula injection attempt
        "service": "http",
        "flag": "SF",
        "src_bytes": 100,
        "dst_bytes": 200,
        "count": 1,
        "srv_count": 1,
    }
    pred_resp = client.post("/predict", json=payload1, headers=headers1)
    assert pred_resp.status_code == 200

    # 4. Authenticated export (format=csv)
    csv_resp = client.get("/api/history/export?format=csv", headers=headers1)
    assert csv_resp.status_code == 200
    assert "text/csv" in csv_resp.headers["content-type"]
    assert "attachment; filename=" in csv_resp.headers["content-disposition"]

    csv_text = csv_resp.text
    assert "ID,Timestamp,Source IP,Destination IP,Protocol,Classification,Risk Score,Risk Level,Attack Family,Confidence" in csv_text
    # Verify formula injection sanitization: =SUM(1,2) must be prefixed with '
    assert "'=SUM(1,2)" in csv_text

    # 5. Unsupported format rejection
    bad_fmt_resp = client.get("/api/history/export?format=json", headers=headers1)
    assert bad_fmt_resp.status_code == 400
    assert "Only 'csv' format is supported" in bad_fmt_resp.json()["detail"]

    # 6. User Isolation Test: Register & login as User 2
    reg_resp = client.post("/api/auth/register", json={"username": "export_user2", "password": "password123"})
    assert reg_resp.status_code in [201, 400]

    login2_resp = client.post("/api/auth/login", data={"username": "export_user2", "password": "password123"})
    assert login2_resp.status_code == 200
    token2 = login2_resp.json()["access_token"]
    headers2 = {"Authorization": f"Bearer {token2}"}

    # User 2 exports their CSV -> should NOT contain User 1's formula payload '=SUM(1,2)'
    csv2_resp = client.get("/api/history/export?format=csv", headers=headers2)
    assert csv2_resp.status_code == 200
    assert "'=SUM(1,2)" not in csv2_resp.text


