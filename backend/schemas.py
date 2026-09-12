"""
Pydantic schemas for request validation, authentication, and response payloads.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


# Auth Schemas
class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"


class TokenData(BaseModel):
    username: Optional[str] = None


class UserCreate(BaseModel):
    username: str
    password: str
    role: Optional[str] = "admin"


class UserResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    username: str
    role: str
    created_at: datetime


# Traffic Input Schema (41 Features)
class TrafficFeatureInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    duration: float = Field(0.0, description="Duration of connection in seconds")
    protocol_type: str = Field("tcp", description="Protocol type (tcp, udp, icmp)")
    service: str = Field("http", description="Network service (http, private, smtp, etc.)")
    flag: str = Field("SF", description="Status flag (SF, S0, REJ, etc.)")
    src_bytes: float = Field(0.0, description="Source bytes")
    dst_bytes: float = Field(0.0, description="Destination bytes")
    land: int = Field(0, description="Land feature (0 or 1)")
    wrong_fragment: int = Field(0, description="Wrong fragments count")
    urgent: int = Field(0, description="Urgent packets count")
    hot: int = Field(0, description="Hot indicators count")
    num_failed_logins: int = Field(0, description="Failed login attempts count")
    logged_in: int = Field(0, description="Logged in indicator (0 or 1)")
    num_compromised: int = Field(0, description="Compromised conditions count")
    root_shell: int = Field(0, description="Root shell obtained (0 or 1)")
    su_attempted: int = Field(0, description="SU attempted (0 or 1)")
    num_root: int = Field(0, description="Root accesses count")
    num_file_creations: int = Field(0, description="File creations count")
    num_shells: int = Field(0, description="Shell prompts count")
    num_access_files: int = Field(0, description="Access files count")
    num_outbound_cmds: int = Field(0, description="Outbound commands count")
    is_host_login: int = Field(0, description="Host login (0 or 1)")
    is_guest_login: int = Field(0, description="Guest login (0 or 1)")
    count: int = Field(0, description="Connections to same host count")
    srv_count: int = Field(0, description="Connections to same service count")
    serror_rate: float = Field(0.0, description="SYN error rate")
    srv_serror_rate: float = Field(0.0, description="Server SYN error rate")
    rerror_rate: float = Field(0.0, description="REJ error rate")
    srv_rerror_rate: float = Field(0.0, description="Server REJ error rate")
    same_srv_rate: float = Field(0.0, description="Same service rate")
    diff_srv_rate: float = Field(0.0, description="Different service rate")
    srv_diff_host_rate: float = Field(0.0, description="Server different host rate")
    dst_host_count: int = Field(0, description="Destination host count")
    dst_host_srv_count: int = Field(0, description="Destination host service count")
    dst_host_same_srv_rate: float = Field(0.0, description="Destination host same service rate")
    dst_host_diff_srv_rate: float = Field(0.0, description="Destination host diff service rate")
    dst_host_same_src_port_rate: float = Field(0.0, description="Destination host same src port rate")
    dst_host_srv_diff_host_rate: float = Field(0.0, description="Destination host srv diff host rate")
    dst_host_serror_rate: float = Field(0.0, description="Destination host SYN error rate")
    dst_host_srv_serror_rate: float = Field(0.0, description="Destination host srv SYN error rate")
    dst_host_rerror_rate: float = Field(0.0, description="Destination host REJ error rate")
    dst_host_srv_rerror_rate: float = Field(0.0, description="Destination host srv REJ error rate")


# Analysis Output & Explanation Schemas
class FeatureImpact(BaseModel):
    feature: str
    value: Any
    impact: float
    direction: str  # "increases_anomaly_risk" or "decreases_anomaly_risk"


class AnalysisResult(BaseModel):
    prediction: str            # "normal" or "anomaly"
    status: str                # "NORMAL" or "ALERT"
    probability: float         # 0.0 to 1.0
    risk_score: float          # 0.0 to 100.0
    risk_level: str            # "Normal", "Low", "Medium", "High", "Critical"
    attack_family: Optional[str] = None  # "DoS", "Probe", "R2L", "U2R", or None
    stage2_confidence: Optional[float] = None
    top_features: Optional[List[FeatureImpact]] = None
    mitigation: Optional[List[str]] = None
    timestamp: str
    source_ip: str = "127.0.0.1"
    destination_ip: str = "127.0.0.1"
    protocol: str = "tcp"
    parsing_latency_ms: Optional[float] = None
    inference_latency_ms: Optional[float] = None
    total_processing_time_ms: Optional[float] = None


# Detection History Schemas
class DetectionLogResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    timestamp: datetime
    source_ip: str
    destination_ip: str
    protocol: str
    classification: str
    attack_family: Optional[str] = None
    risk_score: float
    confidence: float
    top_features: Optional[List[Dict[str, Any]]] = None
    raw_payload: Optional[Dict[str, Any]] = None


class HistorySummary(BaseModel):
    total_records: int
    normal_count: int
    anomaly_count: int
    attack_distribution: Dict[str, int]
    average_risk_score: float = 0.0
    max_risk_score: float = 0.0
    parsing_latency_ms: Optional[float] = None
    inference_latency_ms: Optional[float] = None
    total_processing_time_ms: Optional[float] = None
    average_flow_latency_ms: Optional[float] = None


class PaginatedHistoryResponse(BaseModel):
    total: int
    page: int
    page_size: int
    summary: Optional[HistorySummary] = None
    results: List[DetectionLogResponse]
