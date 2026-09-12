"""
SQLAlchemy ORM models for NetGuard AI persistence.
Defines User authentication table and DetectionLog security audit table.
"""

from datetime import datetime
from sqlalchemy import Column, DateTime, Float, ForeignKey, Integer, JSON, String
from sqlalchemy.orm import relationship
from backend.database import Base


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    role = Column(String, default="admin", nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    detections = relationship("DetectionLog", back_populates="user", cascade="all, delete-orphan")


class DetectionLog(Base):
    __tablename__ = "detection_logs"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True, nullable=False)
    source_ip = Column(String, default="127.0.0.1", nullable=False)
    destination_ip = Column(String, default="127.0.0.1", nullable=False)
    protocol = Column(String, default="tcp", nullable=False)
    classification = Column(String, nullable=False)  # "normal" or "anomaly"
    attack_family = Column(String, nullable=True)    # "DoS", "Probe", "R2L", "U2R", or None
    risk_score = Column(Float, default=0.0, nullable=False)
    confidence = Column(Float, default=0.0, nullable=False)
    top_features = Column(JSON, nullable=True)
    raw_payload = Column(JSON, nullable=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)

    user = relationship("User", back_populates="detections")
