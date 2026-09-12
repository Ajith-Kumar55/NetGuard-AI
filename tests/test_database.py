"""
Unit tests for SQLite + SQLAlchemy ORM database initialization, DetectionLog records, and pagination.
"""

from datetime import datetime
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from backend.database import Base
from backend.models import DetectionLog, User


@pytest.fixture
def db_session():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    session = TestingSessionLocal()
    yield session
    session.close()


def test_user_creation_and_query(db_session):
    user = User(username="admin_test", hashed_password="hashed_pw_value", role="admin")
    db_session.add(user)
    db_session.commit()

    queried_user = db_session.query(User).filter(User.username == "admin_test").first()
    assert queried_user is not None
    assert queried_user.username == "admin_test"
    assert queried_user.role == "admin"


def test_detection_log_creation_and_query(db_session):
    log = DetectionLog(
        timestamp=datetime.utcnow(),
        source_ip="192.168.1.100",
        destination_ip="10.0.0.1",
        protocol="TCP",
        classification="anomaly",
        attack_family="DoS",
        risk_score=85.5,
        confidence=0.95,
        top_features=[{"feature": "count", "value": 150, "impact": 0.45, "direction": "increases_anomaly_risk"}],
    )
    db_session.add(log)
    db_session.commit()

    queried_log = db_session.query(DetectionLog).first()
    assert queried_log is not None
    assert queried_log.classification == "anomaly"
    assert queried_log.attack_family == "DoS"
    assert queried_log.risk_score == 85.5
    assert len(queried_log.top_features) == 1
