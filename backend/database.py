"""
Database configuration and SQLAlchemy session setup for NetGuard AI.
Uses SQLite for persistent storage of users and detection logs.
"""

import os
from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./netguard.db")

# SQLite requires check_same_thread=False for multithreaded FastAPI access
connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}

engine = create_engine(DATABASE_URL, connect_args=connect_args)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


def init_db():
    """Initializes database tables."""
    from backend import models  # noqa: F401
    Base.metadata.create_all(bind=engine)
