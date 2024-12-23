# models.py
from sqlalchemy import (
    Column, Integer, String, Text, DateTime, text, create_engine, ForeignKey
)
from sqlalchemy.orm import declarative_base, sessionmaker, relationship
from datetime import datetime

DATABASE_URL = "sqlite:///./alerting_db.sqlite"

Base = declarative_base()
engine = create_engine(
    DATABASE_URL,
    echo=True,
    connect_args={"check_same_thread": False}
)
SessionLocal = sessionmaker(bind=engine)

class Alert(Base):
    """
    Stores alert info, e.g. sent to some user_email about a specific vulnerability or scan result.
    """
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, autoincrement=True)
    alert_type = Column(String(50), nullable=False)   # e.g. "ScanResult", "CriticalVuln", etc.
    message = Column(Text, nullable=False)
    user_email = Column(String(255), nullable=False)
    created_at = Column(DateTime, server_default=text("CURRENT_TIMESTAMP"))
    # Optionally store a "status" (e.g., "sent", "failed") or other fields

    # Relationship to AuditLog (one-to-many or many-to-one depending on your usage)
    logs = relationship("AuditLog", back_populates="alert_ref")


class AuditLog(Base):
    """
    Audit log records any action performed on an alert
    (e.g. "alert created", "email sent", "alert dismissed", etc.).
    """
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    alert_id = Column(Integer, ForeignKey("alerts.id"), nullable=True)
    action = Column(String(255), nullable=False)
    details = Column(Text, nullable=True)
    performed_at = Column(DateTime, server_default=text("CURRENT_TIMESTAMP"))

    alert_ref = relationship("Alert", back_populates="logs")

def init_db():
    Base.metadata.create_all(bind=engine)

