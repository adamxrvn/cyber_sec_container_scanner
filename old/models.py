from sqlalchemy import (
    Column, Integer, String, DateTime, Text, ForeignKey, text, create_engine
)
from sqlalchemy.types import JSON
from sqlalchemy.orm import declarative_base, sessionmaker, relationship
from datetime import datetime

Base = declarative_base()

DATABASE_URL = "sqlite:///./scanning_db.sqlite"

engine = create_engine(
    DATABASE_URL,
    echo=True,  # Logs SQL queries to console
    connect_args={"check_same_thread": False}
)
SessionLocal = sessionmaker(bind=engine)

class VulnerabilityRecord(Base):
    """
    We'll store a small set of known vulnerabilities,
    each referencing a package_name and a 'patched_version' threshold.
    """
    __tablename__ = 'vulnerabilities'

    id = Column(Integer, primary_key=True, autoincrement=True)
    vulnerability_id = Column(String(100), nullable=False, unique=True)  # e.g. "CVE-2023-1234"
    package_name = Column(String(100), nullable=False)                   # e.g. "bash", "openssl"
    patched_version = Column(String(50), nullable=False)                 # e.g. "1.1.1k", "5.1-2ubuntu3"
    description = Column(Text)
    severity_level = Column(Integer, nullable=False)  # 1=low..4=critical
    status = Column(String(50), nullable=False, default='active')        # e.g. 'active', 'resolved'
    created_at = Column(DateTime, server_default=text("CURRENT_TIMESTAMP"))

class ScanStatus(Base):
    __tablename__ = 'scanstatus'

    id = Column(Integer, primary_key=True, autoincrement=True)
    status_name = Column(String(50), nullable=False, unique=True)
    description = Column(Text)
    created_at = Column(DateTime, server_default=text("CURRENT_TIMESTAMP"))

class ScanningService(Base):
    __tablename__ = 'scanningservice'

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(100), nullable=False, unique=True)
    description = Column(Text)
    created_at = Column(DateTime, server_default=text("CURRENT_TIMESTAMP"))

class ScanTask(Base):
    __tablename__ = 'scantask'

    id = Column(Integer, primary_key=True, autoincrement=True)
    scanning_service_id = Column(Integer, ForeignKey('scanningservice.id'), nullable=False)
    status_id = Column(Integer, ForeignKey('scanstatus.id'), nullable=False)
    frequency = Column(String(50))  # Reusing to store the image name
    created_at = Column(DateTime, server_default=text("CURRENT_TIMESTAMP"))

class Severity(Base):
    __tablename__ = 'severity'

    id = Column(Integer, primary_key=True, autoincrement=True)
    level_name = Column(String(50), nullable=False, unique=True)  # e.g. 'low', 'medium', etc.
    level_value = Column(Integer, nullable=False)
    created_at = Column(DateTime, server_default=text("CURRENT_TIMESTAMP"))

class ScanResult(Base):
    __tablename__ = 'scanresult'

    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_task_id = Column(Integer, ForeignKey('scantask.id'), nullable=False)
    vulnerabilities_found = Column(Integer, default=0)
    severity_level_id = Column(Integer, ForeignKey('severity.id'), nullable=False)
    result_summary = Column(JSON)
    full_report = Column(Text)
    scanned_at = Column(DateTime, server_default=text("CURRENT_TIMESTAMP"))

def init_db():
    Base.metadata.create_all(bind=engine)


init_db()