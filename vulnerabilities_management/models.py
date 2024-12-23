# models.py
from sqlalchemy import (
    Column, Integer, String, Text, DateTime, ForeignKey, text,
    create_engine, UniqueConstraint
)
from sqlalchemy.orm import declarative_base, sessionmaker, relationship
from datetime import datetime

# --- DB Config ---
DATABASE_URL = "sqlite:///./vuln_management_db.sqlite"

Base = declarative_base()
engine = create_engine(
    DATABASE_URL,
    echo=True,
    connect_args={"check_same_thread": False}
)
SessionLocal = sessionmaker(bind=engine)

# --- Models ---
class VulnerabilityDatabase(Base):
    """
    Stores different vulnerability data sources, e.g. "nvd-portion".
    """
    __tablename__ = "vulnerability_databases"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(100), nullable=False, unique=True)
    description = Column(Text, nullable=True)
    created_at = Column(DateTime, server_default=text("CURRENT_TIMESTAMP"))

    records = relationship("VulnerabilityRecord", back_populates="database_ref")


class VulnerabilityRecord(Base):
    """
    Actual vulnerabilities referencing a specific DB source.
    Avoid duplicates with a unique constraint (database_id, cve_id, package_name).
    """
    __tablename__ = "vulnerability_records"

    id = Column(Integer, primary_key=True, autoincrement=True)
    database_id = Column(Integer, ForeignKey("vulnerability_databases.id"), nullable=False)
    cve_id = Column(String(100), nullable=False)
    package_name = Column(String(100), nullable=True)
    affected_version = Column(String(100), nullable=True)
    severity = Column(String(20), nullable=True, default="UNKNOWN")
    description = Column(Text, nullable=True)
    source_url = Column(Text, nullable=True)
    created_at = Column(DateTime, server_default=text("CURRENT_TIMESTAMP"))

    # Unique combo
    __table_args__ = (
        UniqueConstraint("database_id", "cve_id", "package_name", name="uq_dbid_cve_package"),
    )

    database_ref = relationship("VulnerabilityDatabase", back_populates="records")


def init_db():
    Base.metadata.create_all(bind=engine)
