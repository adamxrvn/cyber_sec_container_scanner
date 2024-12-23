# schemas.py
from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime

# ---------- Database-level Schemas ----------
class VulnerabilityDatabaseCreate(BaseModel):
    name: str
    description: Optional[str] = None

class VulnerabilityDatabaseRead(BaseModel):
    id: int
    name: str
    description: Optional[str]
    created_at: datetime
    updated_at: datetime

    class Config:
        orm_mode = True


# ---------- Record-level Schemas ----------
class VulnerabilityRecordCreate(BaseModel):
    cve_id: str
    package_name: Optional[str] = None
    affected_version: Optional[str] = None
    severity: Optional[str] = "UNKNOWN"
    description: Optional[str] = None
    source_url: Optional[str] = None

class VulnerabilityRecordRead(BaseModel):
    id: int
    database_id: int
    cve_id: str
    package_name: Optional[str]
    affected_version: Optional[str]
    severity: Optional[str]
    description: Optional[str]
    source_url: Optional[str]
    created_at: datetime
    updated_at: datetime

    class Config:
        orm_mode = True

# ---------- Bulk Import ----------
class BulkImportItem(BaseModel):
    cve_id: str
    package_name: Optional[str] = None
    affected_version: Optional[str] = None
    severity: Optional[str] = "UNKNOWN"
    description: Optional[str] = None
    source_url: Optional[str] = None
