# schemas.py
from pydantic import BaseModel, EmailStr
from typing import Optional, List
from datetime import datetime

# ---------- ALERT SCHEMAS ----------
class AlertCreate(BaseModel):
    alert_type: str
    message: str
    user_email: EmailStr

class AlertRead(BaseModel):
    id: int
    alert_type: str
    message: str
    user_email: str
    created_at: datetime

    class Config:
        orm_mode = True

# ---------- AUDIT LOG SCHEMAS ----------
class AuditLogCreate(BaseModel):
    alert_id: int
    action: str
    details: Optional[str] = None

class AuditLogRead(BaseModel):
    id: int
    alert_id: int
    action: str
    details: Optional[str]
    performed_at: datetime

    class Config:
        orm_mode = True
