from pydantic import BaseModel, EmailStr
from typing import List, Dict, Any, Optional

class ScanRequest(BaseModel):
    container_id: str
    db_id: Optional[int] = 1  # The ID of the vulnerability DB
    user_email: EmailStr      # <--- NEW: who should get the alert?
