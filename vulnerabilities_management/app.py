import uvicorn
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import List, Optional
from models import init_db, SessionLocal, VulnerabilityRecord

app = FastAPI(
    title="Vulnerabilities Management",
    description="Microservice for storing and managing vulnerability data (CVE).",
    version="1.0.0"
)

init_db()


class VulnerabilityCreate(BaseModel):
    cve_id: str
    description: Optional[str] = None
    severity: Optional[str] = "UNKNOWN"
    source_url: Optional[str] = None
    package_name: Optional[str] = None
    affected_version: Optional[str] = None


@app.post("/vuln/bulk-import", tags=["Vulnerability Management"])
def bulk_import_vulnerabilities(vulns: List[VulnerabilityCreate]):
    """
    Import multiple vulnerabilities in one request.
    If (cve_id + package_name) already exists, skip or update to avoid duplicates.
    """
    db = SessionLocal()
    imported_count = 0
    updated_count = 0
    try:
        for v in vulns:
            existing = db.query(VulnerabilityRecord).filter(
                VulnerabilityRecord.cve_id == v.cve_id,
                VulnerabilityRecord.package_name == v.package_name
            ).first()
            if existing:
                # Optionally update the record if you like:
                existing.description = v.description
                existing.severity = v.severity
                existing.source_url = v.source_url
                existing.affected_version = v.affected_version
                updated_count += 1
            else:
                new_record = VulnerabilityRecord(
                    cve_id=v.cve_id,
                    description=v.description,
                    severity=v.severity,
                    source_url=v.source_url,
                    package_name=v.package_name,
                    affected_version=v.affected_version
                )
                db.add(new_record)
                imported_count += 1
        db.commit()
        return {
            "message": "Bulk import completed",
            "imported": imported_count,
            "updated": updated_count
        }
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        db.close()


@app.get("/vuln/{cve_id}", response_model=List[VulnerabilityCreate], tags=["Vulnerability Management"])
def get_vuln_by_cve(cve_id: str):
    """
    Retrieve one or more vulnerabilities for the given cve_id.
    Possibly multiple packages under the same cve_id if your design allows that.
    """
    db = SessionLocal()
    try:
        rows = db.query(VulnerabilityRecord).filter(VulnerabilityRecord.cve_id == cve_id).all()
        if not rows:
            raise HTTPException(status_code=404, detail="CVE not found")
        return [
            VulnerabilityCreate(
                cve_id=r.cve_id,
                description=r.description,
                severity=r.severity,
                source_url=r.source_url,
                package_name=r.package_name,
                affected_version=r.affected_version,
            ) for r in rows
        ]
    finally:
        db.close()


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=7000)
