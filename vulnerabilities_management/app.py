# main.py
import uvicorn
from fastapi import FastAPI, HTTPException, Path, Body
from typing import List
from sqlalchemy.orm import Session

from models import (
    init_db, SessionLocal,
    VulnerabilityDatabase, VulnerabilityRecord
)
from schemas import (
    VulnerabilityDatabaseCreate, VulnerabilityDatabaseRead,
    VulnerabilityRecordCreate, VulnerabilityRecordRead,
    BulkImportItem
)
from datetime import datetime

app = FastAPI(
    title="Vulnerabilities Management",
    description="Microservice for storing and managing vulnerability data (CVE) from different sources",
    version="1.0.0"
)

# Initialize DB
init_db()

##############################################################################
#           CRUD for VulnerabilityDatabase (tags=["Vulnerability DB"])
##############################################################################
@app.post("/db", tags=["Vulnerability DB"], response_model=VulnerabilityDatabaseRead)
def create_database(db_data: VulnerabilityDatabaseCreate):
    """
    Create a new vulnerability database entry (e.g. 'nvd-portion').
    """
    session: Session = SessionLocal()
    try:
        existing = session.query(VulnerabilityDatabase).filter_by(name=db_data.name).first()
        if existing:
            raise HTTPException(
                status_code=400,
                detail=f"Database with name '{db_data.name}' already exists."
            )
        new_db = VulnerabilityDatabase(
            name=db_data.name,
            description=db_data.description
        )
        session.add(new_db)
        session.commit()
        session.refresh(new_db)
        return new_db
    finally:
        session.close()


@app.get("/db", tags=["Vulnerability DB"], response_model=List[VulnerabilityDatabaseRead])
def list_databases():
    """
    List all vulnerability databases.
    """
    session: Session = SessionLocal()
    try:
        rows = session.query(VulnerabilityDatabase).all()
        return rows
    finally:
        session.close()


@app.get("/db/{db_id}", tags=["Vulnerability DB"], response_model=VulnerabilityDatabaseRead)
def get_database(db_id: int = Path(..., description="Database ID")):
    """
    Get a single vulnerability database entry by its ID.
    """
    session: Session = SessionLocal()
    try:
        row = session.query(VulnerabilityDatabase).get(db_id)
        if not row:
            raise HTTPException(status_code=404, detail="Database not found")
        return row
    finally:
        session.close()


@app.put("/db/{db_id}", tags=["Vulnerability DB"], response_model=VulnerabilityDatabaseRead)
def update_database(db_id: int, db_data: VulnerabilityDatabaseCreate):
    """
    Update an existing vulnerability database entry.
    """
    session: Session = SessionLocal()
    try:
        row = session.query(VulnerabilityDatabase).get(db_id)
        if not row:
            raise HTTPException(status_code=404, detail="Database not found")

        row.name = db_data.name
        row.description = db_data.description
        session.commit()
        session.refresh(row)
        return row
    finally:
        session.close()


@app.delete("/db/{db_id}", tags=["Vulnerability DB"])
def delete_database(db_id: int):
    """
    Delete a vulnerability database entry.
    """
    session: Session = SessionLocal()
    try:
        row = session.query(VulnerabilityDatabase).get(db_id)
        if not row:
            raise HTTPException(status_code=404, detail="Database not found")
        session.delete(row)
        session.commit()
        return {"message": f"Database ID {db_id} deleted."}
    finally:
        session.close()


##############################################################################
#      CRUD for VulnerabilityRecord (tags=["Vulnerabilities"])
##############################################################################
@app.post("/vuln", tags=["Vulnerabilities"], response_model=VulnerabilityRecordRead)
def create_vulnerability_record(
    db_id: int,
    vuln_data: VulnerabilityRecordCreate
):
    """
    Create a new vulnerability record in a specific DB (db_id).
    Avoid duplicates (cve_id + package_name).
    """
    session: Session = SessionLocal()
    try:
        db_item = session.query(VulnerabilityDatabase).get(db_id)
        if not db_item:
            raise HTTPException(status_code=404, detail="Database not found")

        # Check duplicates
        existing = session.query(VulnerabilityRecord).filter_by(
            database_id=db_id,
            cve_id=vuln_data.cve_id,
            package_name=vuln_data.package_name
        ).first()
        if existing:
            raise HTTPException(
                status_code=400,
                detail="Duplicate record: same DB, CVE, and package"
            )

        new_vuln = VulnerabilityRecord(
            database_id=db_id,
            cve_id=vuln_data.cve_id,
            package_name=vuln_data.package_name,
            affected_version=vuln_data.affected_version,
            severity=vuln_data.severity,
            description=vuln_data.description,
            source_url=vuln_data.source_url
        )
        session.add(new_vuln)
        session.commit()
        session.refresh(new_vuln)
        return new_vuln
    finally:
        session.close()


@app.get("/vuln", tags=["Vulnerabilities"], response_model=List[VulnerabilityRecordRead])
def list_vulnerabilities(db_id: int):
    """
    List all vulnerabilities for a given database (db_id).
    """
    session: Session = SessionLocal()
    try:
        rows = session.query(VulnerabilityRecord).filter(
            VulnerabilityRecord.database_id == str(db_id)
        ).all()
        return rows
    finally:
        session.close()


@app.get("/vuln/{vuln_id}", tags=["Vulnerabilities"], response_model=VulnerabilityRecordRead)
def get_vulnerability_record(vuln_id: int):
    """
    Get a single vulnerability record by its ID.
    """
    session: Session = SessionLocal()
    try:
        row = session.query(VulnerabilityRecord).get(vuln_id)
        if not row:
            raise HTTPException(status_code=404, detail="Vulnerability not found")
        return row
    finally:
        session.close()


@app.put("/vuln/{vuln_id}", tags=["Vulnerabilities"], response_model=VulnerabilityRecordRead)
def update_vulnerability_record(vuln_id: int, vuln_data: VulnerabilityRecordCreate):
    """
    Update a vulnerability record by ID.
    """
    session: Session = SessionLocal()
    try:
        row = session.query(VulnerabilityRecord).get(vuln_id)
        if not row:
            raise HTTPException(status_code=404, detail="Vulnerability not found")

        row.cve_id = vuln_data.cve_id
        row.package_name = vuln_data.package_name
        row.affected_version = vuln_data.affected_version
        row.severity = vuln_data.severity
        row.description = vuln_data.description
        row.source_url = vuln_data.source_url
        session.commit()
        session.refresh(row)
        return row
    finally:
        session.close()


@app.delete("/vuln/{vuln_id}", tags=["Vulnerabilities"])
def delete_vulnerability_record(vuln_id: int):
    """
    Delete a vulnerability record by ID.
    """
    session: Session = SessionLocal()
    try:
        row = session.query(VulnerabilityRecord).get(vuln_id)
        if not row:
            raise HTTPException(status_code=404, detail="Vulnerability not found")
        session.delete(row)
        session.commit()
        return {"message": f"Vulnerability ID {vuln_id} deleted."}
    finally:
        session.close()


##############################################################################
#                  Bulk import (tags=["Vulnerabilities"])
##############################################################################
@app.post("/vuln/bulk-import", tags=["Vulnerabilities"])
def bulk_import_vulnerabilities(db_name: str, items: List[BulkImportItem]):
    """
    Bulk import multiple vulnerabilities into the named DB (e.g. name='nvd-portion').
    - If DB doesn't exist, create it.
    - Skip duplicates (cve_id + package_name) or update them as needed.
    """
    session: Session = SessionLocal()
    created_count = 0
    updated_count = 0
    try:
        # 1) Find or create DB by name
        db_item = session.query(VulnerabilityDatabase).filter_by(name=db_name).first()
        if not db_item:
            db_item = VulnerabilityDatabase(
                name=db_name,
                description="Auto-created from bulk import"
            )
            session.add(db_item)
            session.commit()
            session.refresh(db_item)

        for i in items:
            existing = session.query(VulnerabilityRecord).filter_by(
                database_id=db_item.id,
                cve_id=i.cve_id,
                package_name=i.package_name
            ).first()
            if existing:
                # Update fields
                existing.affected_version = i.affected_version
                existing.severity = i.severity
                existing.description = i.description
                existing.source_url = i.source_url
                updated_count += 1
            else:
                new_vuln = VulnerabilityRecord(
                    database_id=db_item.id,
                    cve_id=i.cve_id,
                    package_name=i.package_name,
                    affected_version=i.affected_version,
                    severity=i.severity,
                    description=i.description,
                    source_url=i.source_url
                )
                session.add(new_vuln)
                created_count += 1

        session.commit()
        return {
            "message": "Bulk import completed.",
            "db_id": db_item.id,
            "database_name": db_item.name,
            "created": created_count,
            "updated": updated_count
        }
    except Exception as e:
        session.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        session.close()


##############################################################################
#                  Run if main
##############################################################################
if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=7000)
