import subprocess
import uvicorn
from fastapi import FastAPI, HTTPException, Depends, status
from pydantic import BaseModel
from typing import List, Dict, Any, Optional
import requests  # We'll make HTTP calls to the vulnerabilities microservice
from sqlalchemy import Column, Integer, String, Text, Enum, create_engine
from sqlalchemy.orm import sessionmaker, declarative_base, Session
import enum

app = FastAPI(
    title="Container Vulnerability Scanner",
    description="Microservice that scans containers and queries VulnerabilitiesManagement for known CVEs",
    version="1.0.3",
    root_path="/api01/scan-service",
    swagger_ui_parameters={"openapiUrl": "/api01/scan-service/openapi.json"}
)

##############################################################################
# 1. Database Setup with SQLAlchemy
##############################################################################

DATABASE_URL = "sqlite:///./scan_service.db"  # Using SQLite for simplicity

engine = create_engine(
    DATABASE_URL, connect_args={"check_same_thread": False}
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


# Dependency to get DB session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


##############################################################################
# 2. Enum Definitions
##############################################################################

class ScanStatus(str, enum.Enum):
    pending = "pending"
    in_progress = "in_progress"
    completed = "completed"
    failed = "failed"


class SeverityLevel(str, enum.Enum):
    low = "LOW"
    medium = "MEDIUM"
    high = "HIGH"
    critical = "CRITICAL"


##############################################################################
# 3. ORM Models
##############################################################################

class ScanTask(Base):
    __tablename__ = "scantasks"

    id = Column(Integer, primary_key=True, index=True)
    container_id = Column(String, unique=True, index=True, nullable=False)
    db_id = Column(Integer, nullable=False, default=1)
    status = Column(Enum(ScanStatus), default=ScanStatus.pending, nullable=False)
    vulnerabilities = Column(Text, nullable=True)  # JSON serialized list
    user_email = Column(String, nullable=False)


class AssessmentRule(Base):
    __tablename__ = "assessmentrules"

    id = Column(Integer, primary_key=True, index=True)
    package_name = Column(String, nullable=False)
    affected_version = Column(String, nullable=False)
    severity = Column(Enum(SeverityLevel), nullable=False)
    description = Column(Text, nullable=True)
    source_url = Column(String, nullable=True)


# Create all tables
Base.metadata.create_all(bind=engine)


##############################################################################
# 4. Pydantic Models
##############################################################################

# Existing Models
class ScanRequest(BaseModel):
    container_id: str
    db_id: Optional[int] = 1
    """
    The ID of the vulnerability database in the vulnerabilities microservice 
    you want to scan against. Defaults to 1 if not provided.
    """
    user_email: str


class VulnerabilityInfo(BaseModel):
    package: str
    version: str
    cve: str
    description: Optional[str] = None
    source_url: Optional[str] = None
    severity: Optional[str] = "UNKNOWN"


class ScanResponse(BaseModel):
    container_id: str
    vulnerabilities: List[VulnerabilityInfo]


# New Models for ScanTask
class ScanTaskCreate(BaseModel):
    container_id: str
    db_id: Optional[int] = 1
    user_email: str


class ScanTaskUpdate(BaseModel):
    container_id: Optional[str] = None
    db_id: Optional[int] = None
    status: Optional[ScanStatus] = None
    vulnerabilities: Optional[str] = None
    user_email: Optional[str] = None


class ScanTaskRead(BaseModel):
    id: int
    container_id: str
    db_id: int
    status: ScanStatus
    vulnerabilities: Optional[str] = None
    user_email: str

    class Config:
        orm_mode = True


# New Models for AssessmentRule
class AssessmentRuleCreate(BaseModel):
    package_name: str
    affected_version: str
    severity: SeverityLevel
    description: Optional[str] = None
    source_url: Optional[str] = None


class AssessmentRuleUpdate(BaseModel):
    package_name: Optional[str] = None
    affected_version: Optional[str] = None
    severity: Optional[SeverityLevel] = None
    description: Optional[str] = None
    source_url: Optional[str] = None


class AssessmentRuleRead(BaseModel):
    id: int
    package_name: str
    affected_version: str
    severity: SeverityLevel
    description: Optional[str] = None
    source_url: Optional[str] = None

    class Config:
        orm_mode = True


##############################################################################
# 5. CRUD Endpoints for ScanTask
##############################################################################

@app.post("/scantasks/", response_model=ScanTaskRead, status_code=status.HTTP_201_CREATED, tags=["ScanTasks"])
def create_scantask(task: ScanTaskCreate, db: Session = Depends(get_db)):
    db_task = db.query(ScanTask).filter(ScanTask.container_id == task.container_id).first()
    if db_task:
        raise HTTPException(status_code=400, detail="ScanTask with this container_id already exists.")
    new_task = ScanTask(
        container_id=task.container_id,
        db_id=task.db_id,
        status=ScanStatus.pending,
        user_email=task.user_email
    )
    db.add(new_task)
    db.commit()
    db.refresh(new_task)
    return new_task


@app.get("/scantasks/", response_model=List[ScanTaskRead], tags=["ScanTasks"])
def read_scantasks(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
    tasks = db.query(ScanTask).offset(skip).limit(limit).all()
    return tasks


@app.get("/scantasks/{task_id}/", response_model=ScanTaskRead, tags=["ScanTasks"])
def read_scantask(task_id: int, db: Session = Depends(get_db)):
    task = db.query(ScanTask).filter(ScanTask.id == task_id).first()
    if not task:
        raise HTTPException(status_code=404, detail="ScanTask not found.")
    return task


@app.put("/scantasks/{task_id}/", response_model=ScanTaskRead, tags=["ScanTasks"])
def update_scantask(task_id: int, task_update: ScanTaskUpdate, db: Session = Depends(get_db)):
    task = db.query(ScanTask).filter(ScanTask.id == task_id).first()
    if not task:
        raise HTTPException(status_code=404, detail="ScanTask not found.")
    for var, value in vars(task_update).items():
        if value is not None:
            setattr(task, var, value)
    db.commit()
    db.refresh(task)
    return task


@app.delete("/scantasks/{task_id}/", status_code=status.HTTP_204_NO_CONTENT, tags=["ScanTasks"])
def delete_scantask(task_id: int, db: Session = Depends(get_db)):
    task = db.query(ScanTask).filter(ScanTask.id == task_id).first()
    if not task:
        raise HTTPException(status_code=404, detail="ScanTask not found.")
    db.delete(task)
    db.commit()
    return


##############################################################################
# 6. CRUD Endpoints for AssessmentRule
##############################################################################

@app.post("/assessmentrules/", response_model=AssessmentRuleRead, status_code=status.HTTP_201_CREATED,
          tags=["AssessmentRules"])
def create_assessmentrule(rule: AssessmentRuleCreate, db: Session = Depends(get_db)):
    new_rule = AssessmentRule(
        package_name=rule.package_name,
        affected_version=rule.affected_version,
        severity=rule.severity,
        description=rule.description,
        source_url=rule.source_url
    )
    db.add(new_rule)
    db.commit()
    db.refresh(new_rule)
    return new_rule


@app.get("/assessmentrules/", response_model=List[AssessmentRuleRead], tags=["AssessmentRules"])
def read_assessmentrules(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
    rules = db.query(AssessmentRule).offset(skip).limit(limit).all()
    return rules


@app.get("/assessmentrules/{rule_id}/", response_model=AssessmentRuleRead, tags=["AssessmentRules"])
def read_assessmentrule(rule_id: int, db: Session = Depends(get_db)):
    rule = db.query(AssessmentRule).filter(AssessmentRule.id == rule_id).first()
    if not rule:
        raise HTTPException(status_code=404, detail="AssessmentRule not found.")
    return rule


@app.put("/assessmentrules/{rule_id}/", response_model=AssessmentRuleRead, tags=["AssessmentRules"])
def update_assessmentrule(rule_id: int, rule_update: AssessmentRuleUpdate, db: Session = Depends(get_db)):
    rule = db.query(AssessmentRule).filter(AssessmentRule.id == rule_id).first()
    if not rule:
        raise HTTPException(status_code=404, detail="AssessmentRule not found.")
    for var, value in vars(rule_update).items():
        if value is not None:
            setattr(rule, var, value)
    db.commit()
    db.refresh(rule)
    return rule


@app.delete("/assessmentrules/{rule_id}/", status_code=status.HTTP_204_NO_CONTENT, tags=["AssessmentRules"])
def delete_assessmentrule(rule_id: int, db: Session = Depends(get_db)):
    rule = db.query(AssessmentRule).filter(AssessmentRule.id == rule_id).first()
    if not rule:
        raise HTTPException(status_code=404, detail="AssessmentRule not found.")
    db.delete(rule)
    db.commit()
    return


##############################################################################
# 7. Existing Scanning Logic
##############################################################################
def parse_dpkg_output(output: str) -> List[Dict[str, str]]:
    """
    Parse 'dpkg -l' output lines like: "ii  bash   5.1-2ubuntu3  ..."
    Return list of dicts: [ {"name":"bash", "version":"5.1-2ubuntu3"}, ... ]
    """
    packages = []
    for line in output.split("\n"):
        parts = line.split()
        if len(parts) < 3:
            continue
        # Typically: "ii", package_name, package_version, ...
        pkg_name = parts[1]
        pkg_version = parts[2]
        packages.append({"name": pkg_name, "version": pkg_version})
    return packages


def parse_rpm_output(output: str) -> List[Dict[str, str]]:
    """
    Parse 'rpm -qa --qf "%{NAME} %{VERSION}\n"' lines like: "bash 5.1"
    Return list of dicts: [ {"name":"bash", "version":"5.1"}, ... ]
    """
    packages = []
    for line in output.split("\n"):
        parts = line.strip().split()
        if len(parts) >= 2:
            pkg_name = parts[0]
            pkg_version = parts[1]
            packages.append({"name": pkg_name, "version": pkg_version})
    return packages


def fetch_vulnerabilities_from_db(db_id: int) -> List[Dict[str, Any]]:
    """
    GET /vuln?db_id={db_id} from the vulnerabilities microservice
    (assumed running at http://localhost:7000).

    Returns a list of vulnerability records, each containing:
      {
        "id": 1,
        "database_id": db_id,
        "cve_id": "CVE-2022-XXXX",
        "package_name": "bash",
        "affected_version": "5.1",
        "severity": "HIGH",
        "description": "...",
        "source_url": "...",
        ...
      }
    """
    url = f"http://localhost:7000/vuln?db_id={db_id}"
    try:
        resp = requests.get(url, timeout=5)
        resp.raise_for_status()
        return resp.json()  # list of dict
    except requests.RequestException as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to fetch vulnerabilities from DB {db_id}: {str(e)}"
        )


def scan_container_for_vulns(container_id: str, db_id: int) -> List[VulnerabilityInfo]:
    """
    1) Attempt dpkg -l in container. If that fails, fallback to rpm -qa.
    2) Retrieve vulnerabilities from the VulnMgmt microservice (db_id).
    3) For each installed package, check if it matches any 'package_name' and
       if installed_version contains the 'affected_version' substring.
    4) Return list of found vulnerabilities.
    """
    # 1) Exec dpkg
    cmd_dpkg = f"docker exec {container_id} dpkg -l"
    proc = subprocess.Popen(cmd_dpkg.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = proc.communicate()

    if proc.returncode == 0:
        pkgs = parse_dpkg_output(stdout.decode("utf-8"))
    else:
        # fallback to rpm
        cmd_rpm = f"docker exec {container_id} rpm -qa --qf '%{{NAME}} %{{VERSION}}\\n'"
        proc2 = subprocess.Popen(cmd_rpm, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout2, stderr2 = proc2.communicate()
        if proc2.returncode != 0:
            err = stderr2.decode("utf-8") or stderr.decode("utf-8")
            raise HTTPException(
                status_code=500,
                detail=f"Failed to retrieve packages from container: {err.strip()}"
            )
        pkgs = parse_rpm_output(stdout2.decode("utf-8"))

    # 2) Fetch vulnerabilities from the VulnMgmt service
    vulns_db = fetch_vulnerabilities_from_db(db_id)  # list of dict

    # 3) Match installed packages vs. vulnerability records
    found = []
    for pkg in pkgs:
        p_name = pkg["name"]
        p_version = pkg["version"]

        # For each vulnerability record, check if package_name is in p_name
        # and affected_version is in p_version (like substring check).
        for vuln_rec in vulns_db:
            db_pkg_name = vuln_rec.get("package_name") or ""
            db_ver_substr = vuln_rec.get("affected_version") or ""

            # naive substring match, if p_name contains db_pkg_name
            # and p_version contains db_ver_substr
            if db_pkg_name in p_name and db_ver_substr in p_version:
                found.append(
                    VulnerabilityInfo(
                        package=p_name,
                        version=p_version,
                        cve=vuln_rec["cve_id"],
                        severity=vuln_rec.get("severity", "UNKNOWN"),
                        description=vuln_rec.get("description"),
                        source_url=vuln_rec.get("source_url")
                    )
                )

    # optionally deduplicate
    unique_found = []
    for f in found:
        if f not in unique_found:
            unique_found.append(f)
    return unique_found


##############################################################################
# 8. Alerting Functionality
##############################################################################

def send_alert(alert_type: str, message: str, user_email: str):
    """
    Calls the Alerting microservice's /alert/send endpoint
    to create an alert and send an email.
    """
    url = "http://localhost:9000/alert/send"  # Adjust if different host/port
    payload = {
        "alert_type": alert_type,
        "message": message,
        "user_email": user_email
    }
    try:
        resp = requests.post(url, json=payload, timeout=5)
        resp.raise_for_status()
        return resp.json()  # The AlertRead object from the alerting service
    except requests.RequestException as e:
        print(f"Failed to send alert: {e}")
        # You might decide to raise an HTTPException or just log the error
        return None


##############################################################################
# 9. Existing Scan Endpoint
##############################################################################

@app.post("/scan", response_model=ScanResponse, tags=["Scanning"])
def scan_container_endpoint(req: ScanRequest, db: Session = Depends(get_db)):
    """
    Scans the container for known vulnerabilities from the given 'db_id'
    in the Vulnerabilities Management service.
    Also creates a ScanTask entry.
    """
    container_id = req.container_id
    db_id = req.db_id or 1  # default to 1 if not provided
    user_email = req.user_email

    # Create ScanTask
    scantask = ScanTask(
        container_id=container_id,
        db_id=db_id,
        status=ScanStatus.in_progress,
        user_email=user_email
    )
    db.add(scantask)
    db.commit()
    db.refresh(scantask)

    try:
        results = scan_container_for_vulns(container_id, db_id)
        scantask.status = ScanStatus.completed
        scantask.vulnerabilities = ", ".join([v.cve for v in results])  # Simplified storage
        db.commit()
    except HTTPException as e:
        scantask.status = ScanStatus.failed
        scantask.vulnerabilities = e.detail
        db.commit()
        raise e

    if results:
        # Build a message summarizing the vulnerabilities
        count = len(results)
        lines = [f"- {v.cve} in package {v.package} (version: {v.version})" for v in results]
        summary = "\n".join(lines)

        msg_body = (
            f"Hello,\n\n"
            f"Scan results for container '{container_id}' found {count} vulnerabilities:\n"
            f"{summary}\n\n"
            f"Regards,\nScanning Service"
        )

        send_alert(
            alert_type="ScanResult",
            message=msg_body,
            user_email=user_email
        )

    return ScanResponse(container_id=container_id, vulnerabilities=results)


##############################################################################
# 10. Additional Endpoints
##############################################################################

@app.get("/health", tags=["Scanning"])
def health_check():
    return {"status": "ok"}


##############################################################################
# 11. Run if main
##############################################################################
if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
