import docker
import uvicorn
from fastapi import FastAPI, BackgroundTasks, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session
from datetime import datetime

from models import (
    init_db,
    SessionLocal,
    ScanningService,
    ScanStatus,
    ScanTask,
    Severity,
    ScanResult,
    VulnerabilityRecord
)

app = FastAPI(title="Container Scanning Service (with container_id support)")

init_db()
docker_client = docker.from_env()

# -----------------------------------
# Naive version check helper (same)
# -----------------------------------
def is_vulnerable(current_version: str, patched_version: str) -> bool:
    """
    If current_version < patched_version => return True (very naive).
    """
    try:
        def ver_to_list(ver):
            parts = []
            ver = ver.replace('-', '.')
            for p in ver.split('.'):
                num = ''
                for c in p:
                    if c.isdigit():
                        num += c
                    else:
                        break
                if num:
                    parts.append(int(num))
            return parts

        cur_list = ver_to_list(current_version)
        patch_list = ver_to_list(patched_version)
        for c, p in zip(cur_list, patch_list):
            if c < p:
                return True
            elif c > p:
                return False
        return len(cur_list) < len(patch_list)
    except:
        return current_version < patched_version

# -----------------------------------
# Extract packages FROM A RUNNING CONTAINER
# -----------------------------------
def extract_packages_from_container(container_id: str):
    """
    Given a running container ID, exec 'dpkg -l' or 'rpm -qa' inside that container.
    Return list of (package_name, package_version).
    """
    packages = []
    try:
        container = docker_client.containers.get(container_id)
        # Exec 'dpkg -l'
        exec_res = container.exec_run("dpkg -l")
        if exec_res.exit_code != 0:
            # try rpm-based approach
            exec_res = container.exec_run("rpm -qa --qf '%{NAME} %{VERSION}\n'")
        logs = exec_res.output.decode(errors='replace')
        for line in logs.splitlines():
            parts = line.strip().split()
            if len(parts) >= 2:
                pkg = parts[-2]   # heuristics, e.g. 'bash'
                ver = parts[-1]   # e.g. '5.1-2ubuntu3'
                packages.append((pkg, ver))
    except Exception as e:
        print(f"extract_packages_from_container error: {e}")
    return packages

# -----------------------------------
# Extract packages FROM AN IMAGE (old logic)
# -----------------------------------
def extract_packages_from_image(image_name: str):
    packages = []
    try:
        docker_client.images.pull(image_name)
        # dpkg -l
        container = docker_client.containers.create(image_name, command="dpkg -l")
        container.start()
        exit_code = container.wait()
        logs = container.logs().decode()
        container.remove()

        if exit_code["StatusCode"] != 0:
            # rpm
            container = docker_client.containers.create(
                image_name, command="rpm -qa --qf '%{NAME} %{VERSION}\n'"
            )
            container.start()
            exit_code = container.wait()
            logs = container.logs().decode()
            container.remove()

        for line in logs.splitlines():
            parts = line.strip().split()
            if len(parts) >= 2:
                pkg = parts[-2]
                ver = parts[-1]
                packages.append((pkg, ver))
    except Exception as e:
        print(f"extract_packages_from_image error: {e}")
    return packages

# -----------------------------------
# Pydantic Models
# -----------------------------------
class ScanRequest(BaseModel):
    image_name: str

class ContainerScanRequest(BaseModel):
    container_id: str  # The ID or name of a running container

class ScanResponse(BaseModel):
    scan_task_id: int
    message: str

class ScanStatusResponse(BaseModel):
    scan_task_id: int
    status_name: str
    vulnerabilities: list | None = None
    full_report: str | None = None

# -----------------------------------
# Background tasks
# -----------------------------------
def perform_image_scan(task_id: int, image_name: str):
    """
    The old logic that pulls an image and runs dpkg -l or rpm -qa.
    """
    db: Session = SessionLocal()
    try:
        task = db.query(ScanTask).filter(ScanTask.id == task_id).first()
        if not task:
            print("No ScanTask found for image scan.")
            return

        running_status = db.query(ScanStatus).filter_by(status_name="running").first()
        if not running_status:
            running_status = ScanStatus(status_name="running", description="Scan in progress")
            db.add(running_status)
            db.commit()
            db.refresh(running_status)
        task.status_id = running_status.id
        db.commit()

        # 1) Extract packages
        package_list = extract_packages_from_image(image_name)

        # 2) Check vulnerabilities
        found_vulns = []
        vuln_recs = db.query(VulnerabilityRecord).all()
        for (pkg_name, pkg_ver) in package_list:
            for v in vuln_recs:
                if v.package_name == pkg_name:
                    if is_vulnerable(pkg_ver, v.patched_version):
                        found_vulns.append({
                            "cve_id": v.vulnerability_id,
                            "package": pkg_name,
                            "installed_version": pkg_ver,
                            "patched_version": v.patched_version,
                            "severity_level": v.severity_level,
                            "description": v.description
                        })

        # 3) Overall severity
        highest = 1
        for fv in found_vulns:
            if fv["severity_level"] > highest:
                highest = fv["severity_level"]

        severity_obj = db.query(Severity).filter(Severity.level_value == highest).first()
        if not severity_obj:
            name_map = {1:"low",2:"medium",3:"high",4:"critical"}
            severity_obj = Severity(level_name=name_map.get(highest,"low"), level_value=highest)
            db.add(severity_obj)
            db.commit()
            db.refresh(severity_obj)

        # 4) Insert ScanResult
        sr = ScanResult(
            scan_task_id=task.id,
            vulnerabilities_found=len(found_vulns),
            severity_level_id=severity_obj.id,
            result_summary=found_vulns,
            full_report=f"Found {len(found_vulns)} vulnerabilities in {image_name} at {datetime.utcnow()}"
        )
        db.add(sr)

        # completed
        completed_status = db.query(ScanStatus).filter_by(status_name="completed").first()
        if not completed_status:
            completed_status = ScanStatus(status_name="completed", description="Scan finished")
            db.add(completed_status)
            db.commit()
            db.refresh(completed_status)

        task.status_id = completed_status.id
        db.commit()
        print(f"Image scan {task_id} completed. Found {len(found_vulns)} vulnerabilities.")
    except Exception as e:
        print(f"perform_image_scan error: {e}")
        failed_status = db.query(ScanStatus).filter_by(status_name="failed").first()
        if not failed_status:
            failed_status = ScanStatus(status_name="failed", description="Scan failed")
            db.add(failed_status)
            db.commit()
            db.refresh(failed_status)

        task = db.query(ScanTask).filter(ScanTask.id == task_id).first()
        if task:
            task.status_id = failed_status.id
            db.commit()
    finally:
        db.close()

def perform_container_scan(task_id: int, container_id: str):
    """
    New logic that scans a *running container* by ID.
    """
    db: Session = SessionLocal()
    try:
        task = db.query(ScanTask).filter(ScanTask.id == task_id).first()
        if not task:
            print("No ScanTask found for container scan.")
            return

        running_status = db.query(ScanStatus).filter_by(status_name="running").first()
        if not running_status:
            running_status = ScanStatus(status_name="running", description="Scan in progress")
            db.add(running_status)
            db.commit()
            db.refresh(running_status)

        task.status_id = running_status.id
        db.commit()

        # 1) Extract packages from running container
        package_list = extract_packages_from_container(container_id)

        # 2) Check vulnerabilities
        found_vulns = []
        vuln_recs = db.query(VulnerabilityRecord).all()
        for (pkg_name, pkg_ver) in package_list:
            for v in vuln_recs:
                if v.package_name == pkg_name:
                    if is_vulnerable(pkg_ver, v.patched_version):
                        found_vulns.append({
                            "cve_id": v.vulnerability_id,
                            "package": pkg_name,
                            "installed_version": pkg_ver,
                            "patched_version": v.patched_version,
                            "severity_level": v.severity_level,
                            "description": v.description
                        })

        # 3) Overall severity
        highest = 1
        for fv in found_vulns:
            if fv["severity_level"] > highest:
                highest = fv["severity_level"]

        severity_obj = db.query(Severity).filter(Severity.level_value == highest).first()
        if not severity_obj:
            name_map = {1:"low",2:"medium",3:"high",4:"critical"}
            severity_obj = Severity(level_name=name_map.get(highest,"low"), level_value=highest)
            db.add(severity_obj)
            db.commit()
            db.refresh(severity_obj)

        # 4) Insert ScanResult
        sr = ScanResult(
            scan_task_id=task_id,
            vulnerabilities_found=len(found_vulns),
            severity_level_id=severity_obj.id,
            result_summary=found_vulns,
            full_report=f"Found {len(found_vulns)} vulnerabilities in container {container_id} at {datetime.utcnow()}"
        )
        db.add(sr)

        # completed
        completed_status = db.query(ScanStatus).filter_by(status_name="completed").first()
        if not completed_status:
            completed_status = ScanStatus(status_name="completed", description="Scan finished")
            db.add(completed_status)
            db.commit()
            db.refresh(completed_status)

        task.status_id = completed_status.id
        db.commit()
        print(f"Container scan {task_id} completed. Found {len(found_vulns)} vulnerabilities.")
    except Exception as e:
        print(f"perform_container_scan error: {e}")
        failed_status = db.query(ScanStatus).filter_by(status_name="failed").first()
        if not failed_status:
            failed_status = ScanStatus(status_name="failed", description="Scan failed")
            db.add(failed_status)
            db.commit()
            db.refresh(failed_status)
        task = db.query(ScanTask).filter(ScanTask.id == task_id).first()
        if task:
            task.status_id = failed_status.id
            db.commit()
    finally:
        db.close()


# -----------------------------------
# FastAPI Endpoints
# -----------------------------------

# (1) Old: Scan by Image
@app.post("/api/scan", response_model=ScanResponse)
def create_image_scan(req: ScanRequest, background_tasks: BackgroundTasks):
    """
    Create a new ScanTask for an image-based scan.
    """
    db: Session = SessionLocal()
    try:
        svc = db.query(ScanningService).filter_by(name="DefaultScanner").first()
        if not svc:
            svc = ScanningService(name="DefaultScanner", description="Default scanning service")
            db.add(svc)
            db.commit()
            db.refresh(svc)

        pending_status = db.query(ScanStatus).filter_by(status_name="pending").first()
        if not pending_status:
            pending_status = ScanStatus(status_name="pending", description="Scan pending")
            db.add(pending_status)
            db.commit()
            db.refresh(pending_status)

        new_task = ScanTask(
            scanning_service_id=svc.id,
            status_id=pending_status.id,
            frequency=req.image_name  # storing image_name here
        )
        db.add(new_task)
        db.commit()
        db.refresh(new_task)

        background_tasks.add_task(perform_image_scan, new_task.id, req.image_name)
        return ScanResponse(scan_task_id=new_task.id, message=f"Image scan initiated for {req.image_name}")
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        db.close()

# (2) New: Scan by Container ID
@app.post("/api/scan/container", response_model=ScanResponse)
def create_container_scan(req: ContainerScanRequest, background_tasks: BackgroundTasks):
    """
    Create a new ScanTask for a container-based scan, referencing a running container by ID.
    """
    db: Session = SessionLocal()
    try:
        svc = db.query(ScanningService).filter_by(name="DefaultScanner").first()
        if not svc:
            svc = ScanningService(name="DefaultScanner", description="Default scanning service")
            db.add(svc)
            db.commit()
            db.refresh(svc)

        pending_status = db.query(ScanStatus).filter_by(status_name="pending").first()
        if not pending_status:
            pending_status = ScanStatus(status_name="pending", description="Scan pending")
            db.add(pending_status)
            db.commit()
            db.refresh(pending_status)

        # Reuse "frequency" just to store container_id (hacky, but minimal changes)
        new_task = ScanTask(
            scanning_service_id=svc.id,
            status_id=pending_status.id,
            frequency=req.container_id  # store the container ID here
        )
        db.add(new_task)
        db.commit()
        db.refresh(new_task)

        background_tasks.add_task(perform_container_scan, new_task.id, req.container_id)
        return ScanResponse(scan_task_id=new_task.id, message=f"Container scan initiated for {req.container_id}")
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        db.close()

# (3) Check any scan result
@app.get("/api/scan/{scan_id}", response_model=ScanStatusResponse)
def get_scan_status(scan_id: int):
    """
    Retrieve the current status of a scan (image-based or container-based) and results if completed.
    """
    db: Session = SessionLocal()
    try:
        task = db.query(ScanTask).filter(ScanTask.id == scan_id).first()
        if not task:
            raise HTTPException(status_code=404, detail="ScanTask not found.")

        status_row = db.query(ScanStatus).filter(ScanStatus.id == task.status_id).first()
        status_name = status_row.status_name if status_row else "unknown"

        result = db.query(ScanResult).filter(ScanResult.scan_task_id == task.id).first()
        if result:
            return ScanStatusResponse(
                scan_task_id=scan_id,
                status_name=status_name,
                vulnerabilities=result.result_summary,
                full_report=result.full_report
            )
        else:
            return ScanStatusResponse(
                scan_task_id=scan_id,
                status_name=status_name,
                vulnerabilities=None,
                full_report=None
            )
    finally:
        db.close()

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)