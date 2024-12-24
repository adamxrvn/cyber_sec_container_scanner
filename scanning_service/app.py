import subprocess
import uvicorn
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import List, Dict, Any, Optional
import requests  # We'll make HTTP calls to the vulnerabilities microservice

app = FastAPI(
    title="Container Vulnerability Scanner",
    description="Microservice that scans containers and queries VulnerabilitiesManagement for known CVEs",
    version="1.0.2",
    root_path="/api01/scan-service",
    swagger_ui_parameters={"openapiUrl": "/api01/scan-service/openapi.json"}

)


##############################################################################
# 1. Pydantic Models
##############################################################################
class ScanRequest(BaseModel):
    container_id: str
    db_id: Optional[int] = 1
    """
    The ID of the vulnerability database in the vulnerabilities microservice 
    you want to scan against. Defaults to 1 if not provided.
    """


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


##############################################################################
# 2. Helpers to parse dpkg/rpm output
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


##############################################################################
# 3. The scanning logic (no local dict). We'll fetch from VulnMgmt microservice
##############################################################################
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
# 4. FastAPI Endpoints
##############################################################################
@app.get("/health")
def health_check():
    return {"status": "ok"}


import requests

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


@app.post("/scan", response_model=ScanResponse, tags=["Scanning"])
def scan_container_endpoint(req: ScanRequest):
    """
    Scans the container for known vulnerabilities from the given 'db_id'
    in the Vulnerabilities Management service.
    """
    container_id = req.container_id
    db_id = req.db_id or 1  # default to 1 if not provided
    results = scan_container_for_vulns(container_id, db_id)

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
            user_email="azalkhanashvili@edu.hse.ru"
        )

    return ScanResponse(container_id=container_id, vulnerabilities=results)


##############################################################################
# 5. Run if main
##############################################################################
# if __name__ == "__main__":
#     uvicorn.run(app, host="0.0.0.0", port=8000)
