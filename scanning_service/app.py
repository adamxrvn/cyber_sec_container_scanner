import subprocess
import uvicorn
from fastapi import FastAPI, Request, HTTPException
from pydantic import BaseModel
from typing import List, Dict, Any, Optional

app = FastAPI(
    title="Container Vulnerability Scanner",
    description="Microservices of Container Vulnerability Scanner",
    version="1.0.1"  # updated version
)

# ----------------------------------------------------------------------------
# 1. Mock vulnerability database
#    Key: (package_name_substring, version_substring)
#    Value: dictionary with CVE info
# ----------------------------------------------------------------------------
VULN_DB = {
    ("apt", "1.4.11"): {
        "cve": "CVE-2019-3462",
        "description": "APT MITM vulnerability in apt < 1.4.9 on Debian 9",
        "url": "https://nvd.nist.gov/vuln/detail/CVE-2019-3462",
        "severity": "HIGH"
    },
    ("bash", "4.4"): {
        "cve": "CVE-2019-9924",
        "description": "Bash 4.x vulnerability involving function exporting",
        "url": "https://nvd.nist.gov/vuln/detail/CVE-2019-9924",
        "severity": "MEDIUM"
    },
    ("libssl", "1.1.0"): {
        "cve": "CVE-2022-0778",
        "description": "OpenSSL certificate parsing infinite loop affecting versions of 1.1.0",
        "url": "https://nvd.nist.gov/vuln/detail/CVE-2022-0778",
        "severity": "CRITICAL"
    },
    ("curl", "7.52.1"): {
        "cve": "CVE-2021-22946",
        "description": "curl URL parser vulnerability leading to malicious request injection",
        "url": "https://nvd.nist.gov/vuln/detail/CVE-2021-22946",
        "severity": "MEDIUM"
    },
    ("python2.7", "2.7.13"): {
        "cve": "CVE-2021-3733",
        "description": "Integer overflow in Python 2.7 libraries",
        "url": "https://nvd.nist.gov/vuln/detail/CVE-2021-3733",
        "severity": "LOW"
    },
    ("apt", "2.2.4"): {
        "cve": "CVE-2022-25295",
        "description": "APT vulnerability in Debian 11 related to Release file signature handling",
        "url": "https://nvd.nist.gov/vuln/detail/CVE-2022-25295",
        "severity": "HIGH"
    },
    ("bash", "5.1"): {
        "cve": "CVE-2022-3715",
        "description": "Bash 5.x vulnerability with potential RCE",
        "url": "https://nvd.nist.gov/vuln/detail/CVE-2022-3715",
        "severity": "HIGH"
    },
    ("libssl", "1.1.1k"): {
        "cve": "CVE-2022-0778",
        "description": "OpenSSL certificate infinite loop vulnerability in 1.1.1k",
        "url": "https://nvd.nist.gov/vuln/detail/CVE-2022-0778",
        "severity": "CRITICAL"
    },
    ("curl", "7.74.0"): {
        "cve": "CVE-2022-27780",
        "description": "curl certificate verification bypass in 7.74.0",
        "url": "https://nvd.nist.gov/vuln/detail/CVE-2022-27780",
        "severity": "HIGH"
    },
    ("python3.5", "3.5.3"): {
        "cve": "CVE-2021-23336",
        "description": "Regular expression DoS (ReDoS) vulnerability in Python 3.5 libraries",
        "url": "https://nvd.nist.gov/vuln/detail/CVE-2021-23336",
        "severity": "MEDIUM"
    }
}


# ----------------------------------------------------------------------------
# 2. Pydantic models for request/response
# ----------------------------------------------------------------------------
class ScanRequest(BaseModel):
    container_id: str


class VulnerabilityInfo(BaseModel):
    package: str
    version: str
    cve: str
    description: str
    url: str
    severity: str  # new field


class ScanResponse(BaseModel):
    container_id: str
    vulnerabilities: List[VulnerabilityInfo]


# ----------------------------------------------------------------------------
# 3. Utility function to parse dpkg/rpm output
# ----------------------------------------------------------------------------
def parse_dpkg_output(output: str) -> List[Dict[str, str]]:
    """
    Parses dpkg -l output.
    Expects lines like: "ii  bash   5.1-2ubuntu3  ...",
    We'll return list of dicts: [{"name": "bash", "version": "5.1-2ubuntu3"}, ...]
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
    Parses rpm -qa --qf '%{NAME} %{VERSION}\n' output.
    Lines often look like: "bash 5.1" or "openssl-libs 1.1.1k"
    """
    packages = []
    for line in output.split("\n"):
        parts = line.strip().split()
        if len(parts) >= 2:
            pkg_name = parts[0]
            pkg_version = parts[1]
            packages.append({"name": pkg_name, "version": pkg_version})
    return packages


# ----------------------------------------------------------------------------
# 4. The scanning logic
# ----------------------------------------------------------------------------
def scan_container_for_vulns(container_id: str) -> List[VulnerabilityInfo]:
    """
    1) Try dpkg -l inside the container.
    2) If dpkg fails, try rpm -qa.
    3) Compare each found package against VULN_DB.
    """
    # 1) Attempt dpkg -l
    cmd_dpkg = f"docker exec {container_id} dpkg -l"
    process = subprocess.Popen(cmd_dpkg.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = process.communicate()

    if process.returncode == 0:
        # we have dpkg output
        pkgs = parse_dpkg_output(stdout.decode("utf-8"))
    else:
        # fallback to rpm
        cmd_rpm = f"docker exec {container_id} rpm -qa --qf '%{{NAME}} %{{VERSION}}\\n'"
        process_rpm = subprocess.Popen(cmd_rpm, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout_rpm, stderr_rpm = process_rpm.communicate()
        if process_rpm.returncode != 0:
            # both dpkg and rpm failed => error out
            error_msg = stderr_rpm.decode('utf-8').strip() or stderr.decode('utf-8').strip()
            raise HTTPException(status_code=500, detail=f"Failed to retrieve package list: {error_msg}")
        # parse rpm output
        pkgs = parse_rpm_output(stdout_rpm.decode("utf-8"))

    # 2) Compare packages to VULN_DB
    found_vulns = []
    for pkg in pkgs:
        pkg_name = pkg["name"]
        pkg_version = pkg["version"]

        # Compare with (db_pkg_name, db_version_substring) in VULN_DB
        for (db_pkg_substr, db_ver_substr), vuln_info in VULN_DB.items():
            # If the package name *contains* db_pkg_substr and package version *contains* db_ver_substr
            if db_pkg_substr in pkg_name and db_ver_substr in pkg_version:
                vuln = VulnerabilityInfo(
                    package=pkg_name,
                    version=pkg_version,
                    cve=vuln_info["cve"],
                    description=vuln_info["description"],
                    url=vuln_info["url"],
                    severity=vuln_info.get("severity", "UNKNOWN")
                )
                # Avoid duplicates
                if vuln not in found_vulns:
                    found_vulns.append(vuln)

    return found_vulns


# ----------------------------------------------------------------------------
# 5. Endpoints
# ----------------------------------------------------------------------------
@app.get("/health")
def health_check():
    """
    Simple health check endpoint.
    """
    return {"status": "ok"}


@app.post("/scan", response_model=ScanResponse, tags=["Scanning"])
def scan_container_endpoint(request_body: ScanRequest):
    """
    Scans the container for known vulnerabilities.

    Steps:
    1) Runs either `dpkg -l` or `rpm -qa` inside the given container.
    2) Parses each package name/version.
    3) Compares them to a mock vulnerability database.
    4) Returns identified vulnerabilities in JSON format.
    """
    container_id = request_body.container_id
    vulns = scan_container_for_vulns(container_id)
    return ScanResponse(container_id=container_id, vulnerabilities=vulns)


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
