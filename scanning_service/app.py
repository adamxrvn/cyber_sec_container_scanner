import subprocess

import uvicorn
from fastapi import FastAPI, Request, HTTPException
from pydantic import BaseModel
from typing import List, Dict, Any

app = FastAPI(
    title="Container Vulnerability Scanner",
    description="A simple FastAPI service to scan container packages against a  CVE database",
    version="1.0.0"
)

# ----------------------------------------------------------------------------
# 1. Simple vulnerability database (toy example)
#    Key: (package_name, version_substring)
#    Value: CVE or any vulnerability info
# ----------------------------------------------------------------------------
MOCK_VULN_DB = {
    ("apt", "1.4.11"): {
        "cve": "CVE-2019-3462",
        "description": "APT MITM vulnerability in apt before 1.4.9 on Debian 9",
        "url": "https://nvd.nist.gov/vuln/detail/CVE-2019-3462"
    },
    ("bash", "4.4"): {
        "cve": "CVE-2019-9924",
        "description": "Bash 4.x vulnerability involving function exporting and potential use-after-free",
        "url": "https://nvd.nist.gov/vuln/detail/CVE-2019-9924"
    },
    ("libssl", "1.1.0"): {
        "cve": "CVE-2022-0778",
        "description": "OpenSSL certificate parsing infinite loop affecting versions of 1.1.0",
        "url": "https://nvd.nist.gov/vuln/detail/CVE-2022-0778"
    },
    ("curl", "7.52.1"): {
        "cve": "CVE-2021-22946",
        "description": "curl URL parser vulnerability leading to malicious request injection",
        "url": "https://nvd.nist.gov/vuln/detail/CVE-2021-22946"
    },
    ("python2.7", "2.7.13"): {
        "cve": "CVE-2021-3733",
        "description": "Integer overflow and related issues in Python 2.7 libraries",
        "url": "https://nvd.nist.gov/vuln/detail/CVE-2021-3733"
    },

    ("apt", "2.2.4"): {
        "cve": "CVE-2022-25295",
        "description": "APT vulnerability in Debian 11 related to Release file signature handling",
        "url": "https://nvd.nist.gov/vuln/detail/CVE-2022-25295"
    },
    ("bash", "5.1"): {
        "cve": "CVE-2022-3715",
        "description": "Bash 5.x vulnerability involving function exporting and potential RCE",
        "url": "https://nvd.nist.gov/vuln/detail/CVE-2022-3715"
    },
    ("libssl", "1.1.1k"): {
        "cve": "CVE-2022-0778",
        "description": "OpenSSL certificate infinite loop vulnerability in 1.1.1k",
        "url": "https://nvd.nist.gov/vuln/detail/CVE-2022-0778"
    },
    ("curl", "7.74.0"): {
        "cve": "CVE-2022-27780",
        "description": "curl certificate verification bypass in 7.74.0",
        "url": "https://nvd.nist.gov/vuln/detail/CVE-2022-27780"
    },
    ("python3.5", "3.5.3"): {
        "cve": "CVE-2021-23336",
        "description": "Regular expression DoS (ReDoS) vulnerability in Python 3.5 libraries",
        "url": "https://nvd.nist.gov/vuln/detail/CVE-2021-23336"
    }
}


# ----------------------------------------------------------------------------
# 2. Define request/response models
# ----------------------------------------------------------------------------
class ScanRequest(BaseModel):
    container_id: str


class VulnerabilityInfo(BaseModel):
    package: str
    version: str
    cve: str
    description: str
    url: str


class ScanResponse(BaseModel):
    container_id: str
    vulnerabilities: List[VulnerabilityInfo]


# ----------------------------------------------------------------------------
# 3. /health endpoint
# ----------------------------------------------------------------------------
@app.get("/health")
def health_check():
    """
    Simple health check endpoint.
    """
    return {"status": "ok"}


# ----------------------------------------------------------------------------
# 4. /scan endpoint
# ----------------------------------------------------------------------------
@app.post("/scan", response_model=ScanResponse)
def scan_container(request_body: ScanRequest):
    """
    Scans the container for known vulnerabilities.
    1) Runs `docker exec <container> dpkg -l` (assuming Debian/Ubuntu-based container).
    2) Checks each package against MOCK_VULN_DB.
    3) Returns identified vulnerabilities in JSON format.
    """
    container_id = request_body.container_id

    cmd = f"docker exec {container_id} dpkg -l"
    process = subprocess.Popen(cmd.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = process.communicate()

    if process.returncode != 0:
        error_msg = f"Failed to retrieve package list: {stderr.decode('utf-8').strip()}"
        raise HTTPException(status_code=500, detail=error_msg)

    vulnerabilities_found = []
    lines = stdout.decode("utf-8").split("\n")

    for line in lines:
        parts = line.split()
        if len(parts) < 3:
            continue

        pkg_name = parts[1]
        pkg_version = parts[2]

        # Compare to mock vulnerability database
        for (db_pkg_name, db_version_substr), vuln_info in MOCK_VULN_DB.items():
            if db_pkg_name in pkg_name and db_version_substr in pkg_version:
                vulner = {
                    "package": pkg_name,
                    "version": pkg_version,
                    "cve": vuln_info["cve"],
                    "description": vuln_info["description"],
                    "url": vuln_info["url"]
                }

                if vulner not in vulnerabilities_found:
                    vulnerabilities_found.append(vulner)

    return ScanResponse(
        container_id=container_id,
        vulnerabilities=vulnerabilities_found
    )


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
