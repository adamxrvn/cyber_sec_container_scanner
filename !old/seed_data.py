from models import engine, SessionLocal, init_db, VulnerabilityRecord

def seed_vulnerabilities():
    db = SessionLocal()
    try:
        # Insert a few known entries:
        # e.g. If we find "bash < 5.1-2ubuntu3", it's vulnerable
        # e.g. If we find "openssl < 1.1.1k", it's vulnerable
        # Adjust to your OS packaging
        existing = db.query(VulnerabilityRecord).all()
        if existing:
            print("Vulnerabilities already seeded.")
            return

        vulns = [
            {
                "vulnerability_id": "CVE-2021-3449",
                "package_name": "openssl",
                "patched_version": "1.1.1k",
                "description": "Denial of service in TLS servers before 1.1.1k",
                "severity_level": 3,
            },
            {
                "vulnerability_id": "CVE-2014-6271",
                "package_name": "bash",
                "patched_version": "4.3",
                "description": "Shellshock vulnerability in Bash < 4.3",
                "severity_level": 4,
            },
            {
                "vulnerability_id": "CVE-2022-9999",
                "package_name": "bash",
                "patched_version": "5.1-2ubuntu5",
                "description": "Fake example for demonstration",
                "severity_level": 2,
            },
        ]

        for v in vulns:
            record = VulnerabilityRecord(
                vulnerability_id=v["vulnerability_id"],
                package_name=v["package_name"],
                patched_version=v["patched_version"],
                description=v["description"],
                severity_level=v["severity_level"],
                status="active",
            )
            db.add(record)
        db.commit()
        print("Seeded vulnerabilities.")
    finally:
        db.close()

if __name__ == "__main__":
    init_db()
    seed_vulnerabilities()
