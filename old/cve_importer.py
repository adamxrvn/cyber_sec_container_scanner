# cve_importer.py
import requests
import gzip
import json
from sqlalchemy.orm import sessionmaker
from models import (
    engine, VulnerabilityDatabase, VulnerabilityRecord
)
from datetime import datetime

SessionLocal = sessionmaker(bind=engine)

NVD_2023_JSON = "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2024.json.gz"


def import_nvd_data():
    db = SessionLocal()
    try:
        # 1) Ensure we have a row in VulnerabilityDatabase for "NVD"
        nvd_db = db.query(VulnerabilityDatabase).filter_by(name="NVD").first()
        if not nvd_db:
            nvd_db = VulnerabilityDatabase(
                name="NVD",
                description="National Vulnerability Database",
                source_url="https://nvd.nist.gov/"
            )
            db.add(nvd_db)
            db.commit()
            db.refresh(nvd_db)

        # 2) Download & parse
        response = requests.get(NVD_2023_JSON)
        content = gzip.decompress(response.content)
        nvd_data = json.loads(content)

        cve_items = nvd_data.get("CVE_Items", [])
        for item in cve_items:
            cve_id = item["cve"]["CVE_data_meta"]["ID"]
            published_date = item.get("publishedDate", None)
            last_modified = item.get("lastModifiedDate", None)
            description_data = item["cve"]["description"]["description_data"]
            description_text = description_data[0]["value"] if description_data else ""

            # Determine severity (simplified)
            impact = item.get("impact", {})
            base_metric_v3 = impact.get("baseMetricV3", {})
            cvss_v3 = base_metric_v3.get("cvssV3", {})
            severity_str = cvss_v3.get("baseSeverity", "UNKNOWN").lower()  # e.g., 'HIGH', 'LOW', etc.

            # Map severity_str to an integer
            severity_map = {
                "low": 1,
                "medium": 2,
                "high": 3,
                "critical": 4
            }
            severity_val = severity_map.get(severity_str, 1)

            # 3) Insert/Upsert record
            existing_record = db.query(VulnerabilityRecord).filter_by(vulnerability_id=cve_id).first()
            if not existing_record:
                record = VulnerabilityRecord(
                    vulnerability_db_id=nvd_db.id,
                    vulnerability_id=cve_id,
                    description=description_text,
                    severity_level=severity_val,
                    status="active",
                    published_at=datetime.strptime(published_date, "%Y-%m-%dT%H:%MZ") if published_date else None,
                    last_modified=datetime.strptime(last_modified, "%Y-%m-%dT%H:%MZ") if last_modified else None
                )
                db.add(record)
            else:
                # Update existing
                existing_record.description = description_text
                existing_record.severity_level = severity_val
                existing_record.last_modified = datetime.utcnow()
                existing_record.status = "active"

        db.commit()
        print("Imported CVEs from NVD feed successfully!")
    except Exception as e:
        db.rollback()
        print(f"Error importing data: {e}")
    finally:
        db.close()


if __name__ == "__main__":
    import_nvd_data()
