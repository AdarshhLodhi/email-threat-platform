import os
import sys
import json

# Add backend directory to path so we can import from app
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(os.path.join(BASE_DIR, 'backend'))

from app.database import SessionLocal
from app.models.case import ThreatCase

def seed_demo_data():
    db = SessionLocal()
    
    # Check if data already exists
    if db.query(ThreatCase).count() > 0:
        print("Database already contains data. Skipping seed.")
        db.close()
        return

    print("Seeding demo data...")
    
    demo_cases = [
        ThreatCase(
            status="Open",
            sender_email="admin@g00gle-support.com",
            recipient_email="employee@company.com",
            subject="URGENT: Password Reset Required",
            body_content="Dear User, Your account will be suspended. Click here to reset your password: http://g00gle-support.com/reset",
            ai_classification="Phishing",
            confidence_score=0.95,
            spf_record="Fail",
            dkim_valid=False,
            dmarc_policy="None",
            source_ip="185.12.34.56",
            geo_location="St. Petersburg, Russia",
            asn_info="AS12345 Suspicious Hosting",
            extracted_urls=json.dumps(["http://g00gle-support.com/reset"]),
            suspicious_domains=json.dumps([{"domain": "g00gle-support.com", "reasons": ["Lookalike domain", "Uses HTTP"]}])
        ),
        ThreatCase(
            status="Investigating",
            sender_email="vendor@supplier-invoice-update.net",
            recipient_email="finance@company.com",
            subject="Invoice #49281 Attached for Payment",
            body_content="Please find attached the invoice for Q3. Remittance is expected within 7 days. See attached ZIP file.",
            ai_classification="Malware",
            confidence_score=0.88,
            spf_record="Pass",
            dkim_valid=True,
            dmarc_policy="Quarantine",
            source_ip="45.67.89.10",
            geo_location="Amsterdam, Netherlands",
            asn_info="AS6789 Cloud Provider",
            extracted_urls=json.dumps([]),
            suspicious_domains=json.dumps([])
        )
    ]
    
    for case in demo_cases:
        db.add(case)
        
    db.commit()
    print("Demo data seeded successfully.")
    db.close()

if __name__ == "__main__":
    seed_demo_data()
