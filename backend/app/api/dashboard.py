from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func

from app.database import get_db
from app.models.case import ThreatCase

router = APIRouter()

@router.get("/stats")
def get_dashboard_stats(db: Session = Depends(get_db)):
    """Retrieve high-level statistics for the dashboard."""
    total_cases = db.query(ThreatCase).count()
    open_cases = db.query(ThreatCase).filter(ThreatCase.status == "Open").count()
    
    phishing_cases = db.query(ThreatCase).filter(ThreatCase.ai_classification.ilike("Phishing")).count()
    malware_cases = db.query(ThreatCase).filter(ThreatCase.ai_classification.ilike("Malware")).count()
    benign_cases = db.query(ThreatCase).filter(
        (ThreatCase.ai_classification.ilike("Benign")) | 
        (ThreatCase.ai_classification.ilike("Safe")) | 
        (ThreatCase.ai_classification.ilike("Legitimate"))
    ).count()
    
    return {
        "total_cases": total_cases,
        "open_cases": open_cases,
        "classification_breakdown": {
            "Phishing": phishing_cases,
            "Malware": malware_cases,
            "Benign": benign_cases
        }
    }
