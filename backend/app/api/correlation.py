from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.case import ThreatCase
from app.services.infrastructure_correlation import InfrastructureCorrelationService

router = APIRouter()

@router.get("/graph")
def get_correlation_graph(db: Session = Depends(get_db)):
    """Generate a NetworkX correlation graph for all cases."""
    cases_orm = db.query(ThreatCase).all()
    
    # Convert ORM to dict for the service
    cases = []
    for c in cases_orm:
        cases.append({
            "id": c.id,
            "ai_classification": c.ai_classification,
            "sender_email": c.sender_email,
            "source_ip": c.source_ip,
            "asn_info": c.asn_info,
            "suspicious_domains": c.suspicious_domains
        })
        
    return InfrastructureCorrelationService.build_correlation_graph(cases)
