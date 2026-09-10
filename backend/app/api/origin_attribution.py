from fastapi import APIRouter, Depends, HTTPException, Body
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import Dict, Any, Optional

from app.database import get_db
from app.models.case import ThreatCase
from app.services.origin_attribution import OriginAttributionService

router = APIRouter()

class HeaderAnalysisRequest(BaseModel):
    raw_headers: str
    source_ip: Optional[str] = None
    asn_info: Optional[str] = None
    sender_email: Optional[str] = None
    subject: Optional[str] = None

@router.get("/case/{case_id}")
async def get_case_origin_attribution(case_id: int, db: Session = Depends(get_db)):
    """Retrieves end-to-end Origin Intelligence, Relay Reconstruction, and Attribution scoring for a specific case."""
    case = db.query(ThreatCase).filter(ThreatCase.id == case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail="Threat case not found")
    
    attribution_data = await OriginAttributionService.get_origin_attribution(case_id, case, db)
    return attribution_data

@router.post("/analyze-headers")
async def analyze_raw_headers(payload: HeaderAnalysisRequest, db: Session = Depends(get_db)):
    """Ad-hoc header parsing, relay path reconstruction, and complete origin attribution on arbitrary raw headers."""
    if not payload.raw_headers:
        raise HTTPException(status_code=400, detail="Empty headers provided")
    
    mock_case = ThreatCase(
        id=0,
        subject=payload.subject or "Ad-Hoc Origin Analysis",
        sender_email=payload.sender_email or "threat-source@suspicious-external.net",
        source_ip=payload.source_ip,
        asn_info=payload.asn_info,
        raw_headers=payload.raw_headers,
        ai_classification="Investigating"
    )
    return await OriginAttributionService.get_origin_attribution(0, mock_case, db)
