from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import PlainTextResponse
from sqlalchemy.orm import Session
import json

from app.database import get_db
from app.models.case import ThreatCase
from app.services.report_generator import ReportGeneratorService

router = APIRouter()

@router.get("/{case_id}/forensic", response_class=PlainTextResponse)
def get_forensic_report(case_id: int, db: Session = Depends(get_db)):
    """Generate a structured text forensic report for a case."""
    case = db.query(ThreatCase).filter(ThreatCase.id == case_id).first()
    if case is None:
        raise HTTPException(status_code=404, detail="Case not found")
        
    case_dict = case.__dict__
    # Try parsing raw headers for nicer output if possible, or just pass the string
    return ReportGeneratorService.generate_forensic_report(case_dict)

@router.get("/{case_id}/complaint", response_class=PlainTextResponse)
def get_complaint_draft(case_id: int, db: Session = Depends(get_db)):
    """Generate a draft complaint text for a case."""
    case = db.query(ThreatCase).filter(ThreatCase.id == case_id).first()
    if case is None:
        raise HTTPException(status_code=404, detail="Case not found")
        
    case_dict = case.__dict__
    return ReportGeneratorService.generate_cyber_complaint(case_dict)
