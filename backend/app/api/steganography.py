from fastapi import APIRouter, Depends, HTTPException, UploadFile, File
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import Optional

from app.database import get_db
from app.models.case import ThreatCase
from app.services.steganography import SteganographyService

router = APIRouter()

class SendStegoEmailRequest(BaseModel):
    recipient: Optional[str] = "finance-desk@target-corp.internal"
    subject: Optional[str] = "Urgent: Updated Remittance Invoice #49281 Attached"
    body: Optional[str] = "Please find attached the updated remittance invoice for processing. Immediate review required."
    attachment_name: Optional[str] = "invoice_#49281_remittance.png"
    hidden_payload: Optional[str] = "hxxp://c2.evil-corp-command[.]ru/beacon.php?token=49281_stego_auth&action=inject"
    stego_method: Optional[str] = "LSB (Least Significant Bit)"

class SimulateVectorRequest(BaseModel):
    vector: str = "lsb"

@router.get("/case/{case_id}")
def get_case_steganography(case_id: int, db: Session = Depends(get_db)):
    """Retrieves steganographic forensic analysis for attachments in a specific threat case."""
    case = db.query(ThreatCase).filter(ThreatCase.id == case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail="Threat case not found")
    
    return SteganographyService.get_case_attachment_stego(case_id, case, db=db)

@router.post("/case/{case_id}/simulate-vector")
def simulate_case_vector(case_id: int, req: SimulateVectorRequest, db: Session = Depends(get_db)):
    """Simulates an attack vector (lsb, eof_polyglot, metadata_exif, high_entropy, clean) for live interactive testing."""
    case = db.query(ThreatCase).filter(ThreatCase.id == case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail="Threat case not found")
    
    return SteganographyService.simulate_vector(case_id, req.vector, db=db)

@router.post("/case/{case_id}/attach-scan")
async def attach_scan_to_case(case_id: int, file: UploadFile = File(...), db: Session = Depends(get_db)):
    """Accepts an uploaded attachment, runs multi-engine forensics, and binds it permanently to the case."""
    case = db.query(ThreatCase).filter(ThreatCase.id == case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail="Threat case not found")
    
    try:
        content = await file.read()
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to read uploaded file: {str(e)}")
    
    if not content:
        raise HTTPException(status_code=400, detail="Empty attachment file provided.")
        
    return SteganographyService.attach_and_scan(
        case_id=case_id,
        file_bytes=content,
        filename=file.filename or "uploaded_attachment.bin",
        content_type=file.content_type or "application/octet-stream",
        db=db
    )

@router.post("/scan-upload")
async def scan_attachment_upload(file: UploadFile = File(...)):
    """Accepts an uploaded email attachment file and executes multi-engine steganography forensic analysis."""
    try:
        content = await file.read()
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to read uploaded file: {str(e)}")
    
    if not content:
        raise HTTPException(status_code=400, detail="Empty attachment file provided.")
    
    return SteganographyService.analyze_attachment(
        file_bytes=content,
        filename=file.filename or "uploaded_attachment.bin",
        content_type=file.content_type or "application/octet-stream"
    )

@router.post("/send-test-email")
def send_test_stego_email(req: SendStegoEmailRequest, db: Session = Depends(get_db)):
    """Synthesizes and dispatches an email with a steganographic attachment to simulate threat ingestion."""
    return SteganographyService.send_test_email(
        recipient=req.recipient or "finance-desk@target-corp.internal",
        subject=req.subject or "Urgent: Updated Remittance Invoice #49281 Attached",
        body=req.body or "Please review attached document.",
        attachment_name=req.attachment_name or "invoice_#49281_remittance.png",
        payload_text=req.hidden_payload or "",
        stego_method=req.stego_method or "LSB (Least Significant Bit)",
        db=db
    )
