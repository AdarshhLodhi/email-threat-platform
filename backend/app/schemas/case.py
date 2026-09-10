from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime

class EvidenceBase(BaseModel):
    evidence_type: str
    description: Optional[str] = None
    file_path: Optional[str] = None

class EvidenceCreate(EvidenceBase):
    pass

class Evidence(EvidenceBase):
    id: int
    case_id: int
    created_at: datetime

    class Config:
        from_attributes = True

class ThreatCaseBase(BaseModel):
    status: Optional[str] = "Open"
    sender_email: Optional[str] = None
    recipient_email: Optional[str] = None
    subject: Optional[str] = None
    raw_headers: Optional[str] = None
    body_content: Optional[str] = None
    ai_classification: Optional[str] = None
    confidence_score: Optional[float] = None
    spf_record: Optional[str] = None
    dkim_valid: Optional[bool] = None
    dmarc_policy: Optional[str] = None
    source_ip: Optional[str] = None
    geo_location: Optional[str] = None
    asn_info: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    extracted_urls: Optional[str] = None
    suspicious_domains: Optional[str] = None

class ThreatCaseCreate(ThreatCaseBase):
    pass

class ThreatCase(ThreatCaseBase):
    id: int
    created_at: datetime
    updated_at: datetime
    evidence: List[Evidence] = []

    class Config:
        from_attributes = True
