from fastapi import APIRouter, Depends, HTTPException, UploadFile, File
from sqlalchemy.orm import Session
import json

from app.database import get_db
from app.models.case import ThreatCase
from app.schemas.case import ThreatCase as ThreatCaseSchema
from app.services.email_parser import EmailParserService
from app.services.header_forensics import HeaderForensicsService
from app.services.authentication import AuthenticationService
from app.services.geolocation import GeolocationService
from app.services.domain_analysis import DomainAnalysisService
from app.services.ai_classifier import AIClassifierService

router = APIRouter()

@router.post("/process", response_model=ThreatCaseSchema)
async def process_email(file: UploadFile = File(...), db: Session = Depends(get_db)):
    """Processes a raw email file and creates a new threat case."""
    
    try:
        raw_email_bytes = await file.read()
        raw_content = raw_email_bytes.decode('utf-8', errors='replace')
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error reading file: {str(e)}")

    # 1. Parsing
    parsed_email = EmailParserService.parse_raw_email(raw_content)
    
    # 2. Header Forensics
    headers_info = HeaderForensicsService.analyze_headers(parsed_email["raw_headers"])
    
    # 3. Authentication Checks
    auth_info = AuthenticationService.check_auth(
        raw_email_bytes, 
        parsed_email.get("sender_email", ""),
        raw_headers=parsed_email.get("raw_headers")
    )
    
    # 4. Geolocation (Async with IPGeolocation.io)
    geo_info = {}
    target_ip = headers_info.get("originating_ip")
    if not target_ip and headers_info.get("hop_ips"):
        for ip in headers_info["hop_ips"]:
            if not ip.startswith("10.") and not ip.startswith("192.168.") and ip != "127.0.0.1":
                target_ip = ip
                break
    if not target_ip and headers_info.get("hop_ips"):
        target_ip = headers_info["hop_ips"][0]

    if target_ip:
        geo_info = await GeolocationService.get_ip_info(target_ip)
                
    # 5. Domain Analysis (Async with VirusTotal v3)
    domain_info = await DomainAnalysisService.analyze_domains(
        parsed_email.get("extracted_urls", []), 
        parsed_email.get("sender_email", "")
    )
    
    # 6. AI & Threat Intel Classification
    ai_classification = AIClassifierService.classify_email(
        parsed_email.get("body_content", ""), 
        headers_info,
        suspicious_domains=domain_info.get("suspicious_domains", [])
    )
    
    # 7. Database Persistence
    db_case = ThreatCase(
        sender_email=parsed_email.get("sender_email"),
        recipient_email=parsed_email.get("recipient_email"),
        subject=parsed_email.get("subject"),
        raw_headers=json.dumps(parsed_email.get("raw_headers")),
        body_content=parsed_email.get("body_content"),
        
        ai_classification=ai_classification.get("classification"),
        confidence_score=ai_classification.get("confidence"),
        
        spf_record=auth_info.get("spf_record"),
        dkim_valid=auth_info.get("dkim_valid"),
        dmarc_policy=auth_info.get("dmarc_policy"),
        
        source_ip=target_ip,
        geo_location=geo_info.get("geo_location"),
        asn_info=geo_info.get("asn_info"),
        latitude=geo_info.get("lat"),
        longitude=geo_info.get("lon"),
        
        extracted_urls=json.dumps(parsed_email.get("extracted_urls", [])),
        suspicious_domains=json.dumps(domain_info.get("suspicious_domains", []))
    )
    
    db.add(db_case)
    db.commit()
    db.refresh(db_case)
    
    return db_case
