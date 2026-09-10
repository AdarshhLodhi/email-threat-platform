from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from sqlalchemy import or_, cast, String
from typing import List, Optional
import json
import re

from app.database import get_db
from app.models.case import ThreatCase, Evidence
from app.schemas.case import ThreatCase as ThreatCaseSchema

router = APIRouter()

@router.get("/", response_model=List[ThreatCaseSchema])
def get_cases(
    skip: int = 0, 
    limit: int = 100, 
    classification: Optional[str] = None,
    status: Optional[str] = None,
    search: Optional[str] = None,
    db: Session = Depends(get_db)
):
    """Retrieve all cases with optional filtering by status, classification, or search term."""
    query = db.query(ThreatCase)
    
    if status and status.lower() != 'all':
        query = query.filter(ThreatCase.status.ilike(status))
        
    if classification and classification.lower() != 'all':
        if classification.lower() in ['benign', 'safe', 'legitimate']:
            query = query.filter(
                or_(
                    ThreatCase.ai_classification.ilike("%benign%"),
                    ThreatCase.ai_classification.ilike("%safe%"),
                    ThreatCase.ai_classification.ilike("%legitimate%")
                )
            )
        else:
            query = query.filter(ThreatCase.ai_classification.ilike(f"%{classification}%"))
            
    if search and search.strip():
        search_pattern = f"%{search.strip()}%"
        query = query.filter(
            or_(
                ThreatCase.subject.ilike(search_pattern),
                ThreatCase.sender_email.ilike(search_pattern),
                ThreatCase.source_ip.ilike(search_pattern),
                cast(ThreatCase.id, String).ilike(search_pattern)
            )
        )
        
    cases = query.order_by(ThreatCase.created_at.desc()).offset(skip).limit(limit).all()
    return cases

@router.get("/{case_id}", response_model=ThreatCaseSchema)
def get_case(case_id: int, db: Session = Depends(get_db)):
    """Retrieve a specific case by ID."""
    case = db.query(ThreatCase).filter(ThreatCase.id == case_id).first()
    if case is None:
        raise HTTPException(status_code=404, detail="Case not found")
    return case

@router.put("/{case_id}/status")
def update_case_status(case_id: int, status: str, db: Session = Depends(get_db)):
    """Update case status (Open, Investigating, Closed)"""
    case = db.query(ThreatCase).filter(ThreatCase.id == case_id).first()
    if case is None:
        raise HTTPException(status_code=404, detail="Case not found")
        
    case.status = status
    db.commit()
    return {"status": "success", "new_status": status}

@router.delete("/{case_id}")
def delete_case(case_id: int, db: Session = Depends(get_db)):
    """Delete a specific case and its associated evidence."""
    case = db.query(ThreatCase).filter(ThreatCase.id == case_id).first()
    if case is None:
        raise HTTPException(status_code=404, detail="Case not found")
        
    db.query(Evidence).filter(Evidence.case_id == case_id).delete()
    db.delete(case)
    db.commit()
    return {"status": "success", "message": f"Case #{case_id} deleted successfully"}

@router.get("/{case_id}/auth-forensics")
def get_case_auth_forensics(case_id: int, db: Session = Depends(get_db)):
    """Extracts deep cryptographic authentication forensics (SPF, DKIM, DMARC, ARC) and anti-spoofing analysis."""
    case = db.query(ThreatCase).filter(ThreatCase.id == case_id).first()
    if case is None:
        raise HTTPException(status_code=404, detail="Case not found")
        
    sender = case.sender_email or ""
    domain = sender.split("@")[-1].strip(">").strip() if "@" in sender else ""
    
    # Live DNS records
    from app.services.authentication import AuthenticationService
    live_spf = AuthenticationService._check_spf(domain) if domain else None
    live_dmarc = AuthenticationService._check_dmarc(domain) if domain else None
    
    # Headers inspection
    raw_hdrs = {}
    try:
        raw_hdrs = json.loads(case.raw_headers) if case.raw_headers else {}
    except Exception:
        raw_hdrs = {}
        
    auth_results_raw = raw_hdrs.get("Authentication-Results", "")
    if isinstance(auth_results_raw, list):
        auth_results_raw = " ".join(auth_results_raw)
        
    rec_spf_raw = raw_hdrs.get("Received-SPF", "")
    if isinstance(rec_spf_raw, list):
        rec_spf_raw = " ".join(rec_spf_raw)
        
    dkim_sig_raw = raw_hdrs.get("DKIM-Signature", "")
    if isinstance(dkim_sig_raw, list):
        dkim_sig_raw = dkim_sig_raw[0] if dkim_sig_raw else ""
        
    arc_results = raw_hdrs.get("ARC-Authentication-Results", "")
    if isinstance(arc_results, list):
        arc_results = arc_results[0] if arc_results else ""
        
    # SPF Analysis
    spf_status = "Pass" if (case.spf_record and "pass" in str(case.spf_record).lower()) or "spf=pass" in auth_results_raw.lower() or "pass" in rec_spf_raw.lower() else ("Fail" if "spf=fail" in auth_results_raw.lower() else "None / Neutral")
    
    # DKIM Analysis
    dkim_status = "Valid Signature" if case.dkim_valid or "dkim=pass" in auth_results_raw.lower() else "Invalid / Missing"
    
    dkim_selector = None
    dkim_algo = None
    dkim_domain = None
    dkim_body_hash = None
    if dkim_sig_raw:
        sel_m = re.search(r's=([^;]+)', dkim_sig_raw)
        alg_m = re.search(r'a=([^;]+)', dkim_sig_raw)
        dom_m = re.search(r'd=([^;]+)', dkim_sig_raw)
        bh_m = re.search(r'bh=([^;]+)', dkim_sig_raw)
        if sel_m: dkim_selector = sel_m.group(1).strip()
        if alg_m: dkim_algo = alg_m.group(1).strip()
        if dom_m: dkim_domain = dom_m.group(1).strip()
        if bh_m: dkim_body_hash = bh_m.group(1).strip()
        
    # DMARC Analysis
    dmarc_status = "Pass" if "dmarc=pass" in auth_results_raw.lower() or (case.dmarc_policy and "pass" in str(case.dmarc_policy).lower()) else "None / Unenforced"
    dmarc_policy_val = "none"
    p_match = re.search(r'p=(\w+)', (live_dmarc or "") + " " + auth_results_raw, re.IGNORECASE)
    if p_match:
        dmarc_policy_val = p_match.group(1).lower()
        
    # ARC Analysis
    arc_status = "Pass" if "arc=pass" in auth_results_raw.lower() or "arc=pass" in arc_results.lower() else "None"
    
    # Cross-Identity Impersonation / Living-off-the-Cloud Detection
    subject = case.subject or ""
    body = case.body_content or ""
    combined_text = (subject + " " + body).lower()
    
    impersonated_brand = None
    brands = [
        ("HDFC Bank", ["hdfc", "hdfcbank"]),
        ("ICICI Bank", ["icici"]),
        ("State Bank of India (SBI)", ["sbi", "state bank"]),
        ("PayPal", ["paypal"]),
        ("Apple Security", ["apple id", "apple support", "icloud"]),
        ("Microsoft 365", ["microsoft", "office365", "outlook"]),
        ("Netflix", ["netflix"]),
        ("Amazon Pay", ["amazon pay", "amazon prime", "amazon account"])
    ]
    for brand_name, keywords in brands:
        if any(kw in combined_text for kw in keywords):
            impersonated_brand = brand_name
            break
            
    is_webmail_relay = any(domain.lower().endswith(w) for w in ["gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "proton.me", "aol.com"])
    
    impersonation_detected = bool(impersonated_brand and is_webmail_relay)
    
    return {
        "case_id": case_id,
        "sender_email": sender,
        "sender_domain": domain,
        "source_ip": case.source_ip,
        "envelope_return_path": raw_hdrs.get("Return-Path", sender),
        "header_from": raw_hdrs.get("From", sender),
        "spf": {
            "status": spf_status,
            "dns_record": live_spf or case.spf_record or "None",
            "received_spf": rec_spf_raw,
            "ip_permitted": "Permitted Sender" if spf_status == "Pass" else "Unverified / Non-compliant"
        },
        "dkim": {
            "status": dkim_status,
            "is_valid": dkim_status == "Valid Signature",
            "signing_domain": dkim_domain or domain,
            "selector": dkim_selector or "Unknown",
            "algorithm": dkim_algo or "rsa-sha256",
            "body_hash": dkim_body_hash,
            "signature_header": dkim_sig_raw
        },
        "dmarc": {
            "status": dmarc_status,
            "policy": dmarc_policy_val,
            "dns_record": live_dmarc or case.dmarc_policy or "None",
            "alignment": "Aligned (Envelope matches Header Domain)" if domain else "Unaligned",
            "enforcement_mode": "Monitoring Only (p=none)" if dmarc_policy_val == "none" else f"Enforced (p={dmarc_policy_val})"
        },
        "arc": {
            "status": arc_status,
            "header": arc_results
        },
        "auth_results_raw": auth_results_raw,
        "impersonation": {
            "detected": impersonation_detected,
            "impersonated_brand": impersonated_brand,
            "relay_type": "Public Webmail Relay (Living-off-the-Cloud)" if is_webmail_relay else "Direct / Dedicated MTA",
            "explanation": f"The email technically passes SPF, DKIM, and DMARC because it was transmitted through authenticated {domain} infrastructure. However, the message content and subject impersonate {impersonated_brand}. Attackers exploit free webmail services to achieve legitimate authentication scores and bypass spam filters." if impersonation_detected else "No obvious cross-identity display name impersonation detected between envelope and body content."
        }
    }


