from sqlalchemy import Column, Integer, String, Float, Boolean, ForeignKey, DateTime
from sqlalchemy.orm import relationship
from app.database import Base
from datetime import datetime

class ThreatCase(Base):
    __tablename__ = "threat_cases"

    id = Column(Integer, primary_key=True, index=True)
    status = Column(String, default="Open") # Open, Investigating, Closed
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # ML Classification
    ai_classification = Column(String) # Phishing, Malware, Spam, Benign
    confidence_score = Column(Float)
    
    # Forensic Details
    sender_email = Column(String, index=True)
    recipient_email = Column(String)
    subject = Column(String)
    raw_headers = Column(String)
    body_content = Column(String)
    
    # Auth Checks
    spf_record = Column(String)
    dkim_valid = Column(Boolean)
    dmarc_policy = Column(String)
    
    # Geolocation & Infrastructure
    source_ip = Column(String)
    geo_location = Column(String) # e.g., "Moscow, RU"
    asn_info = Column(String)
    latitude = Column(Float, nullable=True)
    longitude = Column(Float, nullable=True)
    
    # Extracted IOCs (Indicators of Compromise)
    extracted_urls = Column(String) # Comma-separated or JSON string
    suspicious_domains = Column(String)
    
    # Relationships
    evidence = relationship("Evidence", back_populates="threat_case")

class Evidence(Base):
    __tablename__ = "evidence"

    id = Column(Integer, primary_key=True, index=True)
    case_id = Column(Integer, ForeignKey("threat_cases.id"))
    evidence_type = Column(String) # Screenshot, Whois Record, Geolocation Map
    description = Column(String)
    file_path = Column(String) # Path to saved evidence file
    created_at = Column(DateTime, default=datetime.utcnow)

    threat_case = relationship("ThreatCase", back_populates="evidence")
