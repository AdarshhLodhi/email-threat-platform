from typing import Dict, Any
from datetime import datetime
import json

class ReportGeneratorService:
    @staticmethod
    def generate_forensic_report(case_data: Dict[str, Any]) -> str:
        """Generates a structured text report for the forensic case with live threat intelligence."""
        
        report = f"====================================================\n"
        report += f"FORENSIC EMAIL INVESTIGATION REPORT\n"
        report += f"Case ID: {case_data.get('id', 'N/A')}\n"
        report += f"Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC\n"
        report += f"====================================================\n\n"
        
        report += f"1. EXECUTIVE SUMMARY\n"
        report += f"--------------------\n"
        report += f"Subject: {case_data.get('subject', 'N/A')}\n"
        report += f"Sender: {case_data.get('sender_email', 'N/A')}\n"
        report += f"Recipient: {case_data.get('recipient_email', 'N/A')}\n"
        conf = case_data.get('confidence_score', 0) or 0
        report += f"Classification: {case_data.get('ai_classification', 'N/A')} (Confidence: {conf*100:.1f}%)\n"
        report += f"Investigation Status: {case_data.get('status', 'Open')}\n\n"
        
        report += f"2. INFRASTRUCTURE & GEOLOCATION INTELLIGENCE\n"
        report += f"--------------------------------------------\n"
        report += f"Originating IP: {case_data.get('source_ip', 'N/A')}\n"
        report += f"Physical Location: {case_data.get('geo_location', 'N/A')}\n"
        report += f"Network / ASN: {case_data.get('asn_info', 'N/A')}\n"
        lat = case_data.get('latitude')
        lon = case_data.get('longitude')
        if lat and lon:
            report += f"Coordinates: {lat:.4f}, {lon:.4f}\n"
        report += f"\n"
        
        report += f"3. AUTHENTICATION FORENSICS (SENDER IDENTITY)\n"
        report += f"---------------------------------------------\n"
        report += f"SPF Record: {'Pass / Found' if case_data.get('spf_record') else 'Fail / Missing'}\n"
        report += f"DKIM Signature: {'Valid' if case_data.get('dkim_valid') else 'Invalid / Unsigned'}\n"
        report += f"DMARC Policy: {'Configured (' + str(case_data.get('dmarc_policy')) + ')' if case_data.get('dmarc_policy') else 'None'}\n\n"
        
        report += f"4. THREAT INTELLIGENCE & IOC ANALYSIS\n"
        report += f"-------------------------------------\n"
        
        raw_domains = case_data.get('suspicious_domains')
        domains = []
        if raw_domains:
            try:
                domains = json.loads(raw_domains) if isinstance(raw_domains, str) else raw_domains
            except Exception:
                domains = []
                
        if domains:
            for idx, item in enumerate(domains, start=1):
                report += f"\n  [{idx}] Domain: {item.get('domain', 'Unknown')}\n"
                for r in item.get('reasons', []):
                    clean_r = str(r).replace("VirusTotal threat intel detected:", "Threat intelligence detected:").replace("VirusTotal", "Threat Intelligence")
                    report += f"      - Threat Flag: {clean_r}\n"
                vt = item.get('virustotal')
                if vt:
                    report += f"      - Scan Status: {vt.get('status', 'scanned')}\n"
                    report += f"      - Vendor Detections: {vt.get('malicious', 0)} Malicious, {vt.get('suspicious', 0)} Suspicious, {vt.get('harmless', 0)} Harmless\n"
                    if vt.get('reputation') is not None:
                        report += f"      - Reputation Score: {vt.get('reputation')}\n"
        else:
            report += f"No malicious domains flagged by threat intelligence engines or heuristics.\n"
            
        raw_urls = case_data.get('extracted_urls')
        urls = []
        if raw_urls:
            try:
                urls = json.loads(raw_urls) if isinstance(raw_urls, str) else raw_urls
            except Exception:
                urls = []
        if urls:
            report += f"\nExtracted URLs ({len(urls)}):\n"
            for u in urls[:10]:
                report += f"  - {u}\n"
            if len(urls) > 10:
                report += f"  ... and {len(urls) - 10} more\n"
        report += f"\n"
        
        report += f"5. FORENSIC ARTIFACTS (RAW HEADERS)\n"
        report += f"-----------------------------------\n"
        headers = case_data.get('raw_headers', 'N/A')
        if headers and len(str(headers)) > 500:
            headers = str(headers)[:500] + "... [TRUNCATED FOR REPORT]"
        report += f"{headers}\n\n"
        
        report += f"====================================================\n"
        report += f"END OF REPORT - THREATINTEL FORENSIC PLATFORM\n"
        report += f"====================================================\n"
        
        return report

    @staticmethod
    def generate_cyber_complaint(case_data: Dict[str, Any]) -> str:
        """Generates a boilerplate text for submitting a complaint to authorities."""
        
        complaint = f"To the Cyber Crime Investigation Cell,\n\n"
        complaint += f"I am reporting an email threat incident analyzed by our cyber forensic platform.\n\n"
        complaint += f"Incident Summary:\n"
        complaint += f"- Case ID: #{case_data.get('id', 'N/A')}\n"
        complaint += f"- Date Detected: {case_data.get('created_at', datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC'))}\n"
        complaint += f"- Incident Classification: {case_data.get('ai_classification', 'Threat')}\n"
        complaint += f"- Email Subject: {case_data.get('subject', 'N/A')}\n"
        complaint += f"- Purported Sender: {case_data.get('sender_email', 'N/A')}\n"
        complaint += f"- Originating IP: {case_data.get('source_ip', 'N/A')} (Location: {case_data.get('geo_location', 'N/A')})\n"
        complaint += f"- Network Provider: {case_data.get('asn_info', 'N/A')}\n"
        
        lat = case_data.get('latitude')
        lon = case_data.get('longitude')
        if lat and lon:
            complaint += f"- Verified GPS Coordinates: {lat:.4f}, {lon:.4f}\n"

        complaint += f"\nPlease find attached the comprehensive forensic report with threat intelligence indicators and raw headers.\n\n"
        complaint += f"Sincerely,\nThreat Intelligence Team"
        
        return complaint
