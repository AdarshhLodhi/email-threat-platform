import urllib.parse
from typing import List, Dict, Any
from app.services.virustotal import VirusTotalService

class DomainAnalysisService:
    @staticmethod
    async def analyze_domains(urls: List[str], sender_domain: str) -> Dict[str, Any]:
        """Analyzes domains extracted from URLs for suspicious characteristics and queries VirusTotal."""
        suspicious_domains = []
        extracted_domains = set()
        
        for url in urls:
            try:
                parsed_uri = urllib.parse.urlparse(url)
                domain = parsed_uri.netloc.lower()
                
                # Strip port if present
                if ":" in domain:
                    domain = domain.split(":")[0]
                    
                if domain:
                    extracted_domains.add(domain)
            except Exception:
                continue
                
        # Basic heuristic checks for suspicious domains
        for domain in extracted_domains:
            suspicious = False
            reasons = []
            vt_info = None
            
            # Check 1: Very long domain names
            if len(domain) > 40:
                suspicious = True
                reasons.append("Unusually long domain name")
                
            # Check 2: IP address instead of domain
            if domain.replace(".", "").isnumeric():
                suspicious = True
                reasons.append("IP address used as domain")
                
            # Check 3: Free dynamic DNS providers
            ddns_providers = ["duckdns.org", "no-ip.org", "dynu.net", "freedns.afraid.org"]
            if any(domain.endswith(provider) for provider in ddns_providers):
                suspicious = True
                reasons.append("Uses dynamic DNS provider often associated with malicious activity")
                
            # Check 4: VirusTotal Live Threat Intelligence lookup
            try:
                vt_res = await VirusTotalService.check_domain(domain)
                if vt_res.get("configured") and vt_res.get("status") == "scanned":
                    vt_info = vt_res
                    if vt_res.get("is_threat"):
                        suspicious = True
                        mal_count = vt_res.get("malicious", 0)
                        susp_count = vt_res.get("suspicious", 0)
                        reasons.append(
                            f"VirusTotal threat intel detected: {mal_count} security vendors flagged as malicious, {susp_count} suspicious"
                        )
            except Exception as e:
                print(f"Error querying VirusTotal for domain {domain}: {e}")
                
            if suspicious:
                item = {
                    "domain": domain,
                    "reasons": reasons
                }
                if vt_info:
                    item["virustotal"] = vt_info
                suspicious_domains.append(item)
                
        return {
            "all_extracted_domains": list(extracted_domains),
            "suspicious_domains": suspicious_domains
        }
