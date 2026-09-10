import httpx
import os
import base64
from typing import Dict, Any, Optional
from dotenv import load_dotenv

load_dotenv()

class VirusTotalService:
    BASE_URL = "https://www.virustotal.com/api/v3"

    DEFAULT_API_KEY = "23fd38ef1d87e445bba82cdfd469115d1642937f315b7f16d6a9be1a641080e5"

    @classmethod
    def get_api_key(cls) -> Optional[str]:
        key = os.getenv("VIRUSTOTAL_API_KEY")
        if key and key.strip() and key != "your_virustotal_api_key_here":
            return key.strip()
        return cls.DEFAULT_API_KEY

    @classmethod
    async def check_domain(cls, domain: str) -> Dict[str, Any]:
        """Queries VirusTotal v3 API for domain reputation and threat statistics."""
        api_key = cls.get_api_key()
        if not api_key:
            return {
                "configured": False,
                "domain": domain,
                "status": "api_key_missing"
            }

        headers = {"x-apikey": api_key}
        url = f"{cls.BASE_URL}/domains/{domain}"

        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.get(url, headers=headers)
                if response.status_code == 200:
                    data = response.json()
                    attributes = data.get("data", {}).get("attributes", {})
                    stats = attributes.get("last_analysis_stats", {})
                    
                    malicious = stats.get("malicious", 0)
                    suspicious = stats.get("suspicious", 0)
                    harmless = stats.get("harmless", 0)
                    undetected = stats.get("undetected", 0)
                    reputation = attributes.get("reputation", 0)
                    
                    is_threat = (malicious > 0 or suspicious > 0 or reputation < 0)
                    
                    return {
                        "configured": True,
                        "domain": domain,
                        "status": "scanned",
                        "is_threat": is_threat,
                        "malicious": malicious,
                        "suspicious": suspicious,
                        "harmless": harmless,
                        "undetected": undetected,
                        "reputation": reputation,
                        "categories": attributes.get("categories", {}),
                        "details": f"VirusTotal flagged {malicious} malicious and {suspicious} suspicious vendor detections." if is_threat else "Domain verified clean by VirusTotal engines."
                    }
                elif response.status_code == 404:
                    return {
                        "configured": True,
                        "domain": domain,
                        "status": "not_found",
                        "is_threat": False,
                        "details": "Domain not currently cataloged in VirusTotal database."
                    }
                else:
                    return {
                        "configured": True,
                        "domain": domain,
                        "status": f"http_{response.status_code}",
                        "is_threat": False
                    }
        except Exception as e:
            print(f"VirusTotal domain lookup error for {domain}: {e}")
            return {
                "configured": True,
                "domain": domain,
                "status": "error",
                "is_threat": False,
                "error": str(e)
            }

    @classmethod
    async def check_ip(cls, ip_address: str) -> Dict[str, Any]:
        """Queries VirusTotal v3 API for IP reputation and security vendor flags."""
        api_key = cls.get_api_key()
        if not api_key:
            return {"configured": False, "ip": ip_address, "status": "api_key_missing"}

        headers = {"x-apikey": api_key}
        url = f"{cls.BASE_URL}/ip_addresses/{ip_address}"

        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.get(url, headers=headers)
                if response.status_code == 200:
                    data = response.json()
                    attributes = data.get("data", {}).get("attributes", {})
                    stats = attributes.get("last_analysis_stats", {})
                    
                    malicious = stats.get("malicious", 0)
                    suspicious = stats.get("suspicious", 0)
                    harmless = stats.get("harmless", 0)
                    undetected = stats.get("undetected", 0)
                    reputation = attributes.get("reputation", 0)
                    as_owner = attributes.get("as_owner", "")
                    
                    is_threat = (malicious > 0 or suspicious > 0 or reputation < 0)
                    
                    return {
                        "configured": True,
                        "ip": ip_address,
                        "status": "scanned",
                        "is_threat": is_threat,
                        "malicious": malicious,
                        "suspicious": suspicious,
                        "harmless": harmless,
                        "undetected": undetected,
                        "reputation": reputation,
                        "as_owner": as_owner,
                        "details": f"VirusTotal flagged {malicious} security vendor detections for this IP." if is_threat else "IP reputation clean on VirusTotal."
                    }
                elif response.status_code == 404:
                    return {
                        "configured": True,
                        "ip": ip_address,
                        "status": "not_found",
                        "is_threat": False
                    }
                else:
                    return {
                        "configured": True,
                        "ip": ip_address,
                        "status": f"http_{response.status_code}",
                        "is_threat": False
                    }
        except Exception as e:
            print(f"VirusTotal IP lookup error for {ip_address}: {e}")
            return {"configured": True, "ip": ip_address, "status": "error", "error": str(e)}
