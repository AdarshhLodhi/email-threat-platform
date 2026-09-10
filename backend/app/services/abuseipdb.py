import httpx
import os
from typing import Dict, Any, Optional, List
from dotenv import load_dotenv

load_dotenv()

class AbuseIPDBService:
    BASE_URL = "https://api.abuseipdb.com/api/v2"
    DEFAULT_API_KEY = "88715977c60d19c908655f98621dfd10554c07e405ac848007e55fdd4de1280b2d9547fc482be356"

    # Standard AbuseIPDB report category mapping
    CATEGORIES = {
        1: "DNS Compromise",
        2: "DNS Poisoning",
        3: "Fraud Orders",
        4: "DDoS Attack",
        5: "FTP Brute-Force",
        6: "Ping of Death",
        7: "Phishing",
        8: "Fraud VoIP",
        9: "Open Proxy",
        10: "Web Spam",
        11: "Email Spam",
        12: "Blog Spam",
        13: "VPN IP",
        14: "Port Scan",
        15: "Hacking",
        16: "SQL Injection",
        17: "Spoofing",
        18: "Brute-Force",
        19: "Bad Web Bot",
        20: "Exploited Host",
        21: "Web App Attack",
        22: "SSH",
        23: "IoT Targeted"
    }

    @classmethod
    def get_api_key(cls) -> str:
        key = os.getenv("ABUSEIPDB_API_KEY")
        if key and key.strip() and key != "your_abuseipdb_api_key_here":
            return key.strip()
        return cls.DEFAULT_API_KEY

    @classmethod
    def is_private_ip(cls, ip: str) -> bool:
        if not ip:
            return True
        return (
            ip.startswith("10.") 
            or ip.startswith("192.168.") 
            or ip == "127.0.0.1" 
            or ip == "localhost"
            or ip.startswith("172.16.")
            or ip.startswith("172.31.")
            or ip.startswith("169.254.")
        )

    @classmethod
    async def check_ip(cls, ip_address: str, max_age_in_days: int = 90, verbose: bool = True) -> Dict[str, Any]:
        """
        Queries AbuseIPDB API v2 to evaluate IP abuse confidence, reporting history,
        usage type, Tor status, and security flags.
        """
        if not ip_address:
            return {
                "configured": True,
                "ip": "",
                "status": "empty_ip",
                "is_threat": False,
                "abuse_confidence_score": 0,
                "total_reports": 0,
                "verdict": "Invalid IP",
                "details": "No IP address specified."
            }

        if cls.is_private_ip(ip_address):
            return {
                "configured": True,
                "ip": ip_address,
                "status": "private_network",
                "is_threat": False,
                "abuse_confidence_score": 0,
                "total_reports": 0,
                "distinct_users": 0,
                "usage_type": "Private / RFC 1918 Network",
                "isp": "Local Network",
                "domain": "local",
                "is_tor": False,
                "is_whitelisted": True,
                "country_name": "Local Network",
                "country_code": "N/A",
                "last_reported_at": None,
                "verdict": "Private IP Space",
                "details": "Non-routable private IP address. Excluded from global threat databases.",
                "reports": []
            }

        api_key = cls.get_api_key()
        if not api_key:
            return {
                "configured": False,
                "ip": ip_address,
                "status": "api_key_missing",
                "is_threat": False,
                "abuse_confidence_score": 0,
                "total_reports": 0,
                "verdict": "Unchecked",
                "details": "AbuseIPDB API key is not configured."
            }

        headers = {
            "Key": api_key,
            "Accept": "application/json"
        }
        params = {
            "ipAddress": ip_address,
            "maxAgeInDays": max_age_in_days,
            "verbose": verbose
        }

        try:
            async with httpx.AsyncClient(timeout=8.0) as client:
                response = await client.get(f"{cls.BASE_URL}/check", headers=headers, params=params)
                
                if response.status_code == 200:
                    data = response.json().get("data", {})
                    abuse_score = data.get("abuseConfidenceScore", 0)
                    total_reports = data.get("totalReports", 0)
                    distinct_users = data.get("numDistinctUsers", 0)
                    usage_type = data.get("usageType") or "Unknown"
                    isp = data.get("isp") or "Unknown ISP"
                    domain = data.get("domain") or ""
                    is_tor = bool(data.get("isTor", False))
                    is_whitelisted = bool(data.get("isWhitelisted", False))
                    country_name = data.get("countryName") or ""
                    country_code = data.get("countryCode") or ""
                    last_reported_at = data.get("lastReportedAt")

                    is_threat = (abuse_score > 0 or total_reports > 0) and not is_whitelisted

                    if abuse_score >= 50:
                        verdict = "High Risk Malicious"
                    elif abuse_score > 0 or total_reports > 0:
                        verdict = "Suspicious Abuse Activity"
                    else:
                        verdict = "Clean / Low Risk"

                    # Parse recent reports
                    raw_reports = data.get("reports", [])
                    parsed_reports: List[Dict[str, Any]] = []
                    for r in raw_reports[:10]:
                        category_names = [cls.CATEGORIES.get(c, f"Category {c}") for c in r.get("categories", [])]
                        parsed_reports.append({
                            "reported_at": r.get("reportedAt"),
                            "comment": r.get("comment") or "No comment provided",
                            "categories": category_names,
                            "reporter_id": r.get("reporterId")
                        })

                    details = (
                        f"AbuseIPDB logged {total_reports} abuse reports ({abuse_score}% confidence score). "
                        f"Infrastructure: {usage_type} ({isp})."
                        if is_threat else
                        f"No active abuse reports in past {max_age_in_days} days. Confidence score: {abuse_score}%."
                    )

                    return {
                        "configured": True,
                        "ip": ip_address,
                        "status": "scanned",
                        "is_threat": is_threat,
                        "abuse_confidence_score": abuse_score,
                        "total_reports": total_reports,
                        "distinct_users": distinct_users,
                        "usage_type": usage_type,
                        "isp": isp,
                        "domain": domain,
                        "is_tor": is_tor,
                        "is_whitelisted": is_whitelisted,
                        "country_name": country_name,
                        "country_code": country_code,
                        "last_reported_at": last_reported_at,
                        "verdict": verdict,
                        "details": details,
                        "reports": parsed_reports
                    }
                elif response.status_code == 429:
                    return {
                        "configured": True,
                        "ip": ip_address,
                        "status": "rate_limited",
                        "is_threat": False,
                        "abuse_confidence_score": 0,
                        "total_reports": 0,
                        "verdict": "Rate Limited",
                        "details": "AbuseIPDB request limit reached. Falling back to cached and local reputation."
                    }
                else:
                    return {
                        "configured": True,
                        "ip": ip_address,
                        "status": f"http_{response.status_code}",
                        "is_threat": False,
                        "abuse_confidence_score": 0,
                        "total_reports": 0,
                        "verdict": "Scan Error",
                        "details": f"AbuseIPDB returned HTTP {response.status_code}."
                    }
        except Exception as e:
            print(f"AbuseIPDB lookup error for {ip_address}: {e}")
            return {
                "configured": True,
                "ip": ip_address,
                "status": "error",
                "is_threat": False,
                "abuse_confidence_score": 0,
                "total_reports": 0,
                "verdict": "Error",
                "details": f"Failed to contact AbuseIPDB API: {str(e)}",
                "error": str(e)
            }
