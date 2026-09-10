from fastapi import APIRouter
from app.services.virustotal import VirusTotalService
from app.services.geolocation import GeolocationService
from app.services.abuseipdb import AbuseIPDBService

router = APIRouter()

@router.get("/virustotal/domain/{domain}")
async def check_virustotal_domain(domain: str):
    """Query VirusTotal v3 for domain reputation and vendor flags."""
    return await VirusTotalService.check_domain(domain)

@router.get("/virustotal/ip/{ip_address}")
async def check_virustotal_ip(ip_address: str):
    """Query VirusTotal v3 for IP reputation and vendor flags."""
    return await VirusTotalService.check_ip(ip_address)

@router.get("/abuseipdb/{ip_address}")
async def lookup_abuseipdb(ip_address: str, max_age_days: int = 90):
    """Query AbuseIPDB API v2 for IP abuse confidence score, reports, usage type, and Tor exit flags."""
    return await AbuseIPDBService.check_ip(ip_address, max_age_in_days=max_age_days)

@router.get("/ipinfo/{ip_address}")
async def lookup_ipinfo(ip_address: str):
    """Query IPinfo.io using the authorized Bearer token for ASN, hostname, location, and network details."""
    return await GeolocationService.get_ipinfo_data(ip_address)

@router.get("/ipgeo/{ip_address}")
async def lookup_ip_geolocation(ip_address: str):
    """Query primary intelligence (IPinfo.io) with automatic fallback for IP details."""
    return await GeolocationService.get_ip_info(ip_address)
