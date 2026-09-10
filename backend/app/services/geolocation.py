import httpx
import os
import asyncio
from typing import Dict, Any, Optional
from dotenv import load_dotenv

load_dotenv()

class GeolocationService:
    # IPinfo.io API endpoints
    IPINFO_BASE_URL = "https://ipinfo.io"
    IPINFO_LITE_URL = "https://api.ipinfo.io/lite"
    DEFAULT_IPINFO_TOKEN = "0f83e80b989660"

    # IPGeolocation.io API endpoint (fallback)
    IPGEO_API_URL = "https://api.ipgeolocation.io/ipgeo"
    DEFAULT_IPGEO_API_KEY = "0d5125f5ffec44f4bb9de281454a67e5"

    # Secondary public fallback
    FALLBACK_URL = "http://ip-api.com/json/"

    @classmethod
    def get_ipinfo_token(cls) -> str:
        token = os.getenv("IPINFO_TOKEN") or os.getenv("IPINFO_API_KEY")
        if token and token.strip() and token != "your_ipinfo_token_here":
            return token.strip()
        return cls.DEFAULT_IPINFO_TOKEN

    @classmethod
    def get_ipgeo_key(cls) -> str:
        key = os.getenv("IPGEOLOCATION_API_KEY") or os.getenv("IP_API_KEY")
        if key and key.strip() and key != "your_ipgeolocation_api_key_here":
            return key.strip()
        return cls.DEFAULT_IPGEO_API_KEY

    @classmethod
    async def get_ipinfo_data(cls, ip_address: str) -> Dict[str, Any]:
        """
        Directly queries IPinfo.io using Bearer token authentication.
        Concurrently queries both the standard IPinfo endpoint (for geolocation, coordinates, reverse PTR hostname)
        and the IPinfo Lite endpoint (for ASN, domain, and full country/continent taxonomy).
        """
        token = cls.get_ipinfo_token()
        headers = {"Authorization": f"Bearer {token}"} if token else {}

        async with httpx.AsyncClient(timeout=8.0) as client:
            std_task = client.get(f"{cls.IPINFO_BASE_URL}/{ip_address}", headers=headers)
            lite_task = client.get(f"{cls.IPINFO_LITE_URL}/{ip_address}", headers=headers)
            
            res_std, res_lite = await asyncio.gather(std_task, lite_task, return_exceptions=True)

            std_data = res_std.json() if not isinstance(res_std, Exception) and res_std.status_code == 200 else {}
            lite_data = res_lite.json() if not isinstance(res_lite, Exception) and res_lite.status_code == 200 else {}

            if not std_data and not lite_data:
                raise RuntimeError(f"IPinfo query returned no data for {ip_address}")

            city = std_data.get("city") or ""
            region = std_data.get("region") or ""
            country_name = lite_data.get("country") or std_data.get("country") or ""
            country_code = lite_data.get("country_code") or std_data.get("country") or ""
            
            location_parts = [p for p in [city, region, country_name] if p]
            geo_location = ", ".join(location_parts) or "Unknown Location"

            lat, lon = 0.0, 0.0
            if std_data.get("loc") and "," in str(std_data["loc"]):
                try:
                    parts = str(std_data["loc"]).split(",")
                    lat = float(parts[0])
                    lon = float(parts[1])
                except Exception:
                    lat, lon = 0.0, 0.0

            asn = lite_data.get("asn") or (std_data.get("org", "").split()[0] if std_data.get("org") else "")
            as_name = lite_data.get("as_name") or (" ".join(std_data.get("org", "").split()[1:]) if std_data.get("org") else "")
            asn_info = std_data.get("org") or f"{asn} {as_name}".strip() or "Unknown Network"

            return {
                "geo_location": geo_location,
                "asn_info": asn_info,
                "asn": asn,
                "as_name": as_name,
                "as_domain": lite_data.get("as_domain", ""),
                "lat": lat,
                "lon": lon,
                "country": country_name,
                "country_code": country_code,
                "continent": lite_data.get("continent", ""),
                "city": city,
                "region": region,
                "state": region,
                "hostname": std_data.get("hostname", ""),
                "timezone": std_data.get("timezone", ""),
                "postal": std_data.get("postal", ""),
                "anycast": std_data.get("anycast", False),
                "provider": "ipinfo.io"
            }

    @classmethod
    async def get_ip_info(cls, ip_address: str) -> Dict[str, Any]:
        """
        Primary entry point: Fetches high-fidelity geolocation, ASN, and coordinate information.
        Prioritizes IPinfo.io with Bearer token, then falls back to IPGeolocation.io, then ip-api.com.
        """
        # If it's a private or loopback IP, return local network data
        if (
            not ip_address
            or ip_address.startswith("10.") 
            or ip_address.startswith("192.168.") 
            or ip_address == "127.0.0.1"
            or ip_address.startswith("172.16.")
            or ip_address.startswith("172.31.")
            or ip_address.startswith("169.254.")
        ):
            return {
                "geo_location": "Local Network",
                "asn_info": "Private IP Space",
                "lat": 0.0,
                "lon": 0.0,
                "country": "N/A",
                "city": "Internal",
                "state": "Local",
                "hostname": "localhost",
                "provider": "local"
            }

        # 1. Primary: Try IPinfo.io with User Token
        try:
            ipinfo_result = await cls.get_ipinfo_data(ip_address)
            if ipinfo_result and (ipinfo_result.get("lat") != 0.0 or ipinfo_result.get("asn_info") != "Unknown Network"):
                return ipinfo_result
        except Exception as e:
            print(f"IPinfo.io lookup error for {ip_address}: {e}")

        # 2. Secondary Fallback: Try IPGeolocation.io if key is present
        ipgeo_key = cls.get_ipgeo_key()
        if ipgeo_key:
            try:
                async with httpx.AsyncClient(timeout=6.0) as client:
                    response = await client.get(
                        f"{cls.IPGEO_API_URL}?apiKey={ipgeo_key}&ip={ip_address}"
                    )
                    if response.status_code == 200:
                        data = response.json()
                        city = data.get("city") or ""
                        state = data.get("state_prov") or ""
                        country = data.get("country_name") or ""
                        
                        location_parts = [p for p in [city, state, country] if p]
                        geo_location = ", ".join(location_parts) or "Unknown Location"
                        
                        asn_info = (
                            data.get("isp") 
                            or data.get("organization") 
                            or (f"AS{data.get('asn')}" if data.get("asn") else "")
                            or "Unknown Network"
                        )
                        
                        lat = float(data.get("latitude")) if data.get("latitude") is not None else 0.0
                        lon = float(data.get("longitude")) if data.get("longitude") is not None else 0.0
                        
                        return {
                            "geo_location": geo_location,
                            "asn_info": asn_info,
                            "lat": lat,
                            "lon": lon,
                            "country": country or "Unknown",
                            "city": city,
                            "state": state,
                            "hostname": "",
                            "provider": "ipgeolocation.io"
                        }
            except Exception as e:
                print(f"IPGeolocation.io lookup error for {ip_address}: {e}")

        # 3. Tertiary Fallback: ip-api.com
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                response = await client.get(f"{cls.FALLBACK_URL}{ip_address}")
                if response.status_code == 200:
                    data = response.json()
                    if data.get("status") == "success":
                        geo_location = f"{data.get('city', '')}, {data.get('country', '')}".strip(", ")
                        asn_info = data.get('as', '')
                        
                        return {
                            "geo_location": geo_location,
                            "asn_info": asn_info,
                            "lat": data.get("lat", 0.0),
                            "lon": data.get("lon", 0.0),
                            "country": data.get("country", "Unknown"),
                            "city": data.get("city", ""),
                            "state": data.get("regionName", ""),
                            "hostname": "",
                            "provider": "ip-api.com"
                        }
        except Exception as e:
            print(f"Fallback IP lookup error for {ip_address}: {e}")
            
        # 4. Final Fallback for demo / offline mode
        return {
            "geo_location": "Unknown Location (Demo Fallback)",
            "asn_info": "AS0000 Unknown Network",
            "lat": 0.0,
            "lon": 0.0,
            "country": "Unknown",
            "city": "",
            "state": "",
            "hostname": "",
            "provider": "fallback"
        }
