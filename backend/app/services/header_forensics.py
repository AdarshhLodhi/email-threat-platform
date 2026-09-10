import re
from typing import Dict, Any, List

class HeaderForensicsService:
    @staticmethod
    def is_public_ip(ip: str) -> bool:
        """Checks if an IPv4 address is a routable public IP."""
        parts = ip.split('.')
        if len(parts) != 4:
            return False
        try:
            first = int(parts[0])
            second = int(parts[1])
            if first in (0, 10, 127):
                return False
            if first == 192 and second == 168:
                return False
            if first == 172 and (16 <= second <= 31):
                return False
            if first >= 224: # Multicast / reserved
                return False
            return True
        except ValueError:
            return False

    @staticmethod
    def analyze_headers(headers: Dict[str, Any]) -> Dict[str, Any]:
        """Analyzes email headers for forensic artifacts and extracts originating IP with multi-header forensics."""
        ip_pattern = re.compile(
            r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
        )

        originating_ip = None
        hop_ips: List[str] = []

        # 1. Check explicit client-ip in SPF / Authentication headers (Highest fidelity for sender MTA)
        auth_header_names = [
            "Received-SPF", "received-spf", 
            "Authentication-Results", "authentication-results", 
            "ARC-Authentication-Results", "arc-authentication-results"
        ]
        for name in auth_header_names:
            val = headers.get(name)
            if val:
                vals = val if isinstance(val, list) else [val]
                for v in vals:
                    str_v = str(v)
                    # Look for client-ip=1.2.3.4
                    match_client_ip = re.search(r'client-ip=([0-9.]+)', str_v, re.IGNORECASE)
                    if match_client_ip:
                        cip = match_client_ip.group(1)
                        if HeaderForensicsService.is_public_ip(cip):
                            if not originating_ip:
                                originating_ip = cip
                            hop_ips.append(cip)

                    # Look for designates 1.2.3.4 as permitted sender
                    match_designates = re.search(r'designates\s+([0-9.]+)', str_v, re.IGNORECASE)
                    if match_designates:
                        cip = match_designates.group(1)
                        if HeaderForensicsService.is_public_ip(cip):
                            if not originating_ip:
                                originating_ip = cip
                            hop_ips.append(cip)

        # 2. Check explicit originating/client IP headers
        originating_header_names = [
            "X-Originating-IP", "x-originating-ip",
            "X-Sender-IP", "x-sender-ip",
            "X-Client-IP", "x-client-ip",
            "X-Real-IP", "x-real-ip",
            "X-Original-IP", "x-original-ip",
            "X-Remote-IP", "x-remote-ip",
            "X-Forwarded-For", "x-forwarded-for"
        ]
        for name in originating_header_names:
            val = headers.get(name)
            if val:
                vals = val if isinstance(val, list) else [val]
                for v in vals:
                    found = ip_pattern.findall(str(v))
                    for ip in found:
                        if HeaderForensicsService.is_public_ip(ip):
                            if not originating_ip:
                                originating_ip = ip
                            hop_ips.append(ip)

        # 3. Check all 'Received' and 'X-Received' headers
        received_headers: List[str] = []
        for k, v in headers.items():
            if k.lower() in ("received", "x-received"):
                if isinstance(v, list):
                    received_headers.extend([str(item) for item in v])
                else:
                    received_headers.append(str(v))

        for line in received_headers:
            found = ip_pattern.findall(line)
            for ip in found:
                hop_ips.append(ip)
                if HeaderForensicsService.is_public_ip(ip) and not originating_ip:
                    originating_ip = ip

        # 4. Fallback search across all remaining header values for any public IP
        if not originating_ip:
            for k, v in headers.items():
                str_v = str(v)
                found = ip_pattern.findall(str_v)
                for ip in found:
                    if HeaderForensicsService.is_public_ip(ip):
                        originating_ip = ip
                        hop_ips.append(ip)
                        break
                if originating_ip:
                    break

        # Deduplicate while preserving order
        seen = set()
        unique_hop_ips = [x for x in hop_ips if not (x in seen or seen.add(x))]

        # If originating_ip still unset, pick the first public hop IP
        if not originating_ip:
            public_hops = [ip for ip in unique_hop_ips if HeaderForensicsService.is_public_ip(ip)]
            if public_hops:
                originating_ip = public_hops[0]
            elif unique_hop_ips:
                originating_ip = unique_hop_ips[0]

        # Look for anomalies (e.g., mismatched Return-Path and From)
        return_path = str(headers.get("Return-Path", "")).strip("<>")
        from_header = str(headers.get("From", ""))
        
        return_domain = return_path.split("@")[-1] if "@" in return_path else ""
        from_domain = from_header.split("@")[-1].strip("<>") if "@" in from_header else ""
        
        domain_mismatch = False
        if return_domain and from_domain and return_domain.lower() != from_domain.lower():
            domain_mismatch = True
            
        x_mailer = str(headers.get("X-Mailer", ""))
            
        return {
            "hop_ips": unique_hop_ips,
            "originating_ip": originating_ip,
            "return_path": return_path,
            "domain_mismatch": domain_mismatch,
            "x_mailer": x_mailer
        }
