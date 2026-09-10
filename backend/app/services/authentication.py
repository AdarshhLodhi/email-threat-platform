import dns.resolver
import dkim
import re
from typing import Dict, Any, Optional

class AuthenticationService:
    @staticmethod
    def _get_resolver() -> dns.resolver.Resolver:
        resolver = dns.resolver.Resolver()
        resolver.nameservers = ['8.8.8.8', '1.1.1.1', '9.9.9.9']
        resolver.timeout = 3.0
        resolver.lifetime = 3.0
        return resolver

    @staticmethod
    def check_auth(raw_email_bytes: bytes, sender_domain: str, raw_headers: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Checks SPF, DKIM, and DMARC for a given email and domain."""
        
        # If full email passed, extract domain part
        if "@" in sender_domain:
            sender_domain = sender_domain.split("@")[-1].strip(">").strip()

        spf_record = AuthenticationService._check_spf(sender_domain)
        dmarc_policy = AuthenticationService._check_dmarc(sender_domain)
        
        # DKIM verification on raw bytes
        dkim_valid = False
        try:
            dkim_valid = dkim.verify(raw_email_bytes)
        except Exception:
            pass # DKIM check failed or not present
            
        # Parse authoritative MTA headers (Authentication-Results & Received-SPF) if available
        if raw_headers:
            auth_results = raw_headers.get("Authentication-Results", "")
            if isinstance(auth_results, list):
                auth_results = " ".join(auth_results)
            
            # If DKIM python-dkim failed due to encoding or body truncation, but MTA passed:
            if not dkim_valid and "dkim=pass" in auth_results.lower():
                dkim_valid = True
                
            rec_spf = raw_headers.get("Received-SPF", "")
            if isinstance(rec_spf, list):
                rec_spf = " ".join(rec_spf)
                
            if not spf_record:
                if "spf=pass" in auth_results.lower() or "pass" in rec_spf.lower():
                    spf_record = f"Pass (MTA Verified: {sender_domain})"
                elif "spf=fail" in auth_results.lower():
                    spf_record = f"Fail (MTA Verified: {sender_domain})"
            elif "spf=pass" in auth_results.lower() or "pass" in rec_spf.lower():
                if "(Pass)" not in spf_record:
                    spf_record = f"{spf_record} (Pass)"

            if not dmarc_policy:
                if "dmarc=pass" in auth_results.lower():
                    # extract policy p=...
                    p_match = re.search(r'p=(\w+)', auth_results, re.IGNORECASE)
                    p_val = p_match.group(1).lower() if p_match else "none"
                    dmarc_policy = f"p={p_val} (Pass via MTA)"
                elif "dmarc=fail" in auth_results.lower():
                    dmarc_policy = "Fail (MTA Policy Alignment Failed)"
            elif "dmarc=pass" in auth_results.lower():
                if "(Pass)" not in dmarc_policy:
                    dmarc_policy = f"{dmarc_policy} (Pass)"
            
        return {
            "spf_record": spf_record,
            "dkim_valid": dkim_valid,
            "dmarc_policy": dmarc_policy
        }
        
    @staticmethod
    def _check_spf(domain: str) -> Optional[str]:
        if not domain or "." not in domain:
            return None
        try:
            resolver = AuthenticationService._get_resolver()
            answers = resolver.resolve(domain, 'TXT')
            for rdata in answers:
                txt_record = rdata.to_text().strip('"')
                if txt_record.startswith("v=spf1"):
                    return txt_record
        except Exception:
            pass
        return None

    @staticmethod
    def _check_dmarc(domain: str) -> Optional[str]:
        if not domain or "." not in domain:
            return None
        try:
            resolver = AuthenticationService._get_resolver()
            answers = resolver.resolve(f"_dmarc.{domain}", 'TXT')
            for rdata in answers:
                txt_record = rdata.to_text().strip('"')
                if txt_record.startswith("v=DMARC1"):
                    return txt_record
        except Exception:
            pass
        return None

