import email
from email.policy import default
import re
from typing import Dict, Any

class EmailParserService:
    @staticmethod
    def parse_raw_email(raw_content: str) -> Dict[str, Any]:
        """Parses a raw email string into its constituent parts preserving all header values."""
        msg = email.message_from_string(raw_content, policy=default)
        
        # Extract basic info
        sender = msg.get("From", "")
        recipient = msg.get("To", "")
        subject = msg.get("Subject", "")
        
        # Extract raw headers preserving duplicate headers (e.g. multiple 'Received' headers)
        headers = {}
        for k, v in msg.items():
            str_v = str(v)
            if k in headers:
                if isinstance(headers[k], list):
                    headers[k].append(str_v)
                else:
                    headers[k] = [headers[k], str_v]
            else:
                headers[k] = str_v
        
        # Extract body
        body_content = ""
        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                content_disposition = str(part.get("Content-Disposition"))
                
                if content_type == "text/plain" and "attachment" not in content_disposition:
                    try:
                        body_content += part.get_payload(decode=True).decode(part.get_content_charset('utf-8'), errors='replace')
                    except Exception:
                        pass
                elif content_type == "text/html" and not body_content and "attachment" not in content_disposition:
                    try:
                        body_content += part.get_payload(decode=True).decode(part.get_content_charset('utf-8'), errors='replace')
                    except Exception:
                        pass
        else:
            try:
                body_content = msg.get_payload(decode=True).decode(msg.get_content_charset('utf-8'), errors='replace')
            except Exception:
                pass
                
        # Basic URL extraction
        urls = re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', body_content)
        
        return {
            "sender_email": sender,
            "recipient_email": recipient,
            "subject": subject,
            "raw_headers": headers,
            "body_content": body_content,
            "extracted_urls": urls
        }
