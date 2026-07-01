from __future__ import annotations
import re

PII_PATTERNS = {
    "email": (r'[\w.%+-]+@[\w.-]+\.[A-Za-z]{2,}', '***@***.***'),
    "phone": (r'\+\d{1,3}-\d{1,4}-\d{3,4}-\d{3,4}', '***-***-****'),
    "api_key": (r'(?:sk-|pk-|ghp_|gho_|ghu_|ghs_)[A-Za-z0-9]{10,}', '***-***'),
    "ip_address": (r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', '***.***.***.***'),
    "ssn": (r'\d{3}-\d{2}-\d{4}', '***-**-****'),
}

def mask_pii(text: str) -> str:
    for name, (pattern, replacement) in PII_PATTERNS.items():
        text = re.sub(pattern, replacement, text)
    return text

class PIIMask:
    @staticmethod
    def mask(text: str) -> str:
        return mask_pii(text)
    
    @staticmethod
    def mask_finding(finding_dict: dict) -> dict:
        masked = finding_dict.copy()
        for key in ("message", "snippet", "recommendation"):
            if key in masked and isinstance(masked[key], str):
                masked[key] = mask_pii(masked[key])
        return masked
