import re
import base64
import urllib.parse
import codecs
from typing import Tuple, List, Dict, Any

def decode_passes(text: str, depth: int = 0) -> str:
    if depth >= 2:
        return text

    # Strip zero-width chars and bidi chars
    text = re.sub(r'[\u200B-\u200D\uFEFF\u200E\u200F\u202A-\u202E]', '', text)
    
    # Base64
    def replace_b64(m):
        try:
            dec = base64.b64decode(m.group(0)).decode('utf-8')
            return f" [DECODED_B64: {decode_passes(dec, depth + 1)}] "
        except:
            return m.group(0)
    text = re.sub(r'[A-Za-z0-9+/]{20,}={0,2}', replace_b64, text)
    
    # Hex
    def replace_hex(m):
        try:
            dec = bytes.fromhex(m.group(0)).decode('utf-8')
            return f" [DECODED_HEX: {decode_passes(dec, depth + 1)}] "
        except:
            return m.group(0)
    text = re.sub(r'(?:[0-9a-fA-F]{2}){10,}', replace_hex, text)
    
    # URL
    unquoted = urllib.parse.unquote(text)
    if unquoted != text:
        text = unquoted

    # HTML comments
    text = re.sub(r'<!--(.*?)-->', lambda m: f" [HTML_COMMENT: {decode_passes(m.group(1), depth + 1)}] ", text, flags=re.DOTALL)
    
    # Rot13: Append the rot13 version of the string so the regex can catch it
    # We do it only at depth 0 to avoid exponential growth
    if depth == 0:
        text = text + " [ROT13: " + codecs.encode(text, 'rot_13') + "] "

    return text

def scan(text: str, source: str) -> Tuple[str, List[Dict[str, Any]], float]:
    findings = []
    
    # 1. Decode
    decoded_text = decode_passes(text)
    
    # 2. Heuristics
    patterns = [
        (r"(?i)ignore\s+(all\s+)?previous\s+instructions", "rule_ignore_instructions"),
        (r"(?i)system:/?\[?system\]?|<system>", "rule_fake_system_header"),
        (r"(?i)do\s+not\s+tell\s+the\s+user", "rule_concealment"),
        (r"(?i)(email|send|forward)\s+(it\s+to\s+)?[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+", "rule_imperative_exfil"),
    ]
    
    sanitized = text
    # Scan the decoded text
    for pattern, rule_name in patterns:
        for m in re.finditer(pattern, decoded_text):
            findings.append({
                "rule": rule_name,
                "span": m.span(),
                "evidence": m.group(0),
                "severity": "HIGH"
            })
            # To sanitize, we must replace in the ORIGINAL text too, 
            # but since the attack is encoded, we just remove the whole original text or wrap it.
            # A simple approach: if we found something in decoded text, we just scrub the whole input 
            # or replace the entire text with a removal marker.
            sanitized = "[REMOVED: suspected injected instruction]"
            
    risk_score = 1.0 if findings else 0.0
    return sanitized, findings, risk_score
