import json
import time
import os

AUDIT_FILE = "audit.jsonl"

def log(ts: float, request_id: str, layer: str, rule: str, decision: str, evidence_snippet: str, reason: str, latency_ms: float):
    record = {
        "ts": ts,
        "request_id": request_id,
        "layer": layer,
        "rule": rule,
        "decision": decision,
        "evidence_snippet": evidence_snippet,
        "reason": reason,
        "latency_ms": latency_ms
    }
    # Keep it simple and just append
    base_dir = os.path.dirname(__file__)
    file_path = os.path.join(base_dir, AUDIT_FILE)
    try:
        with open(file_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(record) + "\n")
    except Exception:
        pass

def read_all():
    base_dir = os.path.dirname(__file__)
    file_path = os.path.join(base_dir, AUDIT_FILE)
    if not os.path.exists(file_path):
        return []
    res = []
    with open(file_path, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                res.append(json.loads(line))
    return res
