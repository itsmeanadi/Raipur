import json
import re
from dataclasses import dataclass, field
from typing import List, Set, Any

@dataclass
class Scope:
    allowed_tools: Set[str] = field(default_factory=set)
    allowed_paths: List[str] = field(default_factory=lambda: ["documents"])
    allowed_recipients: Set[str] = field(default_factory=set)
    intent: str = ""

def extract(user_msg: str) -> Scope:
    """Extract scope from the user message only using deterministic fallback."""
    user_msg_lower = user_msg.lower()
    scope = Scope(
        allowed_tools={"read_file", "search_web"},  # defaults
        allowed_paths=["documents"],
        allowed_recipients=set(),
        intent=user_msg
    )

    # Keyword to tool mapping
    send_email_synonyms = r'\b(email|send|drop a line|forward|mail|notify|share with)\b'
    if re.search(send_email_synonyms, user_msg_lower):
        scope.allowed_tools.add("send_email")
        
    write_record_synonyms = r'\b(log|save|store|record)\b'
    if re.search(write_record_synonyms, user_msg_lower):
        scope.allowed_tools.add("write_record")

    # Extract emails
    emails = set(re.findall(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+', user_msg))
    scope.allowed_recipients.update(emails)

    # Extract paths - very simple heuristic: look for .txt
    paths = set(re.findall(r'[\w/\\.-]+\.txt', user_msg))
    for p in paths:
        if p not in scope.allowed_paths:
            scope.allowed_paths.append(p)
            
    return scope
