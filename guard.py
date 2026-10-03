import re
from dataclasses import dataclass
from typing import Dict, Any

@dataclass
class Decision:
    decision: str  # ALLOW, BLOCK, ASK
    rule: str
    reason: str
    evidence: str

def check(call: Dict[str, Any], scope, ctx: Dict[str, Any], user_msg: str, session_taint: bool = False) -> Decision:
    name = call.get("name")
    args = call.get("args", {})

    # Helper for taint tracking: string not in user message
    def is_tainted(val: str) -> bool:
        return val not in user_msg

    # Taint & Provenance Tracking (Session Taint)
    session_tainted = bool(session_taint or ctx.get("session_taint", False) or len(ctx.get("confidential_reads", [])) > 0)
    if session_tainted:
        if name in ["send_email", "write_record"]:
            rule = "7_session_taint_email" if name == "send_email" else "7_session_taint_record"
            return Decision("BLOCK", rule, "Data-Flow Violation: Tainted context", name)
        elif name == "search_web":
            q = args.get("query", "")
            if is_tainted(q) and (len(q) > 60 or len(set(q)) > 25):
                return Decision("BLOCK", "7_session_taint_search", "Data-Flow Violation: Tainted context", q[:20])

    # Rule 2: Path restrictions
    if name == "read_file":
        import os
        from pathlib import Path
        path = args.get("path", "")
        base_dir = Path(__file__).parent.resolve()
        resolved_path = os.path.realpath(os.path.join(base_dir, path))
        allowed_resolved = [os.path.realpath(os.path.join(base_dir, p)) for p in scope.allowed_paths]

        # Allow if user explicitly named it
        if resolved_path not in allowed_resolved:
            # Check if it starts with allowed default dir
            if not any(resolved_path.startswith(p) for p in allowed_resolved):
                return Decision("BLOCK", "2_path_outside_scope", "Path not in allowed_paths.", path)
            fake_conf_dir = os.path.realpath(os.path.join(base_dir, "fake_confidential"))
            if resolved_path.startswith(fake_conf_dir):
                return Decision("BLOCK", "2_path_confidential", "Access to fake_confidential is forbidden.", path)

    # Rule 1: Tool not in scope
    if name not in scope.allowed_tools:
        return Decision("BLOCK", "1_out_of_scope_tool", f"Tool {name} not allowed by scope.", name)

    # Rule 3: send_email recipient
    if name == "send_email":
        to = args.get("to", "")
        if to not in scope.allowed_recipients:
            if not to:
                return Decision("ASK_HUMAN", "3_missing_recipient", "No recipient specified, ask user.", "")
            elif is_tainted(to):
                return Decision("BLOCK", "3_tainted_recipient", "Recipient not in user message, potentially from untrusted data.", to)
            else:
                return Decision("ASK_HUMAN", "3_unknown_recipient", "Recipient not explicitly allowed.", to)

    # Rule 8: Mutating action approval (ASK_HUMAN when session is clean)
    if name == "write_record":
        return Decision("ASK_HUMAN", "8_mutating_action_approval", "Database mutation requires human confirmation.", name)

    # Rule 4: Tainted arg + external effect
    external_tools = {"send_email", "write_record"}
    if name in external_tools:
        for k, v in args.items():
            if isinstance(v, str) and is_tainted(v):
                # Ignore subject taint or table taint for simplicity, focus on body/data
                if k in ["body", "data"]:
                    return Decision("BLOCK", "4_tainted_data", f"External tool {name} called with tainted {k}.", v[:20])

    if name == "search_web":
        q = args.get("query", "")
        if len(q) > 50 and is_tainted(q):
             return Decision("BLOCK", "4_tainted_query", "Suspiciously long tainted search query.", q[:20])

    # Rule 5 & 6: Data flow (overlap with confidential reads)
    def check_overlap(val: str):
        if not ctx.get("confidential_reads"): return False
        for secret in ctx["confidential_reads"]:
            # Check for 8-gram overlap
            if len(secret) < 8:
                if secret in val: return True
            else:
                for i in range(len(secret)-8):
                    if secret[i:i+8] in val: return True
        return False

    if name in ["send_email", "write_record", "search_web"]:
        for k, v in args.items():
            if isinstance(v, str) and check_overlap(v):
                return Decision("BLOCK", "5_data_exfiltration", f"Argument {k} contains confidential data.", v[:20])
                
        if name == "search_web":
            # additional exfil checks
            q = args.get("query", "")
            if re.search(r'(?:[A-Za-z0-9+/]{4}){10,}', q):  # looks like base64
                return Decision("BLOCK", "6_search_exfil", "Search query contains encoded blob.", q[:20])

    return Decision("ALLOW", "0_allow", "Action allowed.", "")
