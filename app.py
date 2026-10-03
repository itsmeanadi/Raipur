import streamlit as st
import json
import os
import time
from pathlib import Path
import sys

sys.path.append(os.path.abspath(os.path.dirname(__file__)))

from agent import run_agent, MockLLM
import tools
import audit
import firewall
from demo import get_mock_llm_script

st.set_page_config(layout="wide", page_title="Secure-Agent Demo")

st.title("Secure-Agent Prompt Injection Defences")

# Load datasets
base_dir = Path(__file__).parent
eval_dir = base_dir / "eval"

def load_json(name):
    path = eval_dir / name
    if path.exists():
        with open(path, "r") as f:
            return json.load(f)
    return []

attacks_dev = load_json("attacks_dev.json")
attacks_unseen = load_json("attacks_unseen.json")
all_attacks = attacks_dev + attacks_unseen

attack_opts = {a["id"]: a for a in all_attacks}

col_sel, col_msg = st.columns(2)
with col_sel:
    selected_attack_id = st.selectbox("Select Attack Scenario", options=list(attack_opts.keys()))
with col_msg:
    if selected_attack_id:
        default_msg = attack_opts[selected_attack_id]["user_msg"]
    else:
        default_msg = "Compare the vendor quotations and tell me the cheapest"
    user_msg = st.text_input("User Message", value=default_msg)

use_mock = st.checkbox("Use Mock LLM (Offline Replay)", value=os.environ.get("USE_MOCK_LLM", "0") == "1")
os.environ["USE_MOCK_LLM"] = "1" if use_mock else "0"

if st.button("Run Simulation"):
    st.session_state.run_sim = True
    st.session_state.pending_ask = None
    
if "run_sim" in st.session_state and st.session_state.run_sim:
    attack = attack_opts.get(selected_attack_id, {})
    
    # Write poisoned doc
    docs_dir = base_dir / "documents"
    malicious_file = docs_dir / "malicious_vendor.txt"
    if "poisoned_doc_text" in attack:
        malicious_file.write_text(attack["poisoned_doc_text"], encoding="utf-8")
    elif malicious_file.exists():
        malicious_file.unlink()
        
    script = get_mock_llm_script(attack.get("category", "plain")) if use_mock else []
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("Unprotected Baseline")
        tools.reset_mocks()
        llm = MockLLM(script) if use_mock else None
        res_un = run_agent(user_msg, protected=False, llm=llm)
        
        st.write(f"**Hijacked?** {'🚨 YES' if res_un.hijacked else '✅ NO'}")
        st.write("**Final Response:**", res_un.final_text)
        st.code(json.dumps(
            [c["name"] for c in res_un.tool_calls_executed], 
            indent=2
        ))
        
    with col2:
        st.subheader("Protected Agent")
        
        def handle_ask(call):
            st.session_state.pending_ask = call
            return False # Default deny in sync loop
            
        tools.reset_mocks()
        # Reset mock LLM
        llm = MockLLM(script) if use_mock else None
        res_prot = run_agent(user_msg, protected=True, llm=llm, ask_callback=handle_ask)
        
        st.write(f"**Hijacked?** {'🚨 YES' if res_prot.hijacked else '✅ NO'}")
        if len(res_prot.blocked) > 0:
            st.error("🛡️ Action Blocked by Policy")
            st.code(json.dumps(res_prot.blocked, indent=2, default=str))
            
        if st.session_state.pending_ask:
            st.warning(f"⚠️ Action Requires Approval: {st.session_state.pending_ask['name']}")
            col_a, col_b = st.columns(2)
            with col_a:
                st.button("Approve", key="approve")
            with col_b:
                st.button("Deny", key="deny")
                
        st.write("**Final Response:**", res_prot.final_text)
        
        st.write("### Firewall Sanitization")
        if "poisoned_doc_text" in attack:
            sanitized, findings, risk = firewall.scan(attack["poisoned_doc_text"], "doc")
            if findings:
                st.code(json.dumps(findings, indent=2, default=str))
                st.markdown(sanitized.replace("[REMOVED: suspected injected instruction]", "**:red[[REMOVED: suspected injected instruction]]**"))
                
        st.write("### Latencies")
        st.json(res_prot.timings_ms)

st.write("---")
st.subheader("Live Audit Log (Last 5)")
logs = audit.read_all()
if logs:
    st.code(json.dumps(logs[-5:], indent=2, default=str), language="json")
    
st.write("---")
st.subheader("Evaluation Results")
res_path = eval_dir / "results.json"
if res_path.exists():
    with open(res_path, "r") as f:
        st.json(json.load(f))
else:
    st.info("Run `python eval/run_eval.py` to generate evaluation results.")
