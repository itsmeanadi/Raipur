import streamlit as st
import json
import os
import time
from pathlib import Path
import sys

sys.path.append(os.path.abspath(os.path.dirname(__file__)))

from agent import run_agent, resume_agent, MockLLM, RequiresApprovalError
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
benign_data = load_json("benign.json")
all_scenarios = attacks_dev + attacks_unseen + benign_data

scenario_opts = {s["id"]: s for s in all_scenarios}

col_sel, col_msg = st.columns(2)
with col_sel:
    selected_scenario_id = st.selectbox("Select Scenario (Attacks & Benign)", options=list(scenario_opts.keys()))
with col_msg:
    if selected_scenario_id:
        default_msg = scenario_opts[selected_scenario_id]["user_msg"]
    else:
        default_msg = "Compare the vendor quotations and tell me the cheapest"
    user_msg = st.text_input("User Message", value=default_msg)

use_mock = st.checkbox("Use Mock LLM (Offline Replay)", value=os.environ.get("USE_MOCK_LLM", "1") == "1")
os.environ["USE_MOCK_LLM"] = "1" if use_mock else "0"

if st.button("Run Simulation"):
    st.session_state.run_sim = True
    st.session_state.pending_ask = None
    st.session_state.agent_checkpoint = None
    st.session_state.res_prot = None
    st.session_state.res_un = None
    
if "run_sim" in st.session_state and st.session_state.run_sim:
    scenario = scenario_opts.get(selected_scenario_id, {})
    
    # Write poisoned doc if present
    docs_dir = base_dir / "documents"
    malicious_file = docs_dir / "malicious_vendor.txt"
    if "poisoned_doc_text" in scenario:
        malicious_file.write_text(scenario["poisoned_doc_text"], encoding="utf-8")
    elif malicious_file.exists():
        malicious_file.unlink()
        
    scenario_type = scenario.get("category") or scenario.get("type") or "plain"
    if any(w in user_msg.lower() for w in ["log", "record", "save", "store"]):
        scenario_type = "record_allow"
    script = get_mock_llm_script(scenario_type) if use_mock else []
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("Unprotected Baseline")
        if st.session_state.get("res_un") is None:
            tools.reset_mocks()
            llm = MockLLM(script) if use_mock else None
            res_un = run_agent(user_msg, protected=False, llm=llm)
            st.session_state.res_un = res_un
        else:
            res_un = st.session_state.res_un
        
        st.write(f"**Hijacked?** {'🚨 YES' if res_un.hijacked else '✅ NO'}")
        st.write("**Final Response:**", res_un.final_text)
        st.code(json.dumps(
            [c["name"] for c in res_un.tool_calls_executed], 
            indent=2
        ))
        
    with col2:
        st.subheader("Protected Agent")
        
        if st.session_state.get("res_prot") is None:
            tools.reset_mocks()
            llm = MockLLM(script) if use_mock else None
            try:
                res_prot = run_agent(user_msg, protected=True, llm=llm, pause_on_ask=True)
                st.session_state.res_prot = res_prot
                st.session_state.pending_ask = None
                st.session_state.agent_checkpoint = None
            except RequiresApprovalError as e:
                st.session_state.res_prot = e.result
                st.session_state.pending_ask = e.action
                st.session_state.agent_checkpoint = e.checkpoint
        else:
            res_prot = st.session_state.res_prot
            
        # Human-in-the-Loop circuit breaker UI
        if st.session_state.get("pending_ask"):
            pending = st.session_state.pending_ask
            st.warning("⚠️ **Action Guard Intervention**\nThe Action Guard detected a sensitive action requiring human approval.")
            st.write(f"**Proposed Tool:** `{pending.get('name')}`")
            st.write("**Arguments:**")
            st.json(pending.get("args", {}))
            
            col_a, col_b = st.columns(2)
            with col_a:
                if st.button("Approve Action", key="approve_btn", type="primary"):
                    llm = MockLLM(script) if use_mock else None
                    try:
                        res_prot = resume_agent(st.session_state.agent_checkpoint, approved=True, llm=llm)
                        st.session_state.res_prot = res_prot
                        st.session_state.pending_ask = None
                        st.session_state.agent_checkpoint = None
                        st.rerun()
                    except RequiresApprovalError as e:
                        st.session_state.res_prot = e.result
                        st.session_state.pending_ask = e.action
                        st.session_state.agent_checkpoint = e.checkpoint
                        st.rerun()
            with col_b:
                if st.button("Deny Action", key="deny_btn"):
                    llm = MockLLM(script) if use_mock else None
                    try:
                        res_prot = resume_agent(st.session_state.agent_checkpoint, approved=False, llm=llm)
                        st.session_state.res_prot = res_prot
                        st.session_state.pending_ask = None
                        st.session_state.agent_checkpoint = None
                        st.rerun()
                    except RequiresApprovalError as e:
                        st.session_state.res_prot = e.result
                        st.session_state.pending_ask = e.action
                        st.session_state.agent_checkpoint = e.checkpoint
                        st.rerun()
                        
        if res_prot:
            st.write(f"**Hijacked?** {'🚨 YES' if res_prot.hijacked else '✅ NO'}")
            if len(res_prot.blocked) > 0:
                st.error("🛡️ Action Blocked by Policy")
                st.code(json.dumps(res_prot.blocked, indent=2, default=str))
                
            if not st.session_state.get("pending_ask"):
                st.write("**Final Response:**", res_prot.final_text)
                st.write("**Tool Calls Executed:**")
                st.code(json.dumps(
                    [c["name"] for c in res_prot.tool_calls_executed], 
                    indent=2
                ))
            
            st.write("### Firewall Sanitization")
            if "poisoned_doc_text" in scenario:
                sanitized, findings, risk = firewall.scan(scenario["poisoned_doc_text"], "doc")
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
