import streamlit as st
import streamlit.components.v1 as components
import json
import time
import os
from dotenv import load_dotenv
from neo4j import GraphDatabase
from google import genai
from google.genai import types
from pydantic import BaseModel, Field
from typing import List

# Page config
st.set_page_config(page_title="ThreatGraphRAG | Cyber Threat Intelligence", layout="wide", page_icon="🛡️")

st.title("🛡️ ThreatGraphRAG: Cyber Threat Intelligence & Attack Path Engine")
st.caption("Automated Multi-Hop Attack Graph Reasoning & Supply Chain Blast Radius Analysis")

# Load credentials
load_dotenv()
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "your_gemini_api_key_here")
NEO4J_URI = os.getenv("NEO4J_URI", "neo4j+ssc://e6c68873.databases.neo4j.io")
NEO4J_USERNAME = os.getenv("NEO4J_USERNAME", "e6c68873")
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD", "your_neo4j_password_here")

@st.cache_resource
def get_clients():
    client = genai.Client(api_key=GEMINI_API_KEY)
    driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USERNAME, NEO4J_PASSWORD))
    return client, driver

client, driver = get_clients()

# Schemas
class QueryEntities(BaseModel):
    entities: List[str] = Field(description="Cyber entities mentioned in query: threat actors, CVEs, services, techniques, or packages")

def extract_entities(query: str) -> List[str]:
    # 1. Instant heuristic match (<0.01s)
    known_entities = [
        "APT29", "Cozy Bear", "Lazarus", "LockBit",
        "CVE-2021-44228", "Log4Shell", "CVE-2024-3094", "XZ Backdoor", "CVE-2022-22965", "Spring4Shell", "CVE-2024-21762",
        "Customer-Auth-Service", "Payment-Processing-Gateway", "Enterprise-SSH-Bastion", "Analytics-ETL-Pipeline",
        "Exploit Public-Facing Application", "Supply Chain Compromise", "Command and Scripting Interpreter", "Data Encrypted for Impact",
        "log4j", "xz-utils", "spring-beans", "fortios"
    ]
    matched = [e for e in known_entities if e.lower() in query.lower()]
    if matched:
        return matched

    # 2. Fall back to Gemini if no preset entities detected
    prompt = f"Identify all specific cybersecurity entities, threat groups, CVEs, techniques, or enterprise services mentioned in: '{query}'"
    try:
        res = client.models.generate_content(
            model="gemini-3.6-flash",
            contents=prompt,
            config=types.GenerateContentConfig(
                response_mime_type="application/json",
                response_schema=QueryEntities,
                temperature=0.0
            )
        )
        if res.parsed and res.parsed.entities:
            return res.parsed.entities
    except Exception:
        pass
        
    return [query.strip()]

def fetch_threat_subgraph(entities: List[str]):
    facts = []
    nodes_dict = {}
    edges_list = []
    
    with driver.session() as session:
        for entity in entities:
            cypher = """
            MATCH (source)
            WHERE toLower(source.name) CONTAINS toLower($entity)
            MATCH path = (source)-[r*1..2]-(target)
            UNWIND relationships(path) as rel
            WITH DISTINCT rel, startNode(rel) as s, endNode(rel) as t
            RETURN 
                s.name AS from_name, labels(s)[0] AS from_label,
                type(rel) AS relationship,
                t.name AS to_name, labels(t)[0] AS to_label
            LIMIT 25
            """
            result = session.run(cypher, entity=entity)
            for record in result:
                src, s_label = record['from_name'], record['from_label']
                tgt, t_label = record['to_name'], record['to_label']
                rel = record['relationship']
                
                fact = f"- [{s_label}] `{src}` ──[{rel}]──► [{t_label}] `{tgt}`"
                if fact not in facts:
                    facts.append(fact)
                    nodes_dict[src] = s_label
                    nodes_dict[tgt] = t_label
                    edges_list.append({"from": src, "to": tgt, "label": rel})
                    
    return facts, nodes_dict, edges_list

def answer_threat_query(query: str, facts: List[str]) -> str:
    context = "\n".join(facts) if facts else "No direct attack graph paths discovered."
    prompt = f"""You are a Principal Cyber Threat Intelligence & SOC Analyst.
Analyze the user question STRICTLY using the attack graph paths and dependency topologies provided below.

Structure your response clearly with:
1. 🎯 Executive Threat Summary
2. ⛓️ Multi-Hop Attack Path (Trace step-by-step from Threat Actor -> Technique -> CVE -> Vulnerable Dependency -> Target Service)
3. 💥 Blast Radius & Lateral Movement Risks
4. 🛡️ Prescribed Remediation & Patching Steps

ATTACK GRAPH FACTS:
{context}

USER QUESTION:
{query}
"""
    models_to_try = ["gemini-3.6-flash", "gemini-2.5-flash"]
    for m in models_to_try:
        for attempt in range(2):
            try:
                res = client.models.generate_content(
                    model=m,
                    contents=prompt,
                    config=types.GenerateContentConfig(temperature=0.2)
                )
                if res.text:
                    return res.text
            except Exception:
                time.sleep(2)
                
    # Direct graph-grounded report if external API is temporarily unavailable
    fallback_report = f"### 🛡️ Threat Intelligence Report (Generated from Direct Neo4j Subgraph)\n\n"
    fallback_report += f"**Discovered Attack Chains:**\n"
    for f in facts:
        fallback_report += f"{f}\n"
    return fallback_report

# 2D Attack Graph Visualization with Vis.js
def render_attack_graph(nodes_dict, edges):
    # Color coding by entity category
    color_map = {
        "ThreatActor": "#E63946",       # Red
        "AttackTechnique": "#F4A261",   # Orange
        "Vulnerability": "#D62828",     # Crimson
        "SoftwarePackage": "#E9C46A",   # Gold
        "EnterpriseService": "#00ADB5", # Cyan
        "RemediationPatch": "#2A9D8F"   # Teal / Green
    }
    
    vis_nodes = []
    for name, label in nodes_dict.items():
        color = color_map.get(label, "#A8DADC")
        vis_nodes.append({
            "id": name,
            "label": f"[{label}]\n{name}",
            "color": color,
            "font": {"color": "#FFFFFF", "size": 12},
            "shape": "box" if label == "EnterpriseService" else "dot",
            "size": 22 if label in ["ThreatActor", "Vulnerability"] else 16
        })
        
    vis_edges = [{"from": e["from"], "to": e["to"], "label": e["label"], "arrows": "to", "color": {"color": "#888888"}} for e in edges]
    
    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
      <script type="text/javascript" src="https://unpkg.com/vis-network/standalone/umd/vis-network.min.js"></script>
      <style type="text/css">
        #network {{
          width: 100%;
          height: 520px;
          border: 1px solid #333;
          background-color: #0F172A;
          border-radius: 8px;
        }}
      </style>
    </head>
    <body>
      <div id="network"></div>
      <script type="text/javascript">
        var nodes = new vis.DataSet({json.dumps(vis_nodes)});
        var edges = new vis.DataSet({json.dumps(vis_edges)});
        var container = document.getElementById('network');
        var data = {{ nodes: nodes, edges: edges }};
        var options = {{
          physics: {{ stabilization: true, barnesHut: {{ springLength: 140, springConstant: 0.04, damping: 0.12 }} }},
          edges: {{ font: {{ size: 10, align: 'middle', color: '#38BDF8' }}, smooth: {{ type: 'continuous' }} }}
        }};
        var network = new vis.Network(container, data, options);
      </script>
    </body>
    </html>
    """
    components.html(html, height=540)

# Layout
col1, col2 = st.columns([1, 1])

with col1:
    tab_query, tab_benchmark = st.tabs(["🕵️ Threat Intelligence Query", "📊 Empirical Benchmark (RAG vs GraphRAG)"])
    
    with tab_query:
        sample_queries = [
            "How can APT29 exploit our public-facing services to compromise internal payment processing, and what patch mitigates this?",
            "What is the blast radius and attack path if CVE-2021-44228 (Log4Shell) is targeted against Customer-Auth-Service?",
            "Which threat actors leverage Supply Chain Compromise, and which software packages and infrastructure are affected?"
        ]
        selected_sample = st.selectbox("Select a Preset Threat Scenario (or write your own below):", sample_queries)
        
        user_query = st.text_area("Security Analyst Query:", value=selected_sample, height=90)
        
        if st.button("🚨 Analyze Attack Graph & Blast Radius", type="primary"):
            with st.spinner("Traversing Cyber Threat Graph & Synthesizing SOC Report..."):
                entities = extract_entities(user_query)
                facts, nodes_dict, edges = fetch_threat_subgraph(entities)
                answer = answer_threat_query(user_query, facts)
                
                st.session_state["answer"] = answer
                st.session_state["entities"] = entities
                st.session_state["facts"] = facts
                st.session_state["nodes_dict"] = nodes_dict
                st.session_state["edges"] = edges

        if "answer" in st.session_state:
            st.markdown("### 📋 SOC Threat Intelligence Report")
            st.markdown(st.session_state["answer"])
            with st.expander("🔍 Discovered Attack Graph Paths (Evidence)"):
                for f in st.session_state["facts"]:
                    st.write(f)

    with tab_benchmark:
        st.markdown("#### 🔬 Empirical Evaluation: Naive Vector RAG vs. ThreatGraphRAG")
        st.caption("Quantitative benchmark evaluated on multi-hop attack paths, factual grounding, and remediation precision.")
        
        benchmark_file = "benchmark_results.csv"
        import pandas as pd
        if os.path.exists(benchmark_file):
            df = pd.read_csv(benchmark_file)
            
            # Metric cards
            m1, m2, m3 = st.columns(3)
            diff_recall = (df['Graph_Recall'].mean() - df['Vector_Recall'].mean()) * 100
            diff_faith = (df['Graph_Faithfulness'].mean() - df['Vector_Faithfulness'].mean()) * 100
            diff_prec = (df['Graph_Precision'].mean() - df['Vector_Precision'].mean()) * 100
            
            m1.metric("Multi-Hop Recall", f"{df['Graph_Recall'].mean()*100:.1f}%", f"+{diff_recall:.1f}% vs Vector RAG")
            m2.metric("Answer Faithfulness", f"{df['Graph_Faithfulness'].mean()*100:.1f}%", f"+{diff_faith:.1f}% vs Vector RAG")
            m3.metric("Remediation Precision", f"{df['Graph_Precision'].mean()*100:.1f}%", f"+{diff_prec:.1f}% vs Vector RAG")
            
            st.markdown("##### 📈 Performance Comparison Across Metrics")
            chart_df = pd.DataFrame({
                "Naive Vector RAG": [df["Vector_Recall"].mean()*100, df["Vector_Faithfulness"].mean()*100, df["Vector_Precision"].mean()*100],
                "ThreatGraphRAG (Ours)": [df["Graph_Recall"].mean()*100, df["Graph_Faithfulness"].mean()*100, df["Graph_Precision"].mean()*100]
            }, index=["Multi-Hop Recall", "Answer Faithfulness", "Remediation Precision"])
            st.bar_chart(chart_df)
            
            st.markdown("##### 📋 Granular Test Case Breakdown")
            st.dataframe(df, use_container_width=True)
        else:
            st.info("Benchmark is currently running in the background. Refresh this page in a moment to view the live charts!")

with col2:
    st.subheader("🕸️ Interactive Attack Graph & Blast Radius")
    st.markdown("""
    **Legend:** 🔴 Threat Actor | 🟠 MITRE Technique | 🚨 Vulnerability (CVE) | 🟡 Vulnerable Library | 🔵 Enterprise Service | 🟢 Remediation Patch
    """)
    if "edges" in st.session_state and st.session_state["edges"]:
        st.caption(f"Showing attack path for: {', '.join(st.session_state['entities'])} (Click & Drag nodes)")
        render_attack_graph(st.session_state["nodes_dict"], st.session_state["edges"])
    else:
        st.info("Execute a threat scenario on the left to visualize the attack path and lateral movement graph!")
