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

from src.repo_evaluator import (
    parse_github_url,
    fetch_repo_manifest,
    parse_generic_manifest,
    evaluate_repo_dependencies,
    generate_ai_repo_audit_report,
    PRESET_REPOSITORIES
)

# Page config
st.set_page_config(page_title="ThreatGraphRAG | Cyber Threat Intelligence", layout="wide", page_icon="🛡️")

st.title("🛡️ ThreatGraphRAG: Cyber Threat Intelligence & Attack Path Engine")
st.caption("Automated Multi-Hop Attack Graph Reasoning & Supply Chain Blast Radius Analysis")

# Load credentials
load_dotenv()
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
NEO4J_URI = os.getenv("NEO4J_URI", "neo4j+ssc://e6c68873.databases.neo4j.io")
NEO4J_USERNAME = os.getenv("NEO4J_USERNAME", "neo4j")
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD")

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

# 2D Attack Graph Visualization with Vis.js (Fine-Tuned & High-Readability)
def render_attack_graph(nodes_dict, edges):
    # Professional SOC theme palette
    theme = {
        "GitHubRepo": {
            "bg": "#5B21B6", "border": "#A78BFA", "highlight": "#7C3AED",
            "icon": "🐙", "badge": "Repo"
        },
        "ThreatActor": {
            "bg": "#991B1B", "border": "#F87171", "highlight": "#DC2626",
            "icon": "👤", "badge": "Adversary"
        },
        "AttackTechnique": {
            "bg": "#9A3412", "border": "#FB923C", "highlight": "#EA580C",
            "icon": "⚡", "badge": "Technique"
        },
        "Vulnerability": {
            "bg": "#9F1239", "border": "#FB7185", "highlight": "#E11D48",
            "icon": "🚨", "badge": "CVE"
        },
        "SoftwarePackage": {
            "bg": "#854D0E", "border": "#FACC15", "highlight": "#CA8A04",
            "icon": "📦", "badge": "Package"
        },
        "EnterpriseService": {
            "bg": "#075985", "border": "#38BDF8", "highlight": "#0284C7",
            "icon": "🖥️", "badge": "Service"
        },
        "RemediationPatch": {
            "bg": "#065F46", "border": "#34D399", "highlight": "#059669",
            "icon": "🛡️", "badge": "Remediation"
        },
        "SecurityControl": {
            "bg": "#374151", "border": "#9CA3AF", "highlight": "#4B5563",
            "icon": "🔒", "badge": "Control"
        }
    }

    edge_color_map = {
        "EXPLOITS": "#F43F5E",
        "EXPLOITS_FLAW_IN": "#F43F5E",
        "TARGETS": "#F43F5E",
        "TARGETS_VULNERABILITY": "#F43F5E",
        "CAN_PIVOT_TO": "#FB923C",
        "LATERAL_MOVEMENT": "#FB923C",
        "MITIGATED_BY": "#34D399",
        "PROTECTED_BY": "#34D399",
        "LEVERAGES": "#C084FC",
        "INCLUDES": "#38BDF8",
        "DEPENDS_ON": "#38BDF8",
        "RUNS_SOFTWARE": "#38BDF8"
    }

    vis_nodes = []
    for name, label in nodes_dict.items():
        style = theme.get(label, {
            "bg": "#1E293B", "border": "#94A3B8", "highlight": "#334155",
            "icon": "🔹", "badge": label
        })
        
        # Clean formatted display label with smart truncation
        short_title = name
        subtitle = ""
        
        if label == "SoftwarePackage":
            parts = name.split(":")
            if len(parts) >= 3:
                short_title = parts[1]
                subtitle = f"v{parts[2]}"
            elif len(parts) == 2:
                short_title = parts[0]
                subtitle = f"v{parts[1]}"
        elif label == "Vulnerability":
            if "(" in name and ")" in name:
                parts = name.split("(")
                subtitle = parts[0].strip()
                short_title = parts[1].replace(")", "").strip()
        elif label == "ThreatActor":
            if "(" in name:
                short_title = name.replace("(", "\n(").strip()
        elif label == "RemediationPatch":
            parts = name.split("(")
            short_title = parts[0].strip()
            if len(parts) > 1:
                subtitle = parts[1].replace(")", "").strip()
        elif label == "GitHubRepo":
            short_title = name.replace("Repo: ", "").strip()
            
        display_label = f"[{style['badge'].upper()}]\n{style['icon']} {short_title}"
        if subtitle:
            display_label += f"\n({subtitle})"
            
        vis_nodes.append({
            "id": name,
            "label": display_label,
            "title": f"<b>[{label}]</b><br>{name}",
            "color": {
                "background": style["bg"],
                "border": style["border"],
                "highlight": {
                    "background": style["highlight"],
                    "border": "#FFFFFF"
                },
                "hover": {
                    "background": style["highlight"],
                    "border": "#FFFFFF"
                }
            },
            "font": {
                "color": "#F8FAFC",
                "size": 12,
                "face": "system-ui, -apple-system, Segoe UI, Roboto, sans-serif",
                "align": "center"
            },
            "shape": "box",
            "margin": 10,
            "shapeProperties": {
                "borderRadius": 6
            },
            "borderWidth": 2,
            "borderWidthSelected": 3,
            "shadow": {
                "enabled": True,
                "color": "rgba(0,0,0,0.6)",
                "size": 8,
                "x": 2,
                "y": 2
            }
        })
        
    vis_edges = []
    for e in edges:
        lbl = e["label"]
        edge_color = edge_color_map.get(lbl, "#94A3B8")
        is_critical = lbl in ["EXPLOITS", "EXPLOITS_FLAW_IN", "CAN_PIVOT_TO", "LATERAL_MOVEMENT"]
        
        vis_edges.append({
            "from": e["from"],
            "to": e["to"],
            "label": lbl,
            "arrows": {
                "to": {
                    "enabled": True,
                    "scaleFactor": 0.85,
                    "type": "arrow"
                }
            },
            "color": {
                "color": edge_color,
                "highlight": "#FFFFFF",
                "hover": "#FFFFFF"
            },
            "width": 2.5 if is_critical else 1.8,
            "dashes": True if lbl in ["MITIGATED_BY", "PROTECTED_BY"] else False,
            "font": {
                "size": 10,
                "color": "#E2E8F0",
                "background": "#0F172A",
                "strokeWidth": 0,
                "align": "horizontal"
            },
            "smooth": {
                "type": "curvedCW",
                "roundness": 0.16
            }
        })
        
    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
      <script type="text/javascript" src="https://unpkg.com/vis-network/standalone/umd/vis-network.min.js"></script>
      <style type="text/css">
        body {{
          margin: 0;
          padding: 0;
          font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif;
          background-color: transparent;
        }}
        #graph-wrapper {{
          position: relative;
          width: 100%;
          height: 600px;
          border: 1px solid #334155;
          border-radius: 10px;
          background: radial-gradient(circle at 50% 50%, #111827 0%, #0B0F19 100%);
          overflow: hidden;
          box-shadow: 0 4px 20px rgba(0, 0, 0, 0.5);
        }}
        #network {{
          width: 100%;
          height: 100%;
        }}
        .toolbar {{
          position: absolute;
          top: 12px;
          right: 12px;
          z-index: 100;
          display: flex;
          gap: 6px;
          background: rgba(15, 23, 42, 0.85);
          backdrop-filter: blur(4px);
          padding: 5px 8px;
          border-radius: 6px;
          border: 1px solid #334155;
        }}
        .tool-btn {{
          background: #1E293B;
          color: #E2E8F0;
          border: 1px solid #475569;
          border-radius: 4px;
          padding: 4px 10px;
          font-size: 11px;
          font-weight: 600;
          cursor: pointer;
          transition: all 0.15s ease;
        }}
        .tool-btn:hover {{
          background: #3B82F6;
          border-color: #60A5FA;
          color: #FFFFFF;
        }}
      </style>
    </head>
    <body>
      <div id="graph-wrapper">
        <div class="toolbar">
          <button class="tool-btn" onclick="network.moveTo({{scale: network.getScale() * 1.3}})">🔍 +</button>
          <button class="tool-btn" onclick="network.moveTo({{scale: network.getScale() * 0.7}})">🔍 -</button>
          <button class="tool-btn" onclick="network.fit({{animation: {{duration: 400}}}})">🎯 Fit</button>
          <button class="tool-btn" id="freeze-btn" onclick="togglePhysics()">⏸️ Freeze</button>
        </div>
        <div id="network"></div>
      </div>

      <script type="text/javascript">
        var nodes = new vis.DataSet({json.dumps(vis_nodes)});
        var edges = new vis.DataSet({json.dumps(vis_edges)});
        var container = document.getElementById('network');
        var data = {{ nodes: nodes, edges: edges }};
        
        var options = {{
          physics: {{
            enabled: true,
            solver: 'forceAtlas2Based',
            forceAtlas2Based: {{
              gravitationalConstant: -75,
              centralGravity: 0.015,
              springLength: 180,
              springConstant: 0.08,
              damping: 0.45,
              avoidOverlap: 1.0
            }},
            stabilization: {{
              enabled: true,
              iterations: 200,
              updateInterval: 25
            }}
          }},
          interaction: {{
            hover: true,
            tooltipDelay: 100,
            zoomView: true,
            dragView: true
          }}
        }};
        
        var network = new vis.Network(container, data, options);
        var physicsEnabled = true;
        
        function togglePhysics() {{
          physicsEnabled = !physicsEnabled;
          network.setOptions({{ physics: {{ enabled: physicsEnabled }} }});
          var btn = document.getElementById('freeze-btn');
          btn.innerText = physicsEnabled ? '⏸️ Freeze' : '▶️ Unfreeze';
        }}
      </script>
    </body>
    </html>
    """
    components.html(html, height=620)

# Layout
col1, col2 = st.columns([1, 1])

with col1:
    tab_query, tab_sbom, tab_benchmark = st.tabs(["🕵️ Threat Query", "📦 GitHub & SBOM Supply Chain", "📊 Empirical Benchmark"])
    
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

    with tab_sbom:
        st.markdown("#### 📦 Software Supply Chain & Vulnerability Auditor")
        st.caption("Cross-references dependency manifests against the ThreatGraphRAG Knowledge Graph to detect zero-days, active APT campaigns, and lateral movement blast radius.")
        
        audit_mode = st.radio(
            "Select Supply Chain Audit Target:",
            ["🐙 Live GitHub Repository", "📁 Enterprise Cloud Platform SBOM"],
            horizontal=True
        )
        
        if audit_mode == "🐙 Live GitHub Repository":
            st.markdown("##### 🐙 Audit External Git Repository")
            preset_options = list(PRESET_REPOSITORIES.keys()) + ["Custom Repository URL / Manual Input"]
            selected_repo_preset = st.selectbox("Choose a Repository Scenario or enter Custom:", preset_options)
            
            if selected_repo_preset == "Custom Repository URL / Manual Input":
                repo_url = st.text_input("GitHub Repository URL or owner/repo:", value="https://github.com/apache/logging-log4j2", placeholder="https://github.com/owner/repo")
                col_branch, col_man = st.columns(2)
                with col_branch:
                    target_branch = st.text_input("Branch / Tag (optional):", value="", placeholder="main (default)")
                with col_man:
                    manifest_choice = st.selectbox("Manifest Detection:", ["Auto-Detect", "requirements.txt", "package.json", "pom.xml", "pyproject.toml", "go.mod", "Direct Manifest Paste"])
                
                custom_content = None
                if manifest_choice == "Direct Manifest Paste":
                    custom_content = st.text_area("Paste Manifest Contents (e.g. requirements.txt, pom.xml, or package.json):", height=120)
                selected_manifest_type = None if manifest_choice in ["Auto-Detect", "Direct Manifest Paste"] else manifest_choice
            else:
                preset_data = PRESET_REPOSITORIES[selected_repo_preset]
                st.info(f"ℹ️ **Target:** `{preset_data['owner']}/{preset_data['repo']}` — {preset_data['description']}")
                repo_url = preset_data["url"]
                target_branch = None
                selected_manifest_type = preset_data["manifest_type"]
                custom_content = preset_data["simulated_manifest"]
                
            if st.button("🚀 Audit GitHub Repository Security", type="primary"):
                with st.spinner(f"Auditing dependencies for {repo_url} against Cyber Threat Graph..."):
                    try:
                        parsed = parse_github_url(repo_url)
                        owner = parsed["owner"]
                        repo = parsed["repo"]
                        repo_id = f"{owner}/{repo}"
                        branch = target_branch if target_branch else (parsed.get("branch") or "main")
                        
                        manifest_content = custom_content
                        manifest_filename = selected_manifest_type or "requirements.txt"
                        
                        if not manifest_content:
                            manifest_content, manifest_filename, branch = fetch_repo_manifest(
                                owner, repo, branch=branch, specified_file=selected_manifest_type
                            )
                            
                        packages = parse_generic_manifest(manifest_filename, manifest_content)
                        
                        if not packages:
                            st.warning(f"No parseable dependencies found in {manifest_filename}.")
                        else:
                            eval_res = evaluate_repo_dependencies(driver, packages, repo_id)
                            
                            st.session_state["nodes_dict"] = eval_res["vis_graph"]["nodes"]
                            st.session_state["edges"] = eval_res["vis_graph"]["edges"]
                            st.session_state["entities"] = list(eval_res["vis_graph"]["nodes"].keys())
                            
                            ai_soc_report = generate_ai_repo_audit_report(repo_id, eval_res, gemini_api_key=GEMINI_API_KEY)
                            st.session_state["repo_ai_report"] = ai_soc_report
                            st.session_state["repo_eval_res"] = eval_res
                            
                    except Exception as e:
                        st.error(f"Audit failed: {e}")
                        
            if "repo_eval_res" in st.session_state:
                res = st.session_state["repo_eval_res"]
                posture = res["security_posture"]
                if "CRITICAL" in posture:
                    st.error(f"🚨 **ALERT: CRITICAL SUPPLY CHAIN VULNERABILITIES IDENTIFIED IN {res['repository']}!**")
                elif "HIGH" in posture or "MEDIUM" in posture:
                    st.warning(f"⚠️ **WARNING: ELEVATED RISK IN {res['repository']}!**")
                else:
                    st.success(f"✅ **SECURE: ZERO KNOWN ZERO-DAYS DETECTED IN {res['repository']}.**")
                    
                col_m1, col_m2, col_m3, col_m4 = st.columns(4)
                col_m1.metric("Packages Audited", res["total_dependencies_scanned"])
                col_m2.metric("Critical CVEs", res["critical_vulnerabilities_detected"], delta="CRITICAL" if res["critical_vulnerabilities_detected"] > 0 else "0", delta_color="inverse")
                col_m3.metric("Targeting Adversaries", len(res["active_threat_actors"]))
                col_m4.metric("Supply Chain Risk", f"{res['composite_risk_score']}/100")
                
                if res["findings"]:
                    st.markdown("##### 🔍 Identified Vulnerability Findings & Prescribed Patches")
                    import pandas as pd
                    df_findings = pd.DataFrame(res["findings"])[[
                        "detected_package", "cve", "cvss_score", "vulnerability_type",
                        "exploited_by_adversary", "prescribed_remediation", "simulated_service_blast_radius"
                    ]]
                    df_findings.columns = ["Package", "CVE", "CVSS", "Flaw Type", "Adversary", "Prescribed Patch", "Service at Risk"]
                    st.dataframe(df_findings, use_container_width=True)
                    
                    if res["impacted_enterprise_services"]:
                        st.markdown(f"**💥 Simulated Downstream Blast Radius:** `{', '.join(res['impacted_enterprise_services'])}` ➔ Can pivot to `{', '.join(res['downstream_blast_radius_targets'])}`")
                        
                if "repo_ai_report" in st.session_state and st.session_state["repo_ai_report"]:
                    with st.expander("📋 SOC Threat Intelligence & Remediation Roadmap (AI-Generated)", expanded=True):
                        st.markdown(st.session_state["repo_ai_report"])
                        
                st.success("✅ Interactive Attack Graph on the right updated with the repository supply chain topology!")

        else:
            st.markdown("##### 📁 Enterprise Cloud Platform SBOM (CycloneDX)")
            st.caption("Cross-references enterprise dependency manifests against the ThreatGraphRAG Knowledge Graph to detect zero-days and threat actors.")
            
            if st.button("🛡️ Audit Enterprise Platform Dependencies", type="primary"):
                with st.spinner("Auditing SBOM against ThreatGraphRAG Knowledge Base..."):
                    import json
                    sbom_path = "data/sample_enterprise_sbom.json"
                    if os.path.exists(sbom_path):
                        with open(sbom_path) as f:
                            sbom_data = json.load(f)
                            
                        findings = []
                        infected_nodes = {}
                        infected_edges = []
                        all_cves = set()
                        all_actors = set()
                        
                        with driver.session() as session:
                            for svc in sbom_data["services"]:
                                s_name = svc["name"]
                                infected_nodes[s_name] = "EnterpriseService"
                                for dep in svc["dependencies"]:
                                    dep_search = dep.split(":")[1] if ":" in dep else dep
                                    cypher = """
                                    MATCH (p:SoftwarePackage)
                                    WHERE toLower(p.name) CONTAINS toLower($dep_name)
                                    MATCH (v:Vulnerability)-[:EXPLOITS_FLAW_IN]->(p)
                                    OPTIONAL MATCH (tech:AttackTechnique)-[:TARGETS_VULNERABILITY]->(v)
                                    OPTIONAL MATCH (actor:ThreatActor)-[:LEVERAGES]->(tech)
                                    OPTIONAL MATCH (v)-[:MITIGATED_BY]->(patch:RemediationPatch)
                                    RETURN 
                                        p.name AS pkg, v.name AS cve, v.cvss AS cvss, v.type AS vuln_type,
                                        actor.name AS actor, patch.name AS patch
                                    """
                                    for r in session.run(cypher, dep_name=dep_search):
                                        if r["cve"]:
                                            all_cves.add(r["cve"])
                                            if r["actor"]: all_actors.add(r["actor"])
                                            findings.append({
                                                "Service": s_name,
                                                "Vulnerable Package": dep,
                                                "CVE": r["cve"],
                                                "CVSS": r["cvss"],
                                                "Threat Actor": r["actor"] or "Undisclosed",
                                                "Remediation Patch": r["patch"] or "Vendor Update"
                                            })
                                            pkg_name = r["pkg"]
                                            cve_name = r["cve"]
                                            infected_nodes[pkg_name] = "SoftwarePackage"
                                            infected_nodes[cve_name] = "Vulnerability"
                                            infected_edges.append({"from": s_name, "to": pkg_name, "label": "DEPENDS_ON"})
                                            infected_edges.append({"from": cve_name, "to": pkg_name, "label": "EXPLOITS"})
                                            if r["actor"]:
                                                act_name = r["actor"]
                                                infected_nodes[act_name] = "ThreatActor"
                                                infected_edges.append({"from": act_name, "to": cve_name, "label": "TARGETS"})

                        st.session_state["nodes_dict"] = infected_nodes
                        st.session_state["edges"] = infected_edges
                        st.session_state["entities"] = list(infected_nodes.keys())
                        
                        st.error(f"🚨 ALERT: {len(all_cves)} Critical Zero-Day Vulnerabilities Detected in Deployment!")
                        
                        sb_col1, sb_col2, sb_col3 = st.columns(3)
                        sb_col1.metric("Services Audited", len(sbom_data["services"]))
                        sb_col2.metric("Critical CVEs", len(all_cves), delta="CRITICAL", delta_color="inverse")
                        sb_col3.metric("Targeting Adversaries", ", ".join(all_actors) if all_actors else "None")
                        
                        st.markdown("##### 🔍 Identified Vulnerable Dependencies & Prescribed Fixes")
                        import pandas as pd
                        st.dataframe(pd.DataFrame(findings), use_container_width=True)
                        st.success("✅ Interactive Attack Graph updated on the right to visualize the infected supply chain paths!")
                    else:
                        st.error("Sample SBOM file not found at data/sample_enterprise_sbom.json")

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
    <div style="display: flex; flex-wrap: wrap; gap: 6px; font-size: 11px; margin-bottom: 10px; font-weight: 600;">
        <span style="background: #5B21B6; color: #EDE9FE; padding: 3px 8px; border-radius: 4px; border: 1px solid #7C3AED;">🐙 Repo</span>
        <span style="background: #991B1B; color: #FEE2E2; padding: 3px 8px; border-radius: 4px; border: 1px solid #EF4444;">👤 Adversary</span>
        <span style="background: #9A3412; color: #FFEDD5; padding: 3px 8px; border-radius: 4px; border: 1px solid #FB923C;">⚡ Technique</span>
        <span style="background: #9F1239; color: #FFE4E6; padding: 3px 8px; border-radius: 4px; border: 1px solid #FB7185;">🚨 CVE</span>
        <span style="background: #854D0E; color: #FEF9C3; padding: 3px 8px; border-radius: 4px; border: 1px solid #FACC15;">📦 Package</span>
        <span style="background: #075985; color: #E0F2FE; padding: 3px 8px; border-radius: 4px; border: 1px solid #38BDF8;">🖥️ Service</span>
        <span style="background: #065F46; color: #D1FAE5; padding: 3px 8px; border-radius: 4px; border: 1px solid #34D399;">🛡️ Remediation</span>
    </div>
    """, unsafe_allow_html=True)
    if "edges" in st.session_state and st.session_state["edges"]:
        st.caption(f"Showing attack path for: {', '.join(st.session_state['entities'])} (Click & Drag nodes)")
        render_attack_graph(st.session_state["nodes_dict"], st.session_state["edges"])
    else:
        st.info("Execute a threat scenario on the left to visualize the attack path and lateral movement graph!")
