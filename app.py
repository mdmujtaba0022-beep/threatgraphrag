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
from src.report_generator import synthesize_technical_report

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
        # Adversaries
        "APT29", "Nobelium", "Cozy Bear", "Midnight Blizzard",
        "Lazarus Group", "Lazarus", "HIDDEN COBRA", "Diamond Sleet",
        "Volt Typhoon", "BRONZE SILHOUETTE", "Vanguard Panda",
        "LockBit 3.0", "LockBit", "FIN7", "Carbanak",
        # Vulnerabilities
        "CVE-2021-44228", "Log4Shell", "CVE-2024-3094", "XZ Utils", "XZ Backdoor",
        "CVE-2022-22965", "Spring4Shell", "CVE-2024-21762", "FortiOS",
        "CVE-2023-4966", "Citrix Bleed", "NetScaler",
        # Infrastructure Assets
        "k8s-auth-ingress-gateway", "payment-token-vault-service", "corporate-active-directory-dc01",
        "enterprise-bastion-ssh-host", "data-analytics-dataproc-spark", "edge-vpn-gateway-fortigate",
        "Customer-Auth-Service", "Payment-Processing-Gateway", "Enterprise-SSH-Bastion", "Analytics-ETL-Pipeline",
        # Techniques
        "Exploit Public-Facing Application", "Supply Chain Compromise", "Command and Scripting Interpreter", "Valid Accounts",
        "Remote Services", "Server Software Component", "Data Encrypted for Impact",
        # Packages
        "log4j", "xz-utils", "spring-beans", "fortios", "netscaler"
    ]
    matched = [e for e in known_entities if e.lower() in query.lower()]
    if matched:
        return matched

    # 2. Fall back to Gemini if no preset entities detected
    prompt = f"Identify all specific cybersecurity entities, threat groups, CVEs, techniques, or enterprise services mentioned in: '{query}'"
    for m in ["gemini-3.5-flash-lite", "gemini-flash-lite-latest", "gemini-3.6-flash"]:
        try:
            res = client.models.generate_content(
                model=m,
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
            continue
        
    return [query.strip()]

def fetch_threat_subgraph(entities: List[str]):
    facts = []
    nodes_dict = {}
    edges_list = []
    nodes_meta = {}
    
    with driver.session() as session:
        for entity in entities:
            cypher = """
            MATCH (source)
            WHERE toLower(source.name) CONTAINS toLower($entity)
            MATCH path = (source)-[r*1..2]-(target)
            UNWIND relationships(path) as rel
            WITH DISTINCT rel, startNode(rel) as s, endNode(rel) as t
            RETURN 
                s.name AS from_name, labels(s)[0] AS from_label, properties(s) AS s_props,
                type(rel) AS relationship,
                t.name AS to_name, labels(t)[0] AS to_label, properties(t) AS t_props
            LIMIT 35
            """
            result = session.run(cypher, entity=entity)
            for record in result:
                src, s_label = record['from_name'], record['from_label']
                tgt, t_label = record['to_name'], record['to_label']
                s_props = dict(record['s_props']) if record['s_props'] else {}
                t_props = dict(record['t_props']) if record['t_props'] else {}
                rel = record['relationship']
                
                fact = f"- [{s_label}] `{src}` ──[{rel}]──► [{t_label}] `{tgt}`"
                if fact not in facts:
                    facts.append(fact)
                    nodes_dict[src] = s_label
                    nodes_dict[tgt] = t_label
                    nodes_meta[src] = {"label": s_label, "props": s_props}
                    nodes_meta[tgt] = {"label": t_label, "props": t_props}
                    edges_list.append({"from": src, "to": tgt, "label": rel})
                    
    return facts, nodes_dict, edges_list, nodes_meta

def answer_threat_query(query: str, facts: List[str]) -> str:
    return synthesize_technical_report(facts, query, client=client)

def get_node_level(label: str, name: str, props: dict) -> int:
    lbl = (label or "").lower()
    nm = (name or "").lower()
    if "threatactor" in lbl or "actor" in lbl:
        return 1
    if "technique" in lbl or "ttp" in lbl:
        return 2
    if "vulnerability" in lbl or "cve" in lbl:
        return 3
    if "softwarepackage" in lbl or "package" in lbl:
        return 4
    if "githubrepo" in lbl or "repo" in lbl:
        return 4
    if "enterpriseservice" in lbl or "service" in lbl:
        zone = (props.get("zone", "") if props else "").lower()
        tier = (props.get("tier", "") if props else "").lower()
        status = (props.get("status", "") if props else "").lower()
        if "ingress" in nm or "gateway" in nm or "vpn" in nm or "bastion" in nm or "dmz" in zone or "perimeter" in tier or "exposed" in status:
            return 5
        return 6
    if "remediation" in lbl or "patch" in lbl or "control" in lbl:
        return 7
    return 4

# 2D Attack Graph Visualization with Vis.js (Tactical Cybersecurity Console)
def render_attack_graph(nodes_dict, edges, nodes_meta=None):
    theme = {
        "GitHubRepo": {
            "bg": "#2E1065", "border": "#A855F7", "highlight": "#9333EA",
            "icon": "🐙", "badge": "Repo"
        },
        "ThreatActor": {
            "bg": "#3B0D0C", "border": "#EF4444", "highlight": "#DC2626",
            "icon": "💀", "badge": "Adversary"
        },
        "AttackTechnique": {
            "bg": "#381404", "border": "#F97316", "highlight": "#EA580C",
            "icon": "⚡", "badge": "MITRE TTP"
        },
        "Vulnerability": {
            "bg": "#4C0519", "border": "#F43F5E", "highlight": "#E11D48",
            "icon": "🚨", "badge": "CVE Flaw"
        },
        "SoftwarePackage": {
            "bg": "#362003", "border": "#EAB308", "highlight": "#CA8A04",
            "icon": "📦", "badge": "Package"
        },
        "EnterpriseService": {
            "bg": "#082F49", "border": "#06B6D4", "highlight": "#0284C7",
            "icon": "🌐", "badge": "DMZ Ingress"
        },
        "EnterpriseService_Core": {
            "bg": "#1E1B4B", "border": "#818CF8", "highlight": "#6366F1",
            "icon": "🏛️", "badge": "Tier-0 Asset"
        },
        "RemediationPatch": {
            "bg": "#022C22", "border": "#10B981", "highlight": "#059669",
            "icon": "🛡️", "badge": "Remediation"
        },
        "SecurityControl": {
            "bg": "#1F2937", "border": "#9CA3AF", "highlight": "#4B5563",
            "icon": "🔒", "badge": "Control"
        }
    }

    edge_color_map = {
        "EXPLOITS": "#EF4444",
        "EXPLOITS_FLAW_IN": "#EF4444",
        "TARGETS": "#EF4444",
        "TARGETS_VULNERABILITY": "#EF4444",
        "CAN_PIVOT_TO": "#F97316",
        "LATERAL_MOVEMENT": "#F97316",
        "MITIGATED_BY": "#10B981",
        "PROTECTED_BY": "#10B981",
        "LEVERAGES": "#A855F7",
        "INCLUDES": "#0EA5E9",
        "DEPENDS_ON": "#0EA5E9",
        "RUNS_SOFTWARE": "#0EA5E9"
    }

    vis_nodes = []
    nodes_client_meta = {}
    
    for name, label in nodes_dict.items():
        props = {}
        if nodes_meta and name in nodes_meta:
            props = nodes_meta[name].get("props", {})
            
        level = get_node_level(label, name, props)
        
        lookup_label = label
        if label == "EnterpriseService" and level == 6:
            lookup_label = "EnterpriseService_Core"
            
        style = theme.get(lookup_label, {
            "bg": "#0F172A", "border": "#64748B", "highlight": "#475569",
            "icon": "🔹", "badge": label
        })
        
        if label == "ThreatActor":
            primary = name.split("(")[0].strip()
            tier = props.get("tier", "State-Sponsored APT")
            display_label = f"[{style['badge'].upper()}]\n{style['icon']} {primary}\n{tier}"
        elif label == "Vulnerability":
            cve_id = name.split("(")[0].strip()
            cve_alias = name.split("(")[1].replace(")", "").strip() if "(" in name else ""
            cvss = props.get("cvss", "10.0")
            epss = props.get("epss", "").split(" ")[0]
            metric_str = f"CVSS {cvss}" + (f" • {epss}" if epss else "")
            display_label = f"[{style['badge'].upper()}]\n{style['icon']} {cve_id}"
            if cve_alias:
                display_label += f"\n({cve_alias})"
            display_label += f"\n{metric_str}"
        elif label == "EnterpriseService":
            cloud = props.get("cloud", "")
            cloud_short = cloud.split(" ")[0] if cloud else ""
            display_label = f"[{style['badge'].upper()}]\n{style['icon']} {name}"
            if cloud_short:
                display_label += f"\n[{cloud_short}]"
        elif label == "AttackTechnique":
            t_id = props.get("id", "")
            tactic = props.get("tactic", "")
            clean_name = name[:22] + "..." if len(name) > 22 else name
            badge_txt = f"{style['badge'].upper()}: {t_id}" if t_id else style['badge'].upper()
            display_label = f"[{badge_txt}]\n{style['icon']} {clean_name}"
            if tactic:
                display_label += f"\n<{tactic}>"
        elif label == "SoftwarePackage":
            parts = name.split(":")
            if len(parts) >= 3:
                pkg_show = f"{parts[1]} v{parts[2]}"
            elif len(parts) == 2:
                pkg_show = f"{parts[0]} v{parts[1]}"
            else:
                pkg_show = name
            display_label = f"[{style['badge'].upper()}]\n{style['icon']} {pkg_show}"
        elif label == "RemediationPatch":
            clean_p = name.split("(")[0].strip()[:24]
            bulletin = props.get("bulletin", "").split("/")[0].strip()
            display_label = f"[{style['badge'].upper()}]\n{style['icon']} {clean_p}"
            if bulletin:
                display_label += f"\n{bulletin[:22]}"
        elif label == "GitHubRepo":
            clean_r = name.replace("Repo: ", "").strip()
            display_label = f"[{style['badge'].upper()}]\n{style['icon']} {clean_r}"
        else:
            clean_n = name[:26] + "..." if len(name) > 26 else name
            display_label = f"[{style['badge'].upper()}]\n{style['icon']} {clean_n}"
            
        vis_nodes.append({
            "id": name,
            "label": display_label,
            "level": level,
            "title": f"<b>[{label}]</b> {name}",
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
                "size": 11,
                "face": "ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace",
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
                "size": 10,
                "x": 2,
                "y": 2
            }
        })
        
        nodes_client_meta[name] = {
            "id": name,
            "label": label,
            "badge": style["badge"],
            "icon": style["icon"],
            "level": level,
            "props": props
        }
        
    vis_edges = []
    for e in edges:
        lbl = e["label"]
        edge_color = edge_color_map.get(lbl, "#94A3B8")
        is_critical = lbl in ["EXPLOITS", "EXPLOITS_FLAW_IN", "CAN_PIVOT_TO", "LATERAL_MOVEMENT"]
        is_mitigation = lbl in ["MITIGATED_BY", "PROTECTED_BY"]
        
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
            "dashes": True if (is_mitigation or lbl in ["CAN_PIVOT_TO", "LATERAL_MOVEMENT"]) else False,
            "font": {
                "size": 9,
                "color": "#CBD5E1",
                "background": "#070B14",
                "strokeWidth": 0,
                "align": "horizontal"
            },
            "smooth": {
                "type": "curvedCW",
                "roundness": 0.14
            }
        })
        
    nodes_json = json.dumps(vis_nodes)
    edges_json = json.dumps(vis_edges)
    meta_json = json.dumps(nodes_client_meta)
    
    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
      <script type="text/javascript" src="https://unpkg.com/vis-network/standalone/umd/vis-network.min.js"></script>
      <style type="text/css">
        body {{
          margin: 0;
          padding: 0;
          font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
          background-color: transparent;
          color: #E2E8F0;
        }}
        #graph-wrapper {{
          position: relative;
          width: 100%;
          height: 700px;
          border: 1px solid #1E293B;
          border-radius: 10px;
          background: radial-gradient(circle at 50% 50%, #0F172A 0%, #070B14 100%);
          overflow: hidden;
          box-shadow: 0 8px 32px rgba(0, 0, 0, 0.6);
          display: flex;
          flex-direction: column;
        }}
        #network {{
          width: 100%;
          height: 495px;
          background: transparent;
        }}
        .toolbar {{
          position: absolute;
          top: 10px;
          right: 12px;
          z-index: 100;
          display: flex;
          gap: 5px;
          background: rgba(11, 17, 32, 0.9);
          backdrop-filter: blur(6px);
          padding: 5px 8px;
          border-radius: 6px;
          border: 1px solid #334155;
          box-shadow: 0 4px 12px rgba(0,0,0,0.5);
        }}
        .tool-btn {{
          background: #1E293B;
          color: #CBD5E1;
          border: 1px solid #475569;
          border-radius: 4px;
          padding: 4px 9px;
          font-size: 11px;
          font-weight: 600;
          cursor: pointer;
          transition: all 0.15s ease;
          font-family: inherit;
        }}
        .tool-btn:hover {{
          background: #3B82F6;
          border-color: #60A5FA;
          color: #FFFFFF;
        }}
        .tool-btn.active-mode {{
          background: #2563EB;
          border-color: #93C5FD;
          color: #FFFFFF;
          box-shadow: 0 0 8px rgba(37, 99, 235, 0.6);
        }}
        .divider {{
          width: 1px;
          background: #334155;
          margin: 0 2px;
        }}
        .tactical-hud {{
          height: 205px;
          background: #070B14;
          border-top: 1px solid #1E293B;
          padding: 10px 14px;
          box-sizing: border-box;
          display: flex;
          flex-direction: column;
          gap: 8px;
          overflow-y: auto;
        }}
        .hud-bar {{
          display: flex;
          justify-content: space-between;
          align-items: center;
          border-bottom: 1px solid #1E293B;
          padding-bottom: 6px;
        }}
        .hud-status {{
          display: flex;
          align-items: center;
          gap: 8px;
        }}
        .hud-pulse {{
          width: 8px;
          height: 8px;
          background: #10B981;
          border-radius: 50%;
          box-shadow: 0 0 8px #10B981;
          animation: pulse 2s infinite;
        }}
        @keyframes pulse {{
          0% {{ opacity: 1; transform: scale(1); }}
          50% {{ opacity: 0.4; transform: scale(0.9); }}
          100% {{ opacity: 1; transform: scale(1); }}
        }}
        .hud-title {{
          font-size: 11px;
          font-weight: 700;
          letter-spacing: 1px;
          color: #94A3B8;
        }}
        .hud-hint {{
          font-size: 11px;
          color: #64748B;
        }}
        .hud-empty {{
          display: flex;
          align-items: center;
          gap: 12px;
          color: #64748B;
          font-size: 12px;
          margin-top: 30px;
          justify-content: center;
        }}
        .hud-grid {{
          display: grid;
          grid-template-columns: 1.4fr 1.3fr 1.3fr;
          gap: 12px;
          font-size: 11px;
        }}
        .hud-card {{
          background: #0B1120;
          border: 1px solid #1E293B;
          border-radius: 6px;
          padding: 8px 10px;
          max-height: 145px;
          overflow-y: auto;
        }}
        .hud-card-title {{
          font-size: 10px;
          font-weight: 700;
          color: #38BDF8;
          margin-bottom: 6px;
          text-transform: uppercase;
          letter-spacing: 0.5px;
        }}
        .hud-badge {{
          display: inline-block;
          padding: 2px 6px;
          border-radius: 4px;
          font-weight: 700;
          font-size: 10px;
          margin-right: 4px;
          margin-bottom: 4px;
        }}
        .hud-tag-in {{
          background: rgba(239, 68, 68, 0.12);
          border: 1px solid rgba(239, 68, 68, 0.35);
          color: #FCA5A5;
          padding: 3px 6px;
          border-radius: 4px;
          font-size: 10px;
          margin-bottom: 4px;
          display: block;
          word-break: break-all;
        }}
        .hud-tag-out {{
          background: rgba(249, 115, 22, 0.12);
          border: 1px solid rgba(249, 115, 22, 0.35);
          color: #FDBA74;
          padding: 3px 6px;
          border-radius: 4px;
          font-size: 10px;
          margin-bottom: 4px;
          display: block;
          word-break: break-all;
        }}
      </style>
    </head>
    <body>
      <div id="graph-wrapper">
        <div class="toolbar">
          <button class="tool-btn active-mode" id="btn-lr" onclick="setHierarchy('LR')">🏛️ Kill-Chain (LR)</button>
          <button class="tool-btn" id="btn-ud" onclick="setHierarchy('UD')">🔻 Kill-Chain (UD)</button>
          <button class="tool-btn" id="btn-force" onclick="setForceDirected()">🪐 Force-Directed</button>
          <span class="divider"></span>
          <button class="tool-btn" onclick="network.moveTo({{scale: network.getScale() * 1.3}})">🔍 +</button>
          <button class="tool-btn" onclick="network.moveTo({{scale: network.getScale() * 0.7}})">🔍 -</button>
          <button class="tool-btn" onclick="network.fit({{animation: {{duration: 400}}}})">🎯 Fit</button>
          <button class="tool-btn" id="freeze-btn" onclick="togglePhysics()">⏸️ Freeze</button>
        </div>
        <div id="network"></div>
        <div id="hud-panel" class="tactical-hud">
          <div class="hud-bar">
            <div class="hud-status">
              <span class="hud-pulse"></span>
              <span class="hud-title">TACTICAL ENTITY INSPECTOR</span>
            </div>
            <span id="hud-subtitle" class="hud-hint">Click any graph node to inspect telemetry & attack vectors</span>
          </div>
          <div id="hud-content">
            <div class="hud-empty">
              <span style="font-size: 20px;">🎯</span>
              <span>Click any node in the attack graph above to inspect technical telemetry, attack vectors, and lateral blast radius.</span>
            </div>
          </div>
        </div>
      </div>

      <script type="text/javascript">
        var visNodes = {nodes_json};
        var visEdges = {edges_json};
        var nodesMeta = {meta_json};
        
        var nodes = new vis.DataSet(visNodes);
        var edges = new vis.DataSet(visEdges);
        var container = document.getElementById('network');
        var data = {{ nodes: nodes, edges: edges }};
        
        var options = {{
          layout: {{
            hierarchical: {{
              enabled: true,
              direction: 'LR',
              sortMethod: 'directed',
              levelSeparation: 260,
              nodeSpacing: 110,
              treeSpacing: 140,
              parentCentralization: true,
              edgeMinimization: true
            }}
          }},
          physics: {{
            enabled: false
          }},
          interaction: {{
            hover: true,
            tooltipDelay: 80,
            zoomView: true,
            dragView: true,
            selectable: true,
            multiselect: false
          }}
        }};
        
        var network = new vis.Network(container, data, options);
        var physicsEnabled = false;
        
        function setHierarchy(dir) {{
          setActiveBtn(dir === 'LR' ? 'btn-lr' : 'btn-ud');
          network.setOptions({{
            layout: {{
              hierarchical: {{
                enabled: true,
                direction: dir,
                sortMethod: 'directed',
                levelSeparation: dir === 'LR' ? 260 : 130,
                nodeSpacing: dir === 'LR' ? 110 : 220,
                treeSpacing: 150,
                parentCentralization: true,
                edgeMinimization: true
              }}
            }},
            physics: {{ enabled: false }}
          }});
          physicsEnabled = false;
          document.getElementById('freeze-btn').innerText = '⏸️ Freeze';
          setTimeout(function() {{ network.fit({{ animation: {{ duration: 400 }} }}); }}, 80);
        }}
        
        function setForceDirected() {{
          setActiveBtn('btn-force');
          physicsEnabled = true;
          document.getElementById('freeze-btn').innerText = '⏸️ Freeze';
          network.setOptions({{
            layout: {{ hierarchical: {{ enabled: false }} }},
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
              stabilization: {{ enabled: true, iterations: 150 }}
            }}
          }});
        }}
        
        function togglePhysics() {{
          physicsEnabled = !physicsEnabled;
          network.setOptions({{ physics: {{ enabled: physicsEnabled }} }});
          document.getElementById('freeze-btn').innerText = physicsEnabled ? '⏸️ Freeze' : '▶️ Unfreeze';
        }}
        
        function setActiveBtn(btnId) {{
          ['btn-lr', 'btn-ud', 'btn-force'].forEach(function(id) {{
            var b = document.getElementById(id);
            if (b) b.classList.remove('active-mode');
          }});
          var active = document.getElementById(btnId);
          if (active) active.classList.add('active-mode');
        }}
        
        network.on("selectNode", function(params) {{
          if (params.nodes.length > 0) {{
            inspectNode(params.nodes[0]);
          }}
        }});
        
        network.on("deselectNode", function(params) {{
          resetHUD();
        }});
        
        function inspectNode(nodeId) {{
          var meta = nodesMeta[nodeId] || {{ label: "Entity", props: {{}} }};
          var p = meta.props || {{}};
          
          var allEdges = edges.get();
          var inbound = allEdges.filter(function(e) {{ return e.to === nodeId; }});
          var outbound = allEdges.filter(function(e) {{ return e.from === nodeId; }});
          
          var html = '<div class="hud-grid">';
          
          // Column 1: Node Entity & Telemetry
          html += '<div class="hud-card">';
          html += '<div class="hud-card-title">🔍 ENTITY TELEMETRY</div>';
          html += '<div style="font-weight: 700; color: #FFFFFF; font-size: 12px; margin-bottom: 6px;">' + (meta.icon || '🔹') + ' ' + nodeId + '</div>';
          
          if (p.cvss) {{
            html += '<div><span class="hud-badge" style="background:#EF4444;color:#FFF;">CVSS ' + p.cvss + '</span>';
            if (p.epss) html += '<span class="hud-badge" style="background:#B91C1C;color:#FFF;">EPSS ' + p.epss.split(' ')[0] + '</span>';
            html += '</div>';
          }}
          if (p.vector) html += '<div style="color:#94A3B8;font-size:10px;margin-top:4px;">Vector: <code style="color:#FCA5A5;">' + p.vector + '</code></div>';
          if (p.cisa_kev) html += '<div style="color:#F87171;font-size:10px;margin-top:2px;">⚠️ ' + p.cisa_kev + '</div>';
          
          if (p.cloud) html += '<div style="color:#38BDF8;font-size:10px;margin-top:4px;">☁️ ' + p.cloud + '</div>';
          if (p.zone) html += '<div style="color:#94A3B8;font-size:10px;">Subnet: ' + p.zone + '</div>';
          if (p.iam_role) html += '<div style="color:#94A3B8;font-size:10px;">IAM: <code style="color:#A78BFA;">' + p.iam_role + '</code></div>';
          
          if (p.mitre_id) html += '<div><span class="hud-badge" style="background:#7C3AED;color:#FFF;">' + p.mitre_id + '</span> <span style="color:#C4B5FD;">' + (p.origin || '') + '</span></div>';
          if (p.motive) html += '<div style="color:#94A3B8;font-size:10px;margin-top:2px;">Motive: ' + p.motive + '</div>';
          
          if (p.bulletin) html += '<div style="color:#34D399;font-size:10px;margin-top:4px;">📋 ' + p.bulletin + '</div>';
          if (p.hotfix) html += '<div style="color:#A7F3D0;font-size:10px;margin-top:2px;">Fix: <code>' + p.hotfix + '</code></div>';
          html += '</div>';
          
          // Column 2: Inbound Attack Vectors
          html += '<div class="hud-card">';
          html += '<div class="hud-card-title">⬅ INBOUND ATTACK VECTORS (' + inbound.length + ')</div>';
          if (inbound.length === 0) {{
            html += '<div style="color:#64748B;font-size:10px;">No inbound exploitation paths (Perimeter / Root)</div>';
          }} else {{
            for (var i = 0; i < inbound.length; i++) {{
              var ie = inbound[i];
              html += '<div class="hud-tag-in">⬅ <b>' + ie.from + '</b><br><span style="color:#F87171;">[' + ie.label + ']</span></div>';
            }}
          }}
          html += '</div>';
          
          // Column 3: Outbound Blast Radius
          html += '<div class="hud-card">';
          html += '<div class="hud-card-title">➔ BLAST RADIUS / LATERAL MOVES (' + outbound.length + ')</div>';
          if (outbound.length === 0) {{
            html += '<div style="color:#64748B;font-size:10px;">Terminal target / Countermeasure leaf node</div>';
          }} else {{
            for (var j = 0; j < outbound.length; j++) {{
              var oe = outbound[j];
              html += '<div class="hud-tag-out">➔ <span style="color:#FBBF24;">[' + oe.label + ']</span><br><b>' + oe.to + '</b></div>';
            }}
          }}
          html += '</div>';
          
          html += '</div>';
          
          document.getElementById('hud-content').innerHTML = html;
          document.getElementById('hud-subtitle').innerText = 'Inspecting: ' + nodeId;
        }}
        
        function resetHUD() {{
          document.getElementById('hud-content').innerHTML = '<div class="hud-empty"><span style="font-size: 20px;">🎯</span><span>Click any node in the attack graph above to inspect technical telemetry, attack vectors, and lateral blast radius.</span></div>';
          document.getElementById('hud-subtitle').innerText = 'Click any graph node to inspect telemetry & attack vectors';
        }}
      </script>
    </body>
    </html>
    """
    components.html(html, height=720)

# Layout
col1, col2 = st.columns([1, 1])

with col1:
    tab_query, tab_sbom, tab_benchmark = st.tabs(["🕵️ Threat Query", "📦 GitHub & SBOM Supply Chain", "📊 Empirical Benchmark"])
    
    with tab_query:
        sample_queries = [
            "How can APT29 exploit our public-facing services (e.g. k8s-auth-ingress-gateway) to compromise payment-token-vault-service, and what patch mitigates this?",
            "What is the downstream blast radius and lateral movement path if CVE-2021-44228 (Log4Shell) is targeted against k8s-auth-ingress-gateway?",
            "Evaluate how Volt Typhoon pre-positions in edge-vpn-gateway-fortigate to pivot into corporate-active-directory-dc01.",
            "Analyze the supply chain compromise vector for CVE-2024-3094 (XZ Utils) against enterprise-bastion-ssh-host and its data lake blast radius.",
            "Which threat actors leverage Supply Chain Compromise, and which software packages and infrastructure are affected?"
        ]
        selected_sample = st.selectbox("Select a Preset Threat Scenario (or write your own below):", sample_queries)
        
        user_query = st.text_area("Security Analyst Query:", value=selected_sample, height=90)
        
        if st.button("🚨 Analyze Attack Graph & Blast Radius", type="primary"):
            with st.spinner("Traversing Cyber Threat Graph & Synthesizing SOC Report..."):
                entities = extract_entities(user_query)
                facts, nodes_dict, edges, nodes_meta = fetch_threat_subgraph(entities)
                answer = answer_threat_query(user_query, facts)
                
                st.session_state["answer"] = answer
                st.session_state["entities"] = entities
                st.session_state["facts"] = facts
                st.session_state["nodes_dict"] = nodes_dict
                st.session_state["edges"] = edges
                st.session_state["nodes_meta"] = nodes_meta

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
                            st.session_state["nodes_meta"] = eval_res["vis_graph"].get("nodes_meta", {})
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
                        nodes_meta = {}
                        all_cves = set()
                        all_actors = set()
                        
                        with driver.session() as session:
                            for svc in sbom_data["services"]:
                                s_name = svc["name"]
                                svc_rec = session.run("MATCH (s:EnterpriseService {name: $name}) RETURN properties(s) AS props", name=s_name).single()
                                s_props = dict(svc_rec["props"]) if svc_rec else {}
                                infected_nodes[s_name] = "EnterpriseService"
                                nodes_meta[s_name] = {"label": "EnterpriseService", "props": s_props}
                                
                                # Discover lateral movement blast radius
                                for piv_rec in session.run("MATCH (s:EnterpriseService {name: $name})-[:CAN_PIVOT_TO]->(p:EnterpriseService) RETURN p.name AS p_name, properties(p) AS p_props", name=s_name):
                                    piv_name = piv_rec["p_name"]
                                    piv_props = dict(piv_rec["p_props"])
                                    infected_nodes[piv_name] = "EnterpriseService"
                                    nodes_meta[piv_name] = {"label": "EnterpriseService", "props": piv_props}
                                    infected_edges.append({"from": s_name, "to": piv_name, "label": "CAN_PIVOT_TO"})

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
                                        p.name AS pkg, properties(p) AS pkg_props,
                                        v.name AS cve, properties(v) AS vuln_props,
                                        actor.name AS actor, properties(actor) AS actor_props,
                                        patch.name AS patch, properties(patch) AS patch_props,
                                        tech.name AS tech, properties(tech) AS tech_props
                                    """
                                    for r in session.run(cypher, dep_name=dep_search):
                                        if r["cve"]:
                                            all_cves.add(r["cve"])
                                            if r["actor"]: all_actors.add(r["actor"])
                                            v_props = dict(r["vuln_props"]) if r["vuln_props"] else {}
                                            findings.append({
                                                "Service": s_name,
                                                "Vulnerable Package": dep,
                                                "CVE": r["cve"],
                                                "CVSS": v_props.get("cvss", 9.8),
                                                "Threat Actor": r["actor"] or "Undisclosed",
                                                "Remediation Patch": r["patch"] or "Vendor Update"
                                            })
                                            pkg_name = r["pkg"]
                                            cve_name = r["cve"]
                                            infected_nodes[pkg_name] = "SoftwarePackage"
                                            infected_nodes[cve_name] = "Vulnerability"
                                            nodes_meta[pkg_name] = {"label": "SoftwarePackage", "props": dict(r["pkg_props"]) if r["pkg_props"] else {}}
                                            nodes_meta[cve_name] = {"label": "Vulnerability", "props": v_props}
                                            
                                            infected_edges.append({"from": s_name, "to": pkg_name, "label": "DEPENDS_ON"})
                                            infected_edges.append({"from": cve_name, "to": pkg_name, "label": "EXPLOITS"})
                                            
                                            if r["actor"]:
                                                act_name = r["actor"]
                                                infected_nodes[act_name] = "ThreatActor"
                                                nodes_meta[act_name] = {"label": "ThreatActor", "props": dict(r["actor_props"]) if r["actor_props"] else {}}
                                                if r["tech"]:
                                                    t_name = r["tech"]
                                                    infected_nodes[t_name] = "AttackTechnique"
                                                    nodes_meta[t_name] = {"label": "AttackTechnique", "props": dict(r["tech_props"]) if r["tech_props"] else {}}
                                                    infected_edges.append({"from": act_name, "to": t_name, "label": "LEVERAGES"})
                                                    infected_edges.append({"from": t_name, "to": cve_name, "label": "TARGETS"})
                                                else:
                                                    infected_edges.append({"from": act_name, "to": cve_name, "label": "TARGETS"})
                                                    
                                            if r["patch"]:
                                                patch_name = r["patch"]
                                                infected_nodes[patch_name] = "RemediationPatch"
                                                nodes_meta[patch_name] = {"label": "RemediationPatch", "props": dict(r["patch_props"]) if r["patch_props"] else {}}
                                                infected_edges.append({"from": cve_name, "to": patch_name, "label": "MITIGATED_BY"})

                        st.session_state["nodes_dict"] = infected_nodes
                        st.session_state["edges"] = infected_edges
                        st.session_state["nodes_meta"] = nodes_meta
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
        <span style="background: #3B0D0C; color: #FCA5A5; padding: 3px 8px; border-radius: 4px; border: 1px solid #EF4444;">💀 Adversary</span>
        <span style="background: #381404; color: #FDBA74; padding: 3px 8px; border-radius: 4px; border: 1px solid #F97316;">⚡ MITRE TTP</span>
        <span style="background: #4C0519; color: #FDA4AF; padding: 3px 8px; border-radius: 4px; border: 1px solid #F43F5E;">🚨 CVE Flaw</span>
        <span style="background: #362003; color: #FDE047; padding: 3px 8px; border-radius: 4px; border: 1px solid #EAB308;">📦 Package</span>
        <span style="background: #082F49; color: #67E8F9; padding: 3px 8px; border-radius: 4px; border: 1px solid #06B6D4;">🌐 DMZ Ingress</span>
        <span style="background: #1E1B4B; color: #C7D2FE; padding: 3px 8px; border-radius: 4px; border: 1px solid #818CF8;">🏛️ Tier-0 Asset</span>
        <span style="background: #022C22; color: #6EE7B7; padding: 3px 8px; border-radius: 4px; border: 1px solid #10B981;">🛡️ Remediation</span>
        <span style="background: #2E1065; color: #E9D5FF; padding: 3px 8px; border-radius: 4px; border: 1px solid #A855F7;">🐙 Repo</span>
    </div>
    """, unsafe_allow_html=True)
    if "edges" in st.session_state and st.session_state["edges"]:
        st.caption(f"Showing attack path for: {', '.join(st.session_state.get('entities', []))} • (Click any node to inspect in HUD)")
        render_attack_graph(st.session_state["nodes_dict"], st.session_state["edges"], st.session_state.get("nodes_meta"))
    else:
        st.info("Execute a threat scenario on the left to visualize the attack path and lateral movement graph!")
