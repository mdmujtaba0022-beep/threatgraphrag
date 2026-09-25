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
import importlib
import sys

if "src.report_generator" in sys.modules:
    try:
        importlib.reload(sys.modules["src.report_generator"])
    except Exception:
        pass

if "src.cache_manager" in sys.modules:
    try:
        importlib.reload(sys.modules["src.cache_manager"])
    except Exception:
        pass

try:
    from src.report_generator import (
        synthesize_technical_report,
        synthesize_technical_report_stream,
        synthesize_copilot_followup_stream,
        synthesize_copilot_followup
    )
except ImportError:
    import src.report_generator as _rg
    importlib.reload(_rg)
    synthesize_technical_report = getattr(_rg, "synthesize_technical_report")
    synthesize_technical_report_stream = getattr(_rg, "synthesize_technical_report_stream")
    synthesize_copilot_followup_stream = getattr(_rg, "synthesize_copilot_followup_stream")
    synthesize_copilot_followup = getattr(_rg, "synthesize_copilot_followup")

from src.cache_manager import threat_cache

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

# Sidebar Telemetry & Cache Health
with st.sidebar:
    st.markdown("### ⚡ Engine Performance")
    st.caption("Real-Time Graph Index & Semantic Cache")
    c_stats = threat_cache.get_stats()
    
    col_sb1, col_sb2 = st.columns(2)
    col_sb1.metric("Cache Hit Rate", f"{c_stats['hit_ratio_percent']}%")
    col_sb2.metric("Saved Latency", f"{c_stats['estimated_latency_saved_seconds']}s")
    
    st.metric("Estimated Tokens Saved", f"{c_stats['estimated_tokens_saved']:,}")
    st.markdown(f"**Index:** `Neo4j Full-Text (Active)`  \n**Capacity:** `{c_stats['total_entries']}/{c_stats['capacity']}` entries")
    
    if st.button("🧹 Flush Semantic Cache", use_container_width=True):
        threat_cache.clear()
        st.success("Cache cleared!")
        st.rerun()
    st.markdown("---")

from src.graph_engine import (
    extract_cyber_entities,
    fetch_precision_threat_graph,
    calculate_graph_threat_metrics,
    simulate_countermeasure,
    compute_graph_chokepoints
)

# Schemas
class QueryEntities(BaseModel):
    entities: List[str] = Field(description="Cyber entities mentioned in query: threat actors, CVEs, services, techniques, or packages")

def extract_entities(query: str) -> List[str]:
    """Precision entity extraction combining regex, knowledge base vocab trie, and Gemini 3.8/3.5 semantic fallback."""
    return extract_cyber_entities(query, client=client)

def fetch_threat_subgraph(entities: List[str]):
    """
    High-precision multi-hop attack path retrieval:
    1. Multi-hop shortest paths connecting entity pairs
    2. Contextual blast radius expansion (mitigations, packages, ingress/pivots)
    3. Quantitative graph threat metrics (risk index, path depth, crown jewels)
    """
    return fetch_precision_threat_graph(driver, entities)

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

def render_attack_graph(nodes_dict, edges, nodes_meta=None, graph_height=720, chokepoint_node=None):
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
            
        is_chokepoint = bool(chokepoint_node and (chokepoint_node.lower() == name.lower() or chokepoint_node.lower() in name.lower()))
        if is_chokepoint:
            display_label = f"🎯 [CHOKEPOINT]\n" + display_label

        node_bg = "#78350F" if is_chokepoint else style["bg"]
        node_border = "#F59E0B" if is_chokepoint else style["border"]
        node_highlight_bg = "#92400E" if is_chokepoint else style["highlight"]
        node_highlight_border = "#FBBF24" if is_chokepoint else "#FFFFFF"
        node_border_width = 4 if is_chokepoint else 2
        node_shadow_color = "#F59E0B" if is_chokepoint else "rgba(0,0,0,0.6)"
        node_shadow_size = 18 if is_chokepoint else 10
        node_font_color = "#FEF08A" if is_chokepoint else "#F8FAFC"
            
        vis_nodes.append({
            "id": name,
            "label": display_label,
            "level": level,
            "title": f"<b>[{label}]</b> {name}" + ("<br><b><span style='color:#F59E0B;'>🎯 CRITICAL GRAPH CHOKEPOINT</span></b>" if is_chokepoint else ""),
            "color": {
                "background": node_bg,
                "border": node_border,
                "highlight": {
                    "background": node_highlight_bg,
                    "border": node_highlight_border
                },
                "hover": {
                    "background": node_highlight_bg,
                    "border": node_highlight_border
                }
            },
            "font": {
                "color": node_font_color,
                "size": 11,
                "face": "ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace",
                "align": "center"
            },
            "shape": "box",
            "margin": 10,
            "shapeProperties": {
                "borderRadius": 6
            },
            "borderWidth": node_border_width,
            "borderWidthSelected": 4 if is_chokepoint else 3,
            "shadow": {
                "enabled": True,
                "color": node_shadow_color,
                "size": node_shadow_size,
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
    
    wrapper_h = max(380, int(graph_height))
    hud_h = min(220, max(135, int(wrapper_h * 0.28)))
    network_h = max(220, wrapper_h - hud_h - 10)

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
          height: {wrapper_h}px;
          border: 1px solid #1E293B;
          border-radius: 10px;
          background: radial-gradient(circle at 50% 50%, #0F172A 0%, #070B14 100%);
          overflow: hidden;
          box-shadow: 0 8px 32px rgba(0, 0, 0, 0.6);
          display: flex;
          flex-direction: column;
          transition: height 0.2s ease;
        }}
        #network {{
          width: 100%;
          height: {network_h}px;
          background: transparent;
          transition: height 0.2s ease;
        }}
        .layout-bar {{
          position: absolute;
          top: 10px;
          left: 12px;
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
        .zoom-toolbar {{
          position: absolute;
          top: 10px;
          right: 12px;
          z-index: 100;
          display: flex;
          flex-direction: column;
          gap: 4px;
          background: rgba(11, 17, 32, 0.9);
          backdrop-filter: blur(6px);
          padding: 4px;
          border-radius: 6px;
          border: 1px solid #334155;
          box-shadow: 0 4px 12px rgba(0,0,0,0.5);
        }}
        .zoom-btn {{
          width: 28px;
          height: 28px;
          background: #1E293B;
          color: #E2E8F0;
          border: 1px solid #475569;
          border-radius: 4px;
          font-size: 13px;
          font-weight: 700;
          cursor: pointer;
          display: flex;
          align-items: center;
          justify-content: center;
          transition: all 0.15s ease;
          font-family: inherit;
        }}
        .zoom-btn:hover {{
          background: #3B82F6;
          border-color: #60A5FA;
          color: #FFFFFF;
          transform: scale(1.08);
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
          height: {hud_h}px;
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
        <div class="layout-bar">
          <button class="tool-btn active-mode" id="btn-lr" onclick="setHierarchy('LR')">🏛️ Kill-Chain (LR)</button>
          <button class="tool-btn" id="btn-ud" onclick="setHierarchy('UD')">🔻 Kill-Chain (UD)</button>
          <button class="tool-btn" id="btn-force" onclick="setForceDirected()">🪐 Force</button>
          <button class="tool-btn" id="freeze-btn" onclick="togglePhysics()">⏸️ Freeze</button>
          <button class="tool-btn" onclick="downloadGraphPNG()" title="Download High-Res Attack Graph as PNG Image">📷 Export PNG</button>
          <button class="tool-btn" onclick="downloadGraphJSON()" title="Download Topology Graph Data as JSON">📥 Export JSON</button>
        </div>
        <div class="zoom-toolbar">
          <button class="zoom-btn" onclick="network.moveTo({{scale: network.getScale() * 1.35}})" title="Zoom In (+)">➕</button>
          <button class="zoom-btn" onclick="network.moveTo({{scale: network.getScale() * 0.72}})" title="Zoom Out (-)">➖</button>
          <button class="zoom-btn" onclick="network.fit({{animation: {{duration: 350}}}})" title="Reset View (🎯)">🎯</button>
          <button class="zoom-btn" onclick="downloadGraphPNG()" title="Download Graph Image (PNG)">📷</button>
          <button class="zoom-btn" onclick="downloadGraphJSON()" title="Download Graph JSON (📥)">📥</button>
          <button class="zoom-btn" id="fs-btn" onclick="toggleFullscreen()" title="Fullscreen Toggle (⛶)">⛶</button>
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

        function downloadGraphPNG() {{
          try {{
            var canvas = document.querySelector('#network canvas');
            if (!canvas) return;
            var offscreen = document.createElement('canvas');
            offscreen.width = canvas.width;
            offscreen.height = canvas.height;
            var ctx = offscreen.getContext('2d');
            ctx.fillStyle = '#0B1120';
            ctx.fillRect(0, 0, offscreen.width, offscreen.height);
            ctx.drawImage(canvas, 0, 0);
            var a = document.createElement('a');
            a.download = 'ThreatGraphRAG_Attack_Topology.png';
            a.href = offscreen.toDataURL('image/png');
            a.click();
          }} catch(err) {{
            console.error('Export graph error:', err);
          }}
        }}

        function downloadGraphJSON() {{
          try {{
            var exportObj = {{
              title: 'ThreatGraphRAG Attack Graph Topology',
              exportedAt: new Date().toISOString(),
              nodes: visNodes,
              edges: visEdges,
              metadata: nodesMeta
            }};
            var blob = new Blob([JSON.stringify(exportObj, null, 2)], {{ type: 'application/json' }});
            var url = URL.createObjectURL(blob);
            var a = document.createElement('a');
            a.download = 'ThreatGraphRAG_Attack_Topology.json';
            a.href = url;
            a.click();
            URL.revokeObjectURL(url);
          }} catch(err) {{
            console.error('Export JSON error:', err);
          }}
        }}

        function toggleFullscreen() {{
          var el = document.getElementById('graph-wrapper');
          if (!document.fullscreenElement && !document.webkitFullscreenElement) {{
            if (el.requestFullscreen) {{ el.requestFullscreen(); }}
            else if (el.webkitRequestFullscreen) {{ el.webkitRequestFullscreen(); }}
            else if (el.msRequestFullscreen) {{ el.msRequestFullscreen(); }}
          }} else {{
            if (document.exitFullscreen) {{ document.exitFullscreen(); }}
            else if (document.webkitExitFullscreen) {{ document.webkitExitFullscreen(); }}
          }}
        }}

        function handleFSEvent() {{
          var isFull = !!(document.fullscreenElement || document.webkitFullscreenElement);
          var fsBtn = document.getElementById('fs-btn');
          var wrapper = document.getElementById('graph-wrapper');
          var net = document.getElementById('network');
          if (isFull) {{
            if (fsBtn) fsBtn.innerText = '✖ Exit';
            wrapper.style.height = '100vh';
            net.style.height = 'calc(100vh - 220px)';
          }} else {{
            if (fsBtn) fsBtn.innerText = '⛶ Fullscreen';
            wrapper.style.height = '{wrapper_h}px';
            net.style.height = '{network_h}px';
          }}
          setTimeout(function() {{ network.fit({{ animation: {{ duration: 300 }} }}); }}, 120);
        }}

        document.addEventListener('fullscreenchange', handleFSEvent);
        document.addEventListener('webkitfullscreenchange', handleFSEvent);
      </script>
    </body>
    </html>
    """
    components.html(html, height=wrapper_h + 20)

# Two-column layout with interactive draggable boundary splitter
st.markdown("""
<style>
/* Style the gap between columns */
[data-testid="stHorizontalBlock"] {
  position: relative !important;
}

.threat-boundary-gutter {
  position: absolute !important;
  top: 0 !important;
  bottom: 0 !important;
  width: 16px !important;
  cursor: col-resize !important;
  z-index: 9999 !important;
  display: flex !important;
  align-items: center !important;
  justify-content: center !important;
  user-select: none !important;
  touch-action: none !important;
}

.threat-boundary-line {
  width: 2px !important;
  height: 100% !important;
  background: #334155 !important;
  border-radius: 1px !important;
  transition: all 0.15s ease !important;
}

.threat-boundary-gutter:hover .threat-boundary-line,
.threat-boundary-gutter.dragging .threat-boundary-line {
  background: #3B82F6 !important;
  width: 4px !important;
  box-shadow: 0 0 10px rgba(59, 130, 246, 0.8) !important;
}

.threat-boundary-handle {
  position: absolute !important;
  top: 40% !important;
  transform: translateY(-50%) !important;
  width: 24px !important;
  height: 60px !important;
  background: #0B1120 !important;
  border: 1px solid #475569 !important;
  border-radius: 8px !important;
  display: flex !important;
  flex-direction: column !important;
  align-items: center !important;
  justify-content: center !important;
  gap: 3px !important;
  box-shadow: 0 4px 14px rgba(0, 0, 0, 0.6) !important;
  cursor: col-resize !important;
  transition: all 0.15s ease !important;
}

.threat-boundary-gutter:hover .threat-boundary-handle,
.threat-boundary-gutter.dragging .threat-boundary-handle {
  border-color: #3B82F6 !important;
  background: #1E293B !important;
  box-shadow: 0 0 12px rgba(59, 130, 246, 0.5) !important;
}

.threat-collapse-btn-left,
.threat-collapse-btn-right {
  font-size: 10px !important;
  color: #94A3B8 !important;
  cursor: pointer !important;
  padding: 2px !important;
  transition: color 0.15s ease, transform 0.15s ease !important;
}

.threat-collapse-btn-left:hover {
  color: #60A5FA !important;
  transform: scale(1.2) !important;
}

.threat-collapse-btn-right:hover {
  color: #60A5FA !important;
  transform: scale(1.2) !important;
}

.threat-drag-dots {
  font-size: 11px !important;
  color: #64748B !important;
  line-height: 1 !important;
  pointer-events: none !important;
}

/* Report Fullscreen Styling */
.report-fullscreen-icon {
  background: #1E293B !important;
  color: #CBD5E1 !important;
  border: 1px solid #475569 !important;
  border-radius: 4px !important;
  padding: 4px 10px !important;
  font-size: 11px !important;
  font-weight: 600 !important;
  cursor: pointer !important;
  display: inline-flex !important;
  align-items: center !important;
  gap: 5px !important;
  transition: all 0.15s ease !important;
  font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace !important;
}

.report-fullscreen-icon:hover {
  background: #2563EB !important;
  border-color: #60A5FA !important;
  color: #FFFFFF !important;
  box-shadow: 0 0 8px rgba(37, 99, 235, 0.6) !important;
}

.report-fullscreen-active {
  position: fixed !important;
  top: 0 !important;
  left: 0 !important;
  right: 0 !important;
  bottom: 0 !important;
  width: 100vw !important;
  height: 100vh !important;
  max-width: 100vw !important;
  max-height: 100vh !important;
  z-index: 2147483647 !important;
  background: #070B14 !important;
  color: #E2E8F0 !important;
  padding: 32px 50px !important;
  overflow-y: auto !important;
  box-sizing: border-box !important;
  box-shadow: 0 0 80px rgba(0, 0, 0, 0.95) !important;
}

[data-testid="stVerticalBlock"]:fullscreen,
[data-testid="stColumn"]:fullscreen {
  width: 100vw !important;
  height: 100vh !important;
  background: #070B14 !important;
  color: #E2E8F0 !important;
  padding: 32px 50px !important;
  overflow-y: auto !important;
  box-sizing: border-box !important;
}

.report-fullscreen-active .stMarkdown,
[data-testid="stVerticalBlock"]:fullscreen .stMarkdown,
[data-testid="stColumn"]:fullscreen .stMarkdown {
  max-width: 1180px !important;
  margin: 0 auto !important;
  line-height: 1.65 !important;
}

.report-fullscreen-active [data-testid="element-container"],
[data-testid="stVerticalBlock"]:fullscreen [data-testid="element-container"],
[data-testid="stColumn"]:fullscreen [data-testid="element-container"] {
  max-width: 1180px !important;
  margin-left: auto !important;
  margin-right: auto !important;
}

.report-fullscreen-active .report-fullscreen-icon {
  background: #DC2626 !important;
  border-color: #EF4444 !important;
  color: #FFFFFF !important;
  font-weight: 700 !important;
  box-shadow: 0 0 10px rgba(220, 38, 38, 0.6) !important;
}

.report-fullscreen-active .report-fullscreen-icon:hover {
  background: #B91C1C !important;
  border-color: #F87171 !important;
}

/* Controlled Font Size for CTI Advisory & Threat Headings */
.stMarkdown h1, .stMarkdown h2, .stMarkdown h3 {
  letter-spacing: -0.2px !important;
}

div[data-testid="stMarkdownContainer"] h1,
div[data-testid="stMarkdownContainer"] > h1:first-child,
div[data-testid="stMarkdownContainer"] > h2:first-child,
div[data-testid="stMarkdownContainer"] > h3:first-child,
.cti-advisory-title {
  font-size: 1.18rem !important;
  font-weight: 700 !important;
  line-height: 1.38 !important;
  color: #38BDF8 !important;
  margin-top: 6px !important;
  margin-bottom: 8px !important;
  border-bottom: 1px solid #1E293B !important;
  padding-bottom: 6px !important;
  word-break: break-word !important;
}

div[data-testid="stMarkdownContainer"] h2 {
  font-size: 1.10rem !important;
  font-weight: 600 !important;
  color: #93C5FD !important;
  margin-top: 10px !important;
  margin-bottom: 6px !important;
}

div[data-testid="stMarkdownContainer"] h3 {
  font-size: 1.02rem !important;
  font-weight: 600 !important;
  color: #E2E8F0 !important;
  margin-top: 10px !important;
  margin-bottom: 6px !important;
}
</style>
""", unsafe_allow_html=True)

container_report, container_graph = st.columns([1, 1])

# Boundary Splitter Script: Allows taking mouse to boundary line to drag/minimize/maximize
components.html("""
<script>
(function() {
  function setupBoundarySplitter() {
    try {
      const pDoc = window.parent.document;
      if (!pDoc) return;
      
      const hBlocks = pDoc.querySelectorAll('[data-testid="stHorizontalBlock"]');
      let targetBlock = null;
      let leftCol = null;
      let rightCol = null;
      
      for (const block of hBlocks) {
        const cols = block.querySelectorAll(':scope > [data-testid="stColumn"]');
        if (cols.length === 2) {
          targetBlock = block;
          leftCol = cols[0];
          rightCol = cols[1];
          break;
        }
      }
      
      if (!targetBlock || !leftCol || !rightCol) return;
      
      targetBlock.style.position = 'relative';
      targetBlock.style.overflow = 'visible';
      leftCol.style.position = 'relative';
      leftCol.style.paddingRight = '12px';
      rightCol.style.paddingLeft = '12px';
      
      let gutter = targetBlock.querySelector('.threat-boundary-gutter');
      if (!gutter) {
        gutter = pDoc.createElement('div');
        gutter.className = 'threat-boundary-gutter';
        gutter.title = 'Drag boundary left/right to resize • Click arrows to minimize/maximize';
        gutter.innerHTML = `
          <div class="threat-boundary-line"></div>
          <div class="threat-boundary-handle">
            <span class="threat-collapse-btn-left" title="Minimize Report / Maximize Graph">◀</span>
            <span class="threat-drag-dots">⋮</span>
            <span class="threat-collapse-btn-right" title="Minimize Graph / Maximize Report">▶</span>
          </div>
        `;
        targetBlock.appendChild(gutter);
        
        let isDragging = false;
        let startX = 0;
        let startLeftW = 0;
        
        function setWidths(leftPercent) {
          leftPercent = Math.max(5, Math.min(95, leftPercent));
          sessionStorage.setItem('threat_split_ratio', leftPercent);
          leftCol.style.flex = 'none';
          leftCol.style.width = leftPercent + '%';
          rightCol.style.flex = 'none';
          rightCol.style.width = (100 - leftPercent) + '%';
          gutter.style.left = `calc(${leftPercent}% - 8px)`;
          window.parent.dispatchEvent(new Event('resize'));
        }
        
        const saved = sessionStorage.getItem('threat_split_ratio');
        if (saved) {
          setWidths(parseFloat(saved));
        } else {
          gutter.style.left = 'calc(50% - 8px)';
        }
        
        gutter.addEventListener('mousedown', function(e) {
          if (e.target.classList.contains('threat-collapse-btn-left')) {
            const currentW = (leftCol.getBoundingClientRect().width / targetBlock.getBoundingClientRect().width) * 100;
            setWidths(currentW > 20 ? 8 : 50);
            e.stopPropagation();
            return;
          }
          if (e.target.classList.contains('threat-collapse-btn-right')) {
            const currentW = (leftCol.getBoundingClientRect().width / targetBlock.getBoundingClientRect().width) * 100;
            setWidths(currentW < 80 ? 92 : 50);
            e.stopPropagation();
            return;
          }
          
          isDragging = true;
          startX = e.clientX;
          startLeftW = leftCol.getBoundingClientRect().width;
          gutter.classList.add('dragging');
          pDoc.body.style.cursor = 'col-resize';
          pDoc.body.style.userSelect = 'none';
          
          pDoc.querySelectorAll('iframe').forEach(f => f.style.pointerEvents = 'none');
          e.preventDefault();
        });
        
        gutter.addEventListener('dblclick', function() {
          setWidths(50);
        });
        
        pDoc.addEventListener('mousemove', function(e) {
          if (!isDragging) return;
          const totalW = targetBlock.getBoundingClientRect().width;
          const delta = e.clientX - startX;
          const newW = startLeftW + delta;
          const pct = (newW / totalW) * 100;
          setWidths(pct);
        });
        
        pDoc.addEventListener('mouseup', function() {
          if (isDragging) {
            isDragging = false;
            gutter.classList.remove('dragging');
            pDoc.body.style.cursor = '';
            pDoc.body.style.userSelect = '';
            pDoc.querySelectorAll('iframe').forEach(f => f.style.pointerEvents = '');
            window.parent.dispatchEvent(new Event('resize'));
          }
        });
      } else {
        const saved = sessionStorage.getItem('threat_split_ratio');
        if (saved) {
          const pct = parseFloat(saved);
          leftCol.style.flex = 'none';
          leftCol.style.width = pct + '%';
          rightCol.style.flex = 'none';
          rightCol.style.width = (100 - pct) + '%';
          gutter.style.left = `calc(${pct}% - 8px)`;
        }
      }
    } catch(err) {
      console.error('Splitter error:', err);
    }
  }

  function enforceCTISizes() {
    try {
      const pDoc = window.parent.document;
      if (!pDoc) return;
      pDoc.querySelectorAll('h1, h2, h3').forEach(function(el) {
        if (el.textContent && el.textContent.includes('CTI ADVISORY')) {
          el.style.setProperty('font-size', '1.18rem', 'important');
          el.style.setProperty('line-height', '1.38', 'important');
          el.style.setProperty('color', '#38BDF8', 'important');
          el.style.setProperty('font-weight', '700', 'important');
          el.style.setProperty('border-bottom', '1px solid #1E293B', 'important');
          el.style.setProperty('padding-bottom', '6px', 'important');
          el.style.setProperty('margin-top', '6px', 'important');
          el.style.setProperty('margin-bottom', '8px', 'important');
          el.style.setProperty('word-break', 'break-word', 'important');
        }
      });
    } catch(e) {}
  }

  function handlePageUpdates() {
    setupBoundarySplitter();
    enforceCTISizes();
  }

  setTimeout(handlePageUpdates, 200);
  setTimeout(handlePageUpdates, 600);
  setTimeout(handlePageUpdates, 1500);
  try {
    const observer = new MutationObserver(handlePageUpdates);
    observer.observe(window.parent.document.body, { childList: true, subtree: true });
  } catch(e) {}

  // --- Enhanced Report Fullscreen Engine ---
  function getReportTarget(btn) {
    const pDoc = window.parent.document;
    if (!pDoc) return null;
    
    const kind = btn ? btn.getAttribute('data-report-fs') : null;
    
    if (kind === 'window') {
      const hBlock = pDoc.querySelector('[data-testid="stHorizontalBlock"]');
      if (hBlock) {
        const cols = hBlock.querySelectorAll(':scope > [data-testid="stColumn"]');
        if (cols.length >= 1) return cols[0];
      }
    }
    
    const marker = pDoc.getElementById('threat-report-marker');
    if (marker) {
      const container = marker.closest('[data-testid="stVerticalBlock"]');
      if (container) return container;
    }
    
    if (btn) {
      const vBlock = btn.closest('[data-testid="stVerticalBlock"]');
      if (vBlock) return vBlock;
    }
    
    const hBlock = pDoc.querySelector('[data-testid="stHorizontalBlock"]');
    if (hBlock) {
      const cols = hBlock.querySelectorAll(':scope > [data-testid="stColumn"]');
      if (cols.length >= 1) return cols[0];
    }
    return null;
  }

  function updateAllReportButtons(isFS) {
    try {
      const pDoc = window.parent.document;
      if (!pDoc) return;
      const btns = pDoc.querySelectorAll('.report-fullscreen-icon, [data-report-fs], #report-fs-btn');
      btns.forEach(btn => {
        const icon = btn.querySelector('.fs-icon') || btn.querySelector('#report-fs-icon');
        const text = btn.querySelector('.fs-text') || btn.querySelector('#report-fs-text');
        if (icon) icon.innerText = isFS ? '✖' : '⛶';
        if (text) text.innerText = isFS ? 'Exit Fullscreen' : 'Fullscreen';
        btn.title = isFS ? 'Exit Fullscreen Reading View (Esc)' : 'Toggle Fullscreen Reading View (⛶)';
      });
    } catch(e) {}
  }

  window.parent.toggleReportFullscreen = function(btn) {
    try {
      const pDoc = window.parent.document;
      if (!pDoc) return;
      
      const activeEl = pDoc.querySelector('.report-fullscreen-active');
      const isAlreadyFS = !!activeEl || !!pDoc.fullscreenElement || pDoc.body.classList.contains('report-fs-active');
      
      if (isAlreadyFS) {
        window.parent.exitReportFullscreen();
      } else {
        const target = getReportTarget(btn);
        if (!target) return;
        
        target.classList.add('report-fullscreen-active');
        pDoc.body.classList.add('report-fs-active');
        pDoc.body.style.overflow = 'hidden';
        updateAllReportButtons(true);
        
        try {
          if (!pDoc.fullscreenElement && target.requestFullscreen) {
            target.requestFullscreen().catch(() => {});
          }
        } catch(e) {}
      }
    } catch(err) {
      console.error('Report Fullscreen error:', err);
    }
  };

  window.parent.exitReportFullscreen = function() {
    try {
      const pDoc = window.parent.document;
      if (!pDoc) return;
      
      const targets = pDoc.querySelectorAll('.report-fullscreen-active');
      targets.forEach(t => t.classList.remove('report-fullscreen-active'));
      pDoc.body.classList.remove('report-fs-active');
      pDoc.body.style.overflow = '';
      updateAllReportButtons(false);
      
      try {
        if (pDoc.fullscreenElement && pDoc.exitFullscreen) {
          pDoc.exitFullscreen().catch(() => {});
        }
      } catch(e) {}
    } catch(e) {}
  };

  // Backwards compatibility
  window.parent.toggleReportFS = function() {
    window.parent.toggleReportFullscreen(null);
  };

  // Attach global parent document event listeners once
  try {
    const pDoc = window.parent.document;
    if (pDoc && !window.parent.__threat_report_fs_listener_attached) {
      window.parent.__threat_report_fs_listener_attached = true;
      
      pDoc.addEventListener('click', function(e) {
        const btn = e.target.closest('.report-fullscreen-icon, [data-report-fs], #report-fs-btn');
        if (btn) {
          e.preventDefault();
          e.stopPropagation();
          window.parent.toggleReportFullscreen(btn);
        }
      }, true);
      
      pDoc.addEventListener('keydown', function(e) {
        if (e.key === 'Escape' || e.key === 'Esc' || e.keyCode === 27) {
          if (pDoc.body.classList.contains('report-fs-active') || pDoc.querySelector('.report-fullscreen-active')) {
            window.parent.exitReportFullscreen();
          }
        }
      }, true);
      
      pDoc.addEventListener('fullscreenchange', function() {
        if (!pDoc.fullscreenElement) {
          const targets = pDoc.querySelectorAll('.report-fullscreen-active');
          targets.forEach(t => t.classList.remove('report-fullscreen-active'));
          pDoc.body.classList.remove('report-fs-active');
          pDoc.body.style.overflow = '';
          updateAllReportButtons(false);
        }
      });
    }
  } catch(e) {}
})();
</script>
""", height=0)

with container_report:
    st.markdown("""
    <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:8px; padding-bottom:4px;">
      <span style="font-size:1.15rem; font-weight:700; color:#F8FAFC;">📋 Threat Investigation & Advisory Report</span>
      <button class="report-fullscreen-icon" data-report-fs="window" title="Toggle Fullscreen Reading View (⛶)">
        <span class="fs-icon">⛶</span> <span class="fs-text">Fullscreen</span>
      </button>
    </div>
    """, unsafe_allow_html=True)
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
            t_start = time.time()
            with st.spinner("⚡ Traversing Neo4j Graph Index & Initializing AI Stream..."):
                entities = extract_entities(user_query)
                facts, nodes_dict, edges, nodes_meta, metrics = fetch_threat_subgraph(entities)
                traversal_ms = round((time.time() - t_start) * 1000, 1)
                
                cached_item = threat_cache.get(user_query, facts)
                is_hit = cached_item is not None
                
                st.session_state["entities"] = entities
                st.session_state["facts"] = facts
                st.session_state["nodes_dict"] = nodes_dict
                st.session_state["edges"] = edges
                st.session_state["nodes_meta"] = nodes_meta
                st.session_state["graph_metrics"] = metrics
                st.session_state["is_cached"] = is_hit
                st.session_state["traversal_ms"] = traversal_ms
                
                rep_container = st.container()
                with rep_container:
                    st.markdown("""
                    <div id="threat-report-marker" style="display:flex; justify-content:space-between; align-items:center; margin-bottom:12px; border-bottom:1px solid #1E293B; padding-bottom:8px;">
                      <span style="font-size:1.15rem; font-weight:700; color:#38BDF8;">📋 SOC Threat Intelligence Report</span>
                      <button id="report-fs-btn" class="report-fullscreen-icon" data-report-fs="card" title="Toggle Fullscreen Reading View (⛶)">
                        <span class="fs-icon" id="report-fs-icon">⛶</span> <span class="fs-text" id="report-fs-text">Fullscreen</span>
                      </button>
                    </div>
                    """, unsafe_allow_html=True)
                    
                    # Tactical Telemetry Scorecard
                    m1, m2, m3, m4 = st.columns(4)
                    m1.metric("Composite Risk Index", f"{metrics['composite_risk_score']}/100", delta=metrics["severity_level"], delta_color="inverse")
                    m2.metric("Traversal Latency", f"{traversal_ms}ms", delta="⚡ Cache HIT" if is_hit else "⚡ Neo4j Multi-Hop")
                    m3.metric("Attack Path Hops", len(edges))
                    m4.metric("Crown Jewels at Risk", len(metrics["crown_jewels_at_risk"]))

                    if is_hit:
                        st.info(f"⚡ **Semantic Cache HIT:** Instant sub-millisecond retrieval • 0 LLM API tokens consumed.")
                    else:
                        st.success(f"🚀 **Live Generation:** Multi-hop path resolved in {traversal_ms}ms • Synthesized via Google Gemini.")

                    # Token-by-token live streaming
                    stream_gen = synthesize_technical_report_stream(facts, user_query, client=client)
                    answer = st.write_stream(stream_gen)
                    st.session_state["answer"] = answer

                    st.markdown("<div style='height:8px;'></div>", unsafe_allow_html=True)
                    col_live_dl1, col_live_dl2 = st.columns(2)
                    with col_live_dl1:
                        st.download_button(
                            "⬇️ Download Advisory (.md)",
                            data=answer,
                            file_name="CISA_CTI_Advisory_Report.md",
                            mime="text/markdown",
                            use_container_width=True,
                            key="dl_live_md"
                        )
                    with col_live_dl2:
                        st.download_button(
                            "📄 Download Advisory (.txt)",
                            data=answer,
                            file_name="CISA_CTI_Advisory_Report.txt",
                            mime="text/plain",
                            use_container_width=True,
                            key="dl_live_txt"
                        )

        elif "answer" in st.session_state:
            rep_container = st.container()
            with rep_container:
                st.markdown("""
                <div id="threat-report-marker" style="display:flex; justify-content:space-between; align-items:center; margin-bottom:12px; border-bottom:1px solid #1E293B; padding-bottom:8px;">
                  <span style="font-size:1.15rem; font-weight:700; color:#38BDF8;">📋 SOC Threat Intelligence Report</span>
                  <button id="report-fs-btn" class="report-fullscreen-icon" data-report-fs="card" title="Toggle Fullscreen Reading View (⛶)">
                    <span class="fs-icon" id="report-fs-icon">⛶</span> <span class="fs-text" id="report-fs-text">Fullscreen</span>
                  </button>
                </div>
                """, unsafe_allow_html=True)
                
                if "graph_metrics" in st.session_state:
                    metrics = st.session_state["graph_metrics"]
                    m1, m2, m3, m4 = st.columns(4)
                    m1.metric("Composite Risk Index", f"{metrics['composite_risk_score']}/100", delta=metrics["severity_level"], delta_color="inverse")
                    m2.metric("Traversal Latency", f"{st.session_state.get('traversal_ms', 12)}ms", delta="⚡ Cache HIT" if st.session_state.get("is_cached") else "⚡ Neo4j Multi-Hop")
                    m3.metric("Attack Path Hops", len(st.session_state.get("edges", [])))
                    m4.metric("Crown Jewels at Risk", len(metrics.get("crown_jewels_at_risk", [])))
                
                col_rep_meta, col_rep_md, col_rep_txt = st.columns([1.2, 0.9, 0.9])
                with col_rep_meta:
                    if st.session_state.get("is_cached"):
                        st.info(f"⚡ **Cached Report** (0 LLM API tokens consumed)")
                    else:
                        st.success(f"⚡ **Neo4j Graph Traversal:** {st.session_state.get('traversal_ms', 12)}ms")
                with col_rep_md:
                    st.download_button(
                        "⬇️ Download (.md)",
                        data=st.session_state["answer"],
                        file_name="CISA_CTI_Advisory_Report.md",
                        mime="text/markdown",
                        use_container_width=True,
                        key="dl_cached_md"
                    )
                with col_rep_txt:
                    st.download_button(
                        "📄 Download (.txt)",
                        data=st.session_state["answer"],
                        file_name="CISA_CTI_Advisory_Report.txt",
                        mime="text/plain",
                        use_container_width=True,
                        key="dl_cached_txt"
                    )

                st.markdown(st.session_state["answer"])

        # Persistent Evidence & Interactive Forensics Copilot
        if "answer" in st.session_state and st.session_state.get("facts"):
            with st.expander("🔍 Discovered Attack Graph Paths (Verified Evidence)"):
                for f in st.session_state["facts"]:
                    st.write(f)

            st.markdown("<div style='height: 8px;'></div>", unsafe_allow_html=True)
            with st.expander("💬 SOC Forensics Copilot (Interactive Attack Graph Q&A)", expanded=True):
                st.markdown("""
                <div style="font-size: 13px; color: #94A3B8; margin-bottom: 8px;">
                    Ask iterative forensics questions grounded directly in the verified Neo4j attack graph, telemetry event IDs, emergency containment rules, and downstream blast radius.
                </div>
                """, unsafe_allow_html=True)

                if "copilot_chat_history" not in st.session_state:
                    st.session_state["copilot_chat_history"] = []

                # Quick Investigation Prompts
                st.markdown("<div style='font-size: 11px; font-weight: 700; color: #38BDF8; margin-bottom: 6px;'>⚡ QUICK SOC INVESTIGATION PROMPTS:</div>", unsafe_allow_html=True)
                qp_col1, qp_col2 = st.columns(2)
                qp_col3, qp_col4 = st.columns(2)
                
                quick_query = None
                with qp_col1:
                    if st.button("🔍 Event IDs to Detect Pivot", use_container_width=True, key="btn_qp_events"):
                        quick_query = "What specific Windows Security, Sysmon, or Linux audit event IDs detect this pivot?"
                with qp_col2:
                    if st.button("🛡️ Emergency Ingress Firewall Rule", use_container_width=True, key="btn_qp_firewall"):
                        quick_query = "What exact iptables or network firewall rule can we push right now to contain lateral movement?"
                with qp_col3:
                    if st.button("💥 Vault & PCI-DSS Blast Radius", use_container_width=True, key="btn_qp_blast"):
                        quick_query = "What is the operational impact and PCI-DSS compliance blast radius if payment-token-vault is reached?"
                with qp_col4:
                    if st.button("📋 CISO Executive Briefing", use_container_width=True, key="btn_qp_ciso"):
                        quick_query = "Summarize this incident into a 3-bullet executive briefing with containment urgency for the CISO."

                # Render Previous Conversation Thread
                for msg in st.session_state["copilot_chat_history"]:
                    with st.chat_message(msg["role"], avatar="🕵️" if msg["role"] == "user" else "🛡️"):
                        st.markdown(msg["content"])

                # Chat Input Field
                analyst_input = st.chat_input("Ask a follow-up forensics question on this attack path...", key="copilot_chat_input")
                active_question = quick_query or analyst_input

                if active_question:
                    st.session_state["copilot_chat_history"].append({"role": "user", "content": active_question})
                    with st.chat_message("user", avatar="🕵️"):
                        st.markdown(active_question)
                    with st.chat_message("assistant", avatar="🛡️"):
                        stream_gen = synthesize_copilot_followup_stream(
                            chat_history=st.session_state["copilot_chat_history"][:-1],
                            user_question=active_question,
                            facts=st.session_state.get("facts", []),
                            base_report=st.session_state.get("answer", ""),
                            client=client
                        )
                        reply = st.write_stream(stream_gen)
                    st.session_state["copilot_chat_history"].append({"role": "assistant", "content": reply})

                if st.session_state["copilot_chat_history"]:
                    col_clr, _ = st.columns([1, 2])
                    with col_clr:
                        if st.button("🧹 Clear Conversation History", key="btn_clear_copilot_chat"):
                            st.session_state["copilot_chat_history"] = []
                            st.rerun()

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
                        st.markdown("""
                        <div id="threat-report-marker" style="display:flex; justify-content:space-between; align-items:center; margin-bottom:12px; border-bottom:1px solid #1E293B; padding-bottom:8px;">
                          <span style="font-size:1.05rem; font-weight:700; color:#38BDF8;">📋 SOC Threat Intelligence & Remediation Roadmap</span>
                          <button id="report-fs-btn" class="report-fullscreen-icon" data-report-fs="card" title="Toggle Fullscreen Reading View (⛶)">
                            <span class="fs-icon" id="report-fs-icon">⛶</span> <span class="fs-text" id="report-fs-text">Fullscreen</span>
                          </button>
                        </div>
                        """, unsafe_allow_html=True)
                        st.markdown(st.session_state["repo_ai_report"])
                        col_sb_dl1, col_sb_dl2 = st.columns(2)
                        with col_sb_dl1:
                            st.download_button(
                                "⬇️ Download SBOM Advisory (.md)",
                                data=st.session_state["repo_ai_report"],
                                file_name=f"SupplyChain_Security_Audit_{res['repository'].replace('/', '_')}.md",
                                mime="text/markdown",
                                use_container_width=True,
                                key="dl_repo_ai_md"
                            )
                        with col_sb_dl2:
                            st.download_button(
                                "📄 Download SBOM Advisory (.txt)",
                                data=st.session_state["repo_ai_report"],
                                file_name=f"SupplyChain_Security_Audit_{res['repository'].replace('/', '_')}.txt",
                                mime="text/plain",
                                use_container_width=True,
                                key="dl_repo_ai_txt"
                            )
                        
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

with container_graph:
    col_g_title, col_g_dl = st.columns([1.5, 1])
    with col_g_title:
        st.subheader("🕸️ Interactive Attack Graph & Blast Radius")
    with col_g_dl:
        if "edges" in st.session_state and st.session_state["edges"]:
            import json
            graph_export_payload = {
                "scenario_entities": st.session_state.get("entities", []),
                "nodes": st.session_state.get("nodes_dict", {}),
                "edges": st.session_state["edges"],
                "nodes_metadata": st.session_state.get("nodes_meta", {}),
                "threat_metrics": st.session_state.get("graph_metrics", {}),
                "exported_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            }
            st.download_button(
                "⬇️ Export Graph Data (JSON)",
                data=json.dumps(graph_export_payload, indent=2),
                file_name="ThreatGraph_Attack_Topology.json",
                mime="application/json",
                use_container_width=True,
                key="btn_dl_graph_json"
            )
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
        # Algorithmic Chokepoint & Quantitative Risk Computation
        chokepoint_data = compute_graph_chokepoints(
            st.session_state["nodes_dict"],
            st.session_state["edges"],
            st.session_state.get("nodes_meta", {})
        )
        st.session_state["chokepoint_data"] = chokepoint_data
        primary_chokepoint = chokepoint_data.get("primary_chokepoint")
        risk_mod = chokepoint_data.get("risk_modeling", {})

        # Chokepoint & Quantitative Risk Analysis Panel
        with st.expander("🎯 Algorithmic Chokepoint & Quantitative Risk Engine (Graph Theory)", expanded=True):
            st.markdown("""
            <div style="font-size: 13px; color: #94A3B8; margin-bottom: 12px;">
                Identifies graph-theoretic <b>S-T Articulation Points (Cut-Vertices)</b> and computes <b>Bayesian cumulative exploitability</b> across all discovered attack paths leading to Tier-0 crown jewels.
            </div>
            """, unsafe_allow_html=True)
            
            cp_col1, cp_col2, cp_col3, cp_col4 = st.columns(4)
            is_perfect_cut = chokepoint_data.get("is_perfect_cut", False)
            p_breach = risk_mod.get("cumulative_breach_probability", 95.0)
            ttc_display = risk_mod.get("fastest_time_to_compromise", "~20m")
            active_paths_count = chokepoint_data.get("total_active_paths", 0)

            cp_col1.metric(
                "Primary Chokepoint",
                primary_chokepoint or "None Identified",
                delta="🎯 Perfect Cut-Vertex" if is_perfect_cut else "Bridge Pivot"
            )
            cp_col2.metric(
                "Cumulative Breach Prob",
                f"{p_breach}%",
                delta="CVSS/EPSS Bayesian Risk",
                delta_color="inverse"
            )
            cp_col3.metric(
                "Est. Time-to-Compromise",
                ttc_display,
                delta=risk_mod.get("exploit_maturity_tier", "WEAPONIZED")
            )
            cp_col4.metric(
                "Active Kill-Chain Paths",
                active_paths_count,
                delta="Direct Traversal Paths"
            )

            if primary_chokepoint:
                rankings = chokepoint_data.get("chokepoint_rankings", [])
                top_cut_pct = rankings[0].get("severance_percentage", 100.0) if rankings else 100.0
                st.markdown(f"""
                <div style="background: rgba(245, 158, 11, 0.08); border-left: 3px solid #F59E0B; padding: 10px 14px; border-radius: 4px; font-size: 13px; color: #F8FAFC; margin: 8px 0 14px 0;">
                    <b style="color: #FBBF24;">🎯 Tactical Chokepoint Strategy:</b> Neutralizing <b><code>{primary_chokepoint}</code></b> severs <b>{top_cut_pct}%</b> of all active adversary traversals to Tier-0 assets. Highlighted with a golden halo on the graph canvas.
                </div>
                """, unsafe_allow_html=True)

                if rankings:
                    st.markdown("###### 📊 Mathematically Ranked Intervention Priorities")
                    import pandas as pd
                    df_rankings = pd.DataFrame([
                        {
                            "Node": r["node"],
                            "Entity Type": r["label"],
                            "Path Severance": f"{r['severance_percentage']}%",
                            "Betweenness Centrality": r["betweenness_score"],
                            "Articulation Point": "🎯 Cut-Vertex" if r["is_articulation_point"] else "Bridge",
                            "Recommended Countermeasure": r["recommended_action"],
                            "Friction Cost": r["operational_friction"]
                        }
                        for r in rankings
                    ])
                    st.dataframe(df_rankings, use_container_width=True, hide_index=True)

        # Extract candidate mitigation targets (CVEs, Services, Packages)
        nodes_dict = st.session_state["nodes_dict"]
        cve_candidates = [n for n, l in nodes_dict.items() if l == "Vulnerability"]
        svc_candidates = [n for n, l in nodes_dict.items() if l == "EnterpriseService"]
        pkg_candidates = [n for n, l in nodes_dict.items() if l == "SoftwarePackage"]
        all_candidates = cve_candidates + svc_candidates + pkg_candidates
        if not all_candidates:
            all_candidates = list(nodes_dict.keys())

        # What-If Countermeasure Simulator Expander
        with st.expander("🛡️ Interactive 'What-If' Countermeasure Simulator & Defense Playbooks", expanded=True):
            st.markdown("""
            <div style="font-size: 13px; color: #94A3B8; margin-bottom: 8px;">
                Simulate removing a vulnerability (patching) or severing network ingress (pod isolation) to mathematically evaluate kill-chain reachability and compile deployable SOAR detection rules.
            </div>
            """, unsafe_allow_html=True)
            
            col_sim_target, col_sim_action, col_sim_btn = st.columns([1.6, 1.2, 0.9])
            with col_sim_target:
                default_target_idx = 0
                if primary_chokepoint and primary_chokepoint in all_candidates:
                    default_target_idx = all_candidates.index(primary_chokepoint)
                target_choice = st.selectbox("Select Target Node to Mitigate:", all_candidates, index=default_target_idx, key="cm_target_select")
            with col_sim_action:
                default_act_idx = 0 if any(flaw in str(target_choice) for flaw in ["CVE-", "log4j", "xz-utils", "fortios", "spring"]) else 1
                action_mode = st.radio("Mitigation Action:", ["🛡️ Patch Vulnerability", "🔒 Isolate Pod / Host"], index=default_act_idx, horizontal=True, key="cm_action_mode")
                action_type = "patch" if "Patch" in action_mode else "isolate"
            with col_sim_btn:
                st.write("")
                st.write("")
                sim_btn = st.button("⚡ Run Simulation", type="primary", use_container_width=True, key="btn_run_cm_sim")

            if sim_btn:
                sim_res = simulate_countermeasure(
                    nodes_dict=st.session_state["nodes_dict"],
                    edges=st.session_state["edges"],
                    nodes_meta=st.session_state.get("nodes_meta", {}),
                    target_entity=target_choice,
                    action_type=action_type
                )
                st.session_state["countermeasure_sim"] = sim_res

            if "countermeasure_sim" in st.session_state:
                cm = st.session_state["countermeasure_sim"]
                
                # Tactical Scorecard
                sc1, sc2, sc3, sc4 = st.columns(4)
                sc1.metric("Kill-Chain Reachability", "🟢 SEVERED" if cm["kill_chain_broken"] else "⚠️ PARTIAL", delta="0 Hops to Jewels" if cm["kill_chain_broken"] else "Residual Path")
                sc2.metric("Composite Risk Index", f"{cm['after_metrics']['composite_risk_score']}/100", delta=f"-{cm['risk_delta']} pts", delta_color="inverse")
                sc3.metric("Severed Attack Hops", cm["severed_edges_count"], delta="BLOCKED")
                sc4.metric("Crown Jewels Protected", len(cm["protected_crown_jewels"]))

                if cm["kill_chain_broken"]:
                    st.success(f"✅ **MATHEMATICAL PROOF: KILL-CHAIN TERMINATED.** Traversal reachability from ingress to Tier-0 crown jewels drops to 0. Lateral movement paths to `{', '.join(cm['protected_crown_jewels']) if cm['protected_crown_jewels'] else 'crown jewels'}` are broken.")
                else:
                    st.warning("⚠️ **PARTIAL CONTAINMENT:** Primary attack hop severed, but secondary pivot paths remain active.")

                col_toggle_graph, col_reset_sim = st.columns([2, 1])
                with col_toggle_graph:
                    show_sim_graph = st.checkbox("🎨 Overlay Severed Attack Edges on Graph Canvas (Red dashed [BLOCKED] lines)", value=True, key="chk_show_sim_graph")
                with col_reset_sim:
                    if st.button("🔄 Reset to Baseline Graph", use_container_width=True, key="btn_reset_sim"):
                        del st.session_state["countermeasure_sim"]
                        st.rerun()

                st.markdown("##### 🛠️ Auto-Generated SecOps Defense Artifacts (Deployable)")
                tab_sig, tab_k8s, tab_sh = st.tabs(["📄 Sigma SIEM Rule (.yml)", "☸️ Kubernetes NetworkPolicy (.yaml)", "💻 DevOps Quarantine Script (.sh)"])
                
                with tab_sig:
                    st.caption("Standardized Sigma detection rule for SIEM ingestion (Splunk, Microsoft Sentinel, Elastic, QRadar).")
                    st.code(cm["defense_artifacts"]["sigma_rule"], language="yaml")
                    st.download_button(
                        "⬇️ Download Sigma Rule (.yml)",
                        data=cm["defense_artifacts"]["sigma_rule"],
                        file_name=f"sigma_detect_{cm['target_entity'].replace(':', '_').replace('/', '_')}.yml",
                        mime="text/yaml",
                        use_container_width=True,
                        key="dl_cm_sigma"
                    )
                with tab_k8s:
                    st.caption("Zero-Trust Kubernetes NetworkPolicy restricting lateral network sockets to/from the compromised pod.")
                    st.code(cm["defense_artifacts"]["kubernetes_policy"], language="yaml")
                    st.download_button(
                        "⬇️ Download NetworkPolicy (.yaml)",
                        data=cm["defense_artifacts"]["kubernetes_policy"],
                        file_name=f"k8s_isolate_{cm['target_entity'].replace(':', '_').replace('/', '_')}.yaml",
                        mime="text/yaml",
                        use_container_width=True,
                        key="dl_cm_k8s"
                    )
                with tab_sh:
                    st.caption("Automated bash incident response playbook executing pod cordoning, iptables severing, and forensic labeling.")
                    st.code(cm["defense_artifacts"]["quarantine_script"], language="bash")
                    st.download_button(
                        "⬇️ Download Quarantine Script (.sh)",
                        data=cm["defense_artifacts"]["quarantine_script"],
                        file_name=f"quarantine_{cm['target_entity'].replace(':', '_').replace('/', '_')}.sh",
                        mime="text/x-sh",
                        use_container_width=True,
                        key="dl_cm_sh"
                    )

        # Graph Rendering (either baseline or simulation visual overlay)
        graph_nodes = st.session_state["nodes_dict"]
        graph_edges = st.session_state["edges"]
        graph_meta = st.session_state.get("nodes_meta")
        
        if "countermeasure_sim" in st.session_state and st.session_state.get("chk_show_sim_graph", True):
            graph_nodes = st.session_state["countermeasure_sim"]["visual_nodes"]
            graph_edges = st.session_state["countermeasure_sim"]["visual_edges"]
            st.caption(f"Showing attack path with **Simulated Countermeasure applied on `{st.session_state['countermeasure_sim']['target_entity']}`** • (Red dashed edges indicate `[BLOCKED]` hops)")
        else:
            st.caption(f"Showing attack path for: {', '.join(st.session_state.get('entities', []))} • (🎯 Golden halo highlights primary articulation point `{primary_chokepoint}` • Click node to inspect • 📷 Export PNG or 📥 Export JSON in top toolbar)")
            
        render_attack_graph(graph_nodes, graph_edges, graph_meta, graph_height=700, chokepoint_node=primary_chokepoint)
    else:
        st.info("Execute a threat scenario on the left to visualize the attack path and lateral movement graph!")
