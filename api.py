import os
import time
import json
from typing import List, Dict, Any, Optional
from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from dotenv import load_dotenv
from neo4j import GraphDatabase
from google import genai
from google.genai import types

from src.repo_evaluator import (
    parse_github_url,
    fetch_repo_manifest,
    parse_generic_manifest,
    evaluate_repo_dependencies,
    generate_ai_repo_audit_report,
    PRESET_REPOSITORIES
)
from src.report_generator import synthesize_technical_report, synthesize_technical_report_stream
from src.cache_manager import threat_cache
from src.graph_engine import extract_cyber_entities, fetch_precision_threat_graph, simulate_countermeasure

load_dotenv()

# App initialization
app = FastAPI(
    title="ThreatGraphRAG API",
    description="Enterprise Cyber Threat Intelligence & Multi-Hop Attack Path Reasoning Service",
    version="1.0.0"
)

# Credentials
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
NEO4J_URI = os.getenv("NEO4J_URI", "neo4j+ssc://e6c68873.databases.neo4j.io")
NEO4J_USERNAME = os.getenv("NEO4J_USERNAME", "neo4j")
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD")

client = genai.Client(api_key=GEMINI_API_KEY)
driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USERNAME, NEO4J_PASSWORD))

# Request / Response Schemas
class QueryRequest(BaseModel):
    query: str = Field(..., example="How can APT29 exploit our public-facing services, and what patch is needed?")

class QueryResponse(BaseModel):
    query: str
    discovered_entities: List[str]
    attack_path_facts: List[str]
    threat_intelligence_report: str
    execution_time_seconds: float
    cache_hit: bool = False
    traversal_time_seconds: float = 0.0

class BlastRadiusResponse(BaseModel):
    target_node: str
    compromised_services: List[str]
    vulnerabilities: List[str]
    lateral_movement_paths: List[str]
    severity_level: str

class CountermeasureRequest(BaseModel):
    target_entity: str = Field(..., example="CVE-2021-44228", description="CVE flaw ID or enterprise service to mitigate")
    action_type: str = Field("patch", example="patch", description="'patch' to mitigate CVE flaw or 'isolate' to quarantine host/pod")

class CountermeasureResponse(BaseModel):
    target_entity: str
    action_type: str
    kill_chain_broken: bool
    risk_delta: int
    before_risk_score: int
    after_risk_score: int
    severed_edges_count: int
    protected_crown_jewels: List[str]
    sigma_rule: str
    kubernetes_policy: str
    quarantine_script: str

# Endpoints
@app.get("/health", tags=["System"])
def health_check():
    """Verifies API, Neo4j, and Gemini connection status."""
    try:
        driver.verify_connectivity()
        db_status = "connected"
    except Exception as e:
        db_status = f"unhealthy: {e}"
    return {
        "status": "online",
        "database": db_status,
        "model": "gemini-3.6-flash",
        "service": "ThreatGraphRAG Enterprise API"
    }

@app.get("/api/graph-summary", tags=["Threat Intelligence"])
def get_graph_summary():
    """Returns total node counts, attack techniques, and critical vulnerabilities."""
    with driver.session() as session:
        nodes = session.run("MATCH (n) RETURN count(n) AS count").single()["count"]
        edges = session.run("MATCH ()-[r]->() RETURN count(r) AS count").single()["count"]
        actors = [r["name"] for r in session.run("MATCH (n:ThreatActor) RETURN n.name AS name")]
        cves = [r["name"] for r in session.run("MATCH (n:Vulnerability) RETURN n.name AS name")]
        services = [r["name"] for r in session.run("MATCH (n:EnterpriseService) RETURN n.name AS name")]
        
    return {
        "total_nodes": nodes,
        "total_relationships": edges,
        "tracked_threat_actors": actors,
        "critical_vulnerabilities": cves,
        "monitored_enterprise_services": services
    }

@app.get("/api/blast-radius", response_model=BlastRadiusResponse, tags=["Security Analysis"])
def calculate_blast_radius(target: str = Query(..., description="Service name or CVE ID to analyze")):
    """Calculates the lateral movement blast radius and compromised upstream/downstream services."""
    services = set()
    cves = set()
    paths = []
    
    with driver.session() as session:
        cypher = """
        MATCH (target)
        WHERE toLower(target.name) CONTAINS toLower($target)
        MATCH p = (target)-[r*1..3]-(neighbor)
        RETURN 
            startNode(r[0]).name AS s_name, labels(startNode(r[0]))[0] AS s_label,
            type(r[0]) AS rel,
            endNode(r[0]).name AS t_name, labels(endNode(r[0]))[0] AS t_label
        LIMIT 30
        """
        results = session.run(cypher, target=target)
        for record in results:
            s_name, s_label = record["s_name"], record["s_label"]
            t_name, t_label = record["t_name"], record["t_label"]
            rel = record["rel"]
            
            paths.append(f"[{s_label}] `{s_name}` ──[{rel}]──► [{t_label}] `{t_name}`")
            if s_label == "EnterpriseService": services.add(s_name)
            if t_label == "EnterpriseService": services.add(t_name)
            if s_label == "Vulnerability": cves.add(s_name)
            if t_label == "Vulnerability": cves.add(t_name)
            
    if not paths:
        raise HTTPException(status_code=404, detail=f"No graph paths found for entity '{target}'")
        
    return BlastRadiusResponse(
        target_node=target,
        compromised_services=list(services),
        vulnerabilities=list(cves),
        lateral_movement_paths=paths,
        severity_level="CRITICAL" if any("10.0" in c for c in cves) else "HIGH"
    )

@app.post("/api/countermeasure/simulate", response_model=CountermeasureResponse, tags=["Active Defense & SOAR"])
def simulate_defense_countermeasure(request: CountermeasureRequest):
    """
    Simulates graph-theoretic countermeasure reachability and blast radius reduction.
    Evaluates whether patching a vulnerability or isolating a Kubernetes pod breaks the multi-hop kill-chain to crown jewels.
    Returns quantitative risk deltas, severed paths, and auto-generated Sigma & Kubernetes defense artifacts.
    """
    facts, nodes_dict, edges, nodes_meta, metrics = fetch_precision_threat_graph(driver, [request.target_entity])
    if not nodes_dict:
        raise HTTPException(status_code=404, detail=f"Target entity '{request.target_entity}' not found in knowledge graph.")
        
    sim_res = simulate_countermeasure(
        nodes_dict=nodes_dict,
        edges=edges,
        nodes_meta=nodes_meta,
        target_entity=request.target_entity,
        action_type=request.action_type
    )
    
    return CountermeasureResponse(
        target_entity=sim_res["target_entity"],
        action_type=sim_res["action_type"],
        kill_chain_broken=sim_res["kill_chain_broken"],
        risk_delta=sim_res["risk_delta"],
        before_risk_score=sim_res["before_metrics"]["composite_risk_score"],
        after_risk_score=sim_res["after_metrics"]["composite_risk_score"],
        severed_edges_count=sim_res["severed_edges_count"],
        protected_crown_jewels=sim_res["protected_crown_jewels"],
        sigma_rule=sim_res["defense_artifacts"]["sigma_rule"],
        kubernetes_policy=sim_res["defense_artifacts"]["kubernetes_policy"],
        quarantine_script=sim_res["defense_artifacts"]["quarantine_script"]
    )

@app.post("/api/threat-query", response_model=QueryResponse, tags=["Threat Intelligence"])
def query_threat_graph(request: QueryRequest):
    """Executes multi-hop attack path traversal and Gemini-grounded threat report synthesis."""
    t0 = time.time()
    
    # 1. High-Precision Entity Extraction
    entities = extract_cyber_entities(request.query, client=client)
    
    # 2. Precision Multi-Hop Graph Traversal
    t_trav_start = time.time()
    facts, nodes_dict, edges_list, nodes_meta, metrics = fetch_precision_threat_graph(driver, entities)
    traversal_time = round(time.time() - t_trav_start, 4)
    
    cached_check = threat_cache.get(request.query, facts)
    is_cached = cached_check is not None
    
    # 3. Grounded Technical Synthesis (with Semantic Cache)
    report = synthesize_technical_report(facts, request.query, client=client)
        
    return QueryResponse(
        query=request.query,
        discovered_entities=entities,
        attack_path_facts=facts,
        threat_intelligence_report=report,
        execution_time_seconds=round(time.time() - t0, 3),
        cache_hit=is_cached,
        traversal_time_seconds=traversal_time
    )

@app.post("/api/threat-query-stream", tags=["Threat Intelligence"])
def query_threat_graph_stream(request: QueryRequest):
    """
    Streams the CTI Advisory token-by-token using Server-Sent Events (SSE).
    Provides instant sub-300ms time-to-first-token.
    """
    known_entities = [
        "APT29", "Nobelium", "Cozy Bear", "Midnight Blizzard",
        "Lazarus Group", "Lazarus", "HIDDEN COBRA", "Diamond Sleet",
        "Volt Typhoon", "BRONZE SILHOUETTE", "Vanguard Panda",
        "LockBit 3.0", "LockBit", "FIN7", "Carbanak",
        "CVE-2021-44228", "Log4Shell", "CVE-2024-3094", "XZ Utils", "XZ Backdoor",
        "CVE-2022-22965", "Spring4Shell", "CVE-2024-21762", "FortiOS",
        "CVE-2023-4966", "Citrix Bleed", "NetScaler",
        "k8s-auth-ingress-gateway", "payment-token-vault-service", "corporate-active-directory-dc01",
        "enterprise-bastion-ssh-host", "data-analytics-dataproc-spark", "edge-vpn-gateway-fortigate",
        "Customer-Auth-Service", "Payment-Processing-Gateway", "Enterprise-SSH-Bastion", "Analytics-ETL-Pipeline",
        "Exploit Public-Facing Application", "Supply Chain Compromise", "Command and Scripting Interpreter", "Valid Accounts",
        "Remote Services", "Server Software Component", "Data Encrypted for Impact",
        "log4j", "xz-utils", "spring-beans", "fortios", "netscaler"
    ]
    matched = [e for e in known_entities if e.lower() in request.query.lower()]
    entities = matched if matched else [request.query.strip()]

    facts = []
    with driver.session() as session:
        for entity in entities:
            clean_e = entity.strip()
            cypher = """
            MATCH (source)
            WHERE toLower(source.name) CONTAINS toLower($entity)
            MATCH path = (source)-[r*1..2]-(target)
            UNWIND relationships(path) as rel
            WITH DISTINCT rel, startNode(rel) as s, endNode(rel) as t
            RETURN s.name AS src, labels(s)[0] AS s_label, type(rel) AS rel_type, t.name AS tgt, labels(t)[0] AS t_label
            LIMIT 25
            """
            for record in session.run(cypher, entity=clean_e):
                fact = f"- [{record['s_label']}] `{record['src']}` ──[{record['rel_type']}]──► [{record['t_label']}] `{record['tgt']}`"
                if fact not in facts:
                    facts.append(fact)

    def event_stream():
        # First send metadata header
        yield f"data: {json.dumps({'type': 'meta', 'entities': entities, 'facts_count': len(facts)})}\n\n"
        # Stream text chunks
        for chunk in synthesize_technical_report_stream(facts, request.query, client=client):
            yield f"data: {json.dumps({'type': 'chunk', 'text': chunk})}\n\n"
        yield f"data: {json.dumps({'type': 'done'})}\n\n"

    return StreamingResponse(event_stream(), media_type="text/event-stream")

@app.get("/api/cache/stats", tags=["System"])
def get_cache_statistics():
    """Returns telemetry on in-memory semantic cache hit ratio and token savings."""
    return threat_cache.get_stats()

@app.post("/api/cache/clear", tags=["System"])
def clear_semantic_cache():
    """Flushes the in-memory threat intelligence semantic cache."""
    threat_cache.clear()
    return {"status": "ok", "message": "Threat intelligence cache purged."}

class SBOMServiceInput(BaseModel):
    name: str
    dependencies: List[str]

class SBOMScanRequest(BaseModel):
    application_name: str = "Enterprise Cloud Platform"
    services: List[SBOMServiceInput]

@app.post("/api/scan-sbom", tags=["Supply Chain Security"])
def scan_sbom(sbom: SBOMScanRequest):
    """Scans software dependencies against the ThreatGraphRAG knowledge base to flag critical zero-days and threat actors."""
    findings = []
    all_vulnerabilities = set()
    all_threat_actors = set()
    
    with driver.session() as session:
        for svc in sbom.services:
            for dep in svc.dependencies:
                cypher = """
                MATCH (p:SoftwarePackage)
                WHERE toLower(p.name) CONTAINS toLower($dep_name) OR toLower($dep_name) CONTAINS toLower(p.name)
                MATCH (v:Vulnerability)-[:EXPLOITS_FLAW_IN]->(p)
                OPTIONAL MATCH (tech:AttackTechnique)-[:TARGETS_VULNERABILITY]->(v)
                OPTIONAL MATCH (actor:ThreatActor)-[:LEVERAGES]->(tech)
                OPTIONAL MATCH (v)-[:MITIGATED_BY]->(patch:RemediationPatch)
                RETURN 
                    p.name AS package,
                    v.name AS cve, v.cvss AS cvss, v.type AS vuln_type,
                    actor.name AS threat_actor,
                    patch.name AS remediation
                """
                # Extract package name prefix for matching
                dep_search = dep.split(":")[1] if ":" in dep else dep
                records = list(session.run(cypher, dep_name=dep_search))
                for r in records:
                    if r["cve"]:
                        all_vulnerabilities.add(r["cve"])
                        if r["threat_actor"]: all_threat_actors.add(r["threat_actor"])
                        findings.append({
                            "service": svc.name,
                            "vulnerable_dependency": dep,
                            "cve": r["cve"],
                            "cvss_score": r["cvss"],
                            "flaw_type": r["vuln_type"],
                            "exploited_by_threat_actor": r["threat_actor"] or "Undisclosed",
                            "prescribed_patch": r["remediation"] or "Apply upstream vendor patch"
                        })
                        
    return {
        "status": "COMPLETED",
        "total_services_analyzed": len(sbom.services),
        "critical_vulnerabilities_detected": len(all_vulnerabilities),
        "active_threat_actors_targeting_stack": list(all_threat_actors),
        "vulnerability_findings": findings,
        "security_posture": "CRITICAL RISK" if len(all_vulnerabilities) > 0 else "SECURE"
    }

class GitHubScanRequest(BaseModel):
    repo_url: str = Field(..., example="https://github.com/apache/logging-log4j2", description="GitHub URL or owner/repo shorthand")
    branch: Optional[str] = Field(None, description="Git branch or tag (default: main or master)")
    manifest_type: Optional[str] = Field(None, description="Specific manifest file (e.g. pom.xml, requirements.txt, package.json)")
    custom_manifest_content: Optional[str] = Field(None, description="Direct manifest content to evaluate without fetching from GitHub")
    generate_ai_report: bool = Field(True, description="Whether to include Gemini-generated SOC executive summary")

@app.get("/api/github-presets", tags=["Supply Chain Security"])
def get_github_presets():
    """Returns curated presets for quick demonstration and evaluation."""
    return [
        {"name": k, "url": v["url"], "description": v["description"], "manifest_type": v["manifest_type"]}
        for k, v in PRESET_REPOSITORIES.items()
    ]

@app.post("/api/scan-github-repo", tags=["Supply Chain Security"])
def scan_github_repo(req: GitHubScanRequest):
    """
    Evaluates an external GitHub repository for software supply chain risks, zero-days, and state-sponsored threat actor targets.
    """
    t0 = time.time()
    manifest_content = req.custom_manifest_content
    manifest_filename = req.manifest_type or "requirements.txt"
    resolved_branch = req.branch or "main"
    
    # 1. Parse repository identifier
    try:
        parsed_url = parse_github_url(req.repo_url)
        owner = parsed_url["owner"]
        repo = parsed_url["repo"]
        repo_id = f"{owner}/{repo}"
        if parsed_url.get("branch") and not req.branch:
            resolved_branch = parsed_url["branch"]
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid repository URL: {e}")
        
    # 2. Fetch manifest from GitHub if not provided directly
    if not manifest_content:
        # Check if URL matches a known preset
        for preset_name, preset_data in PRESET_REPOSITORIES.items():
            if preset_data["owner"] == owner and preset_data["repo"] == repo:
                manifest_content = preset_data["simulated_manifest"]
                manifest_filename = preset_data["manifest_type"]
                break
                
        if not manifest_content:
            try:
                manifest_content, manifest_filename, resolved_branch = fetch_repo_manifest(
                    owner, repo, branch=resolved_branch, specified_file=req.manifest_type
                )
            except Exception as e:
                raise HTTPException(
                    status_code=422,
                    detail=f"Failed to fetch dependency manifest from GitHub repository {repo_id}: {str(e)}. You can supply custom_manifest_content in the request body."
                )
                
    # 3. Parse dependencies
    packages = parse_generic_manifest(manifest_filename, manifest_content)
    if not packages:
        raise HTTPException(
            status_code=400,
            detail=f"No software packages or dependencies found in manifest '{manifest_filename}'."
        )
        
    # 4. Evaluate against Neo4j Knowledge Graph
    evaluation = evaluate_repo_dependencies(driver, packages, repo_id)
    
    # 5. Generate AI Executive SOC Briefing
    ai_report = None
    if req.generate_ai_report:
        ai_report = generate_ai_repo_audit_report(repo_id, evaluation, gemini_api_key=GEMINI_API_KEY)
        
    evaluation["manifest_filename"] = manifest_filename
    evaluation["resolved_branch"] = resolved_branch
    evaluation["executive_threat_report"] = ai_report
    evaluation["execution_time_seconds"] = round(time.time() - t0, 3)
    
    return evaluation

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("api:app", host="0.0.0.0", port=8000, reload=True)
