import os
import time
from typing import List, Dict, Any, Optional
from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel, Field
from dotenv import load_dotenv
from neo4j import GraphDatabase
from google import genai
from google.genai import types

load_dotenv()

# App initialization
app = FastAPI(
    title="ThreatGraphRAG API",
    description="Enterprise Cyber Threat Intelligence & Multi-Hop Attack Path Reasoning Service",
    version="1.0.0"
)

# Credentials
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "your_gemini_api_key_here")
NEO4J_URI = os.getenv("NEO4J_URI", "neo4j+ssc://e6c68873.databases.neo4j.io")
NEO4J_USERNAME = os.getenv("NEO4J_USERNAME", "e6c68873")
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD", "your_neo4j_password_here")

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

class BlastRadiusResponse(BaseModel):
    target_node: str
    compromised_services: List[str]
    vulnerabilities: List[str]
    lateral_movement_paths: List[str]
    severity_level: str

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

@app.post("/api/threat-query", response_model=QueryResponse, tags=["Threat Intelligence"])
def query_threat_graph(request: QueryRequest):
    """Executes multi-hop attack path traversal and Gemini-grounded threat report synthesis."""
    t0 = time.time()
    
    # 1. Fast Entity Extraction
    known_entities = [
        "APT29", "Cozy Bear", "Lazarus", "LockBit",
        "CVE-2021-44228", "Log4Shell", "CVE-2024-3094", "XZ Backdoor", "CVE-2022-22965", "Spring4Shell", "CVE-2024-21762",
        "Customer-Auth-Service", "Payment-Processing-Gateway", "Enterprise-SSH-Bastion", "Analytics-ETL-Pipeline"
    ]
    matched = [e for e in known_entities if e.lower() in request.query.lower()]
    entities = matched if matched else [request.query.strip()]
    
    # 2. Graph Traversal
    facts = []
    with driver.session() as session:
        for entity in entities:
            cypher = """
            MATCH (source)
            WHERE toLower(source.name) CONTAINS toLower($entity)
            MATCH path = (source)-[r*1..2]-(target)
            UNWIND relationships(path) as rel
            WITH DISTINCT rel, startNode(rel) as s, endNode(rel) as t
            RETURN s.name AS src, labels(s)[0] AS s_label, type(rel) AS rel_type, t.name AS tgt, labels(t)[0] AS t_label
            LIMIT 20
            """
            for record in session.run(cypher, entity=entity):
                fact = f"- [{record['s_label']}] `{record['src']}` ──[{record['rel_type']}]──► [{record['t_label']}] `{record['tgt']}`"
                if fact not in facts:
                    facts.append(fact)
                    
    # 3. Grounded Synthesis with Gemini
    context = "\n".join(facts) if facts else "No direct attack graph paths found."
    prompt = f"""You are a Principal Cyber Threat Intelligence Analyst.
Analyze the user question STRICTLY using the attack graph paths provided:
{context}

QUESTION: {request.query}

Output a clean, executive SOC advisory with Threat Summary, Multi-Hop Attack Path, and Prescribed Patches.
"""
    try:
        res = client.models.generate_content(
            model="gemini-3.6-flash",
            contents=prompt,
            config=types.GenerateContentConfig(temperature=0.2)
        )
        report = res.text
    except Exception as e:
        report = f"Graph facts retrieved: {context}\n(Automated report fallback: {e})"
        
    return QueryResponse(
        query=request.query,
        discovered_entities=entities,
        attack_path_facts=facts,
        threat_intelligence_report=report,
        execution_time_seconds=round(time.time() - t0, 3)
    )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("api:app", host="0.0.0.0", port=8000, reload=True)
