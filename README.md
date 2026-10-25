# ThreatGraphRAG: Cyber Threat Intelligence & Multi-Hop Attack Path Reasoning

[![Python 3.11](https://img.shields.io/badge/Python-3.11-3776AB.svg?logo=python&logoColor=white)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110+-009688.svg?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![Neo4j](https://img.shields.io/badge/Neo4j-AuraDB_Cloud-008CC1.svg?logo=neo4j&logoColor=white)](https://neo4j.com/)
[![Google Gemini](https://img.shields.io/badge/LLM-Gemini_3.5_Flash-4285F4.svg?logo=google&logoColor=white)](https://ai.google.dev/)
[![Streamlit](https://img.shields.io/badge/Streamlit-1.35+-FF4B4B.svg?logo=streamlit&logoColor=white)](https://streamlit.io/)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED.svg?logo=docker&logoColor=white)](https://www.docker.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

An enterprise-grade Cyber Threat Intelligence (CTI) and graph-theoretic attack path reasoning platform. ThreatGraphRAG models multi-hop relational dependencies across threat actors, MITRE ATT&CK techniques, software vulnerabilities, open-source dependencies, and cloud microservices to discover attack paths, compute graph chokepoints, and generate automated active defense countermeasures.

---

## Table of Contents
- [Overview](#overview)
- [The Core Problem: Why Vector RAG Fails in Cybersecurity](#the-core-problem-why-vector-rag-fails-in-cybersecurity)
- [System Architecture and Data Flow](#system-architecture-and-data-flow)
- [Core Capabilities](#core-capabilities)
  - [Graph-Theoretic Chokepoints and Articulation Points](#graph-theoretic-chokepoints-and-articulation-points)
  - [Quantitative Path Risk and Time-to-Compromise (TTC)](#quantitative-path-risk-and-time-to-compromise-ttc)
  - [Active Defense and Automated Countermeasures](#active-defense-and-automated-countermeasures)
  - [Live Software Supply Chain and SBOM Auditing](#live-software-supply-chain-and-sbom-auditing)
  - [Conversational SOC Forensics Copilot](#conversational-soc-forensics-copilot)
- [Empirical Evaluation and Benchmarks](#empirical-evaluation-and-benchmarks)
- [Repository Structure](#repository-structure)
- [Installation and Setup](#installation-and-setup)
- [Execution and Usage](#execution-and-usage)
  - [Interactive Streamlit Console](#interactive-streamlit-console)
  - [Headless FastAPI REST Service](#headless-fastapi-rest-service)
  - [Docker Container Deployment](#docker-container-deployment)
- [REST API Reference](#rest-api-reference)
- [Testing and Quality Assurance](#testing-and-quality-assurance)
- [License](#license)

---

## Overview

Modern cyber attacks rarely follow a single isolated vector. State-sponsored Advanced Persistent Threats (APTs) leverage multi-stage campaigns: exploiting edge-facing web vulnerabilities, executing remote payloads, moving laterally across internal microservices, and compromising Tier-0 crown-jewel assets (identity stores, customer databases, token vaults).

Traditional Security Information and Event Management (SIEM) tools and standard Large Language Model (LLM) Retrieval-Augmented Generation (RAG) struggle to connect these multi-hop relationships because:
1. Threat intelligence documents, CVE advisories, and dependency manifests are stored across disparate data silos.
2. Vector similarity search retrieves isolated text chunks that lack topological awareness, failing to reconstruct complete attack paths.
3. Remediation advice is often generic, lacking mathematical proof of whether a patch or isolation policy actually breaks the kill-chain before critical assets are reached.

**ThreatGraphRAG** bridges this gap by unifying deterministic graph algorithms (Neo4j Cypher traversals, articulation points, betweenness centrality) with generative reasoning (Google Gemini 3.5 Flash). It identifies multi-hop attack paths, computes the mathematically optimal chokepoint to sever the threat, and generates production-ready defense playbooks across SIEM, Kubernetes, host, and network tiers.

---

## The Core Problem: Why Vector RAG Fails in Cybersecurity

Standard Vector RAG embeds unstructured documents into high-dimensional vector spaces and computes cosine similarity against a query. In cybersecurity, this methodology exhibits critical failure modes:

* **Relational Disconnect Across Multi-Hop Chains**:
  An attack path spanning 6 hops:
  $$\text{APT29} \xrightarrow{\text{EXPLOITS}} \text{T1190} \xrightarrow{\text{TARGETS}} \text{CVE-2021-44228} \xrightarrow{\text{AFFECTS}} \text{log4j-core} \xrightarrow{\text{RUNS\_ON}} \text{k8s-auth-gateway} \xrightarrow{\text{PIVOTS\_TO}} \text{payment-vault}$$
  cannot be resolved by vector embeddings because no single CVE bulletin or threat report describes this specific end-to-end traversal.

* **Hallucination of Non-Existent Mitigations**:
  Vector similarity frequently retrieves adjacent but irrelevant remediation advisories (e.g., recommending a generic SSH patch for a Log4j flaw), resulting in inaccurate guidance.

* **Lack of Quantitative Reachability Proof**:
  Vector RAG cannot compute graph metrics such as articulation points, shortest attack paths, or residual blast radius.

ThreatGraphRAG replaces heuristic chunk retrieval with **deterministic graph extraction and traversal**, feeding verified subgraphs into the LLM context. This guarantees zero hallucination of network topology and provides mathematically verifiable reachability reduction.

---

## System Architecture and Data Flow

The following diagram illustrates the end-to-end data processing lifecycle:

```
+-----------------------------------------------------------------------------------+
|                           Ingestion & Knowledge Graph                             |
|  - CTI Bulletins (CISA KEV, MITRE ATT&CK, NVD CVEs)                               |
|  - Enterprise Topology (Services, Subnets, IAM Roles, Crown Jewels)              |
|  - Software Bills of Materials (SBOMs, GitHub Dependency Manifests)               |
+-----------------------------------------------------------------------------------+
                                          |
                                          v
+-----------------------------------------------------------------------------------+
|                     Neo4j Graph Database (with In-Memory Fallback)                 |
|  - Nodes: ThreatActor, AttackTechnique, Vulnerability, SoftwarePackage,            |
|           EnterpriseService, RemediationPatch, SecurityControl                    |
|  - Edges: EXPLOITS, TARGETS, CAN_PIVOT_TO, LATERAL_MOVEMENT, MITIGATED_BY        |
+-----------------------------------------------------------------------------------+
                                          |
                                    User Query
                                          |
                                          v
+-----------------------------------------------------------------------------------+
|                           Precision Extraction Engine                             |
|  - Deterministic Entity Extraction (Exact matching + CTI Regex Patterns)          |
|  - Cypher Path Traversal: Finds all paths from Ingress/Actor to Crown Jewels      |
+-----------------------------------------------------------------------------------+
                                          |
                                          v
+-----------------------------------------------------------------------------------+
|                       Graph-Theoretic Analytics Engine                            |
|  - Articulation Point Detection (Hopcroft-Tarjan S-T Cut-Vertex Algorithm)        |
|  - Betweenness Centrality Ranking across all active attack trajectories           |
|  - Bayesian Cumulative Exploitability & Time-to-Compromise (TTC) Calculation      |
+-----------------------------------------------------------------------------------+
                                          |
                                          v
+-----------------------------------------------------------------------------------+
|                        Grounded Gemini Synthesis Engine                           |
|  - Strictly constrained to verified graph facts (Zero Hallucination)              |
|  - Structured SOC Advisory Report Generation with Severity Scorecards             |
|  - Real-Time Server-Sent Events (SSE) Token Streaming                             |
+-----------------------------------------------------------------------------------+
                                          |
                 +------------------------+------------------------+
                 |                                                 |
                 v                                                 v
+----------------------------------+             +----------------------------------+
|      Interactive Web Console     |             |      Headless REST Service       |
|  - Streamlit UI (:8501)          |             |  - FastAPI Gateway (:8000)       |
|  - 2D Vis.js Topology Graph      |             |  - Swagger Interactive Docs      |
|  - Tactical Entity HUD Inspector |             |  - Microservice Integration      |
|  - Floating SOC Copilot Drawer   |             |  - Automated CI/CD Webhooks      |
|  - Active Defense Exporters      |             +----------------------------------+
+----------------------------------+
```

---

## Core Capabilities

### Graph-Theoretic Chokepoints and Articulation Points
The platform analyzes all multi-hop paths connecting perimeter entry points to internal crown-jewel assets. It identifies **Cut-Vertices (Articulation Points)**—nodes whose removal disconnects the adversary from the target network:
* **Identification**: Implements graph-theoretic traversal algorithms to locate single points of structural failure.
* **Betweenness Centrality**: Measures how frequently an asset or package appears along the shortest attack paths.
* **Optimal Containment**: Recommends the specific asset where defensive intervention yields the greatest reduction in blast radius with minimal operational disruption.

### Quantitative Path Risk and Time-to-Compromise (TTC)
Rather than relying on static CVSS scores alone, ThreatGraphRAG computes composite path-level risk metrics:
* **Bayesian Exploitability**: Models cumulative breach probability as a Bayesian joint distribution incorporating CVSS v3.1 base score, EPSS (Exploit Prediction Scoring System) probability, CISA KEV weaponization status, and asset exposure level.
* **Time-to-Compromise (TTC)**: Estimates the minimum time in minutes required for an adversary to traverse each intermediate hop, based on exploit maturity and lateral movement complexity.

### Active Defense and Automated Countermeasures
When a user simulates mitigating a vulnerability or isolating a compromised workload, the engine calculates the post-mitigation topological state and generates five deployable security artifacts:

1. **Sigma SIEM Detection Rule (YAML)**:
   A multi-source detection rule correlating Kubernetes Ingress audit logs, Endpoint Process Creation (Windows Event ID 4688, Sysmon Event ID 1, Linux auditd execve), and Network Connections (Sysmon Event ID 3, Zeek) with exploit-specific payload patterns and false-positive suppression.
2. **Kubernetes Zero-Trust NetworkPolicy (YAML)**:
   A strict microsegmentation manifest that isolates the compromised workload, dropping all lateral egress to private RFC1918 subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`) and cloud metadata instances (`169.254.169.254`), while preserving cluster CoreDNS (`port 53`) and authenticated SOC forensic inspection channels (`port 8443`).
3. **Automated Bash Quarantine Playbook (Shell)**:
   A DevOps incident containment script executing six sequential phases: node cordoning/tainting, volatile memory dump acquisition (`gcore`), live socket harvesting (`ss -tulpn`), host iptables session termination, cgroup CPU throttling (restricting compromised workloads to 5% CPU quota to deny cryptominers/wipers), and automated Slack/Teams webhook alert dispatch.
4. **Suricata / Snort 3 Network IDS Signatures (Rules)**:
   High-performance deep packet inspection rules targeting inbound exploit delivery payloads, secondary stager callbacks, and lateral movement probes.
5. **Splunk SPL Threat Hunting Query (SQL/SPL)**:
   A multi-stage hunting query that categorizes security telemetry into four kill-chain phases (*Inbound Web Exploit*, *Shell Spawning*, *C2 Egress*, and *Lateral Movement*) and aggregates distinct target assets.

### Live Software Supply Chain and SBOM Auditing
ThreatGraphRAG audits open-source dependencies directly against the threat intelligence graph:
* **Live GitHub Repository Auditing**: Connects to any public GitHub repository (e.g., `apache/logging-log4j2`, `jiaT75/xz`), parses the dependency manifest (`pom.xml`, `requirements.txt`, `package.json`, `pyproject.toml`, or `go.mod`), and maps imported packages directly to known CVEs and APT campaigns.
* **CycloneDX SBOM Parsing**: Ingests enterprise CycloneDX / SPDX JSON bills of materials to assess organizational exposure to supply chain backdoors.

### Conversational SOC Forensics Copilot
A slide-out, draggable analytical drawer embedded within the web interface allows security analysts to ask natural language questions regarding the active attack graph. The Copilot streams responses token-by-token over Server-Sent Events (SSE), referencing verified Neo4j telemetry.

---

## Empirical Evaluation and Benchmarks

The system was evaluated against traditional Vector RAG across enterprise zero-day and supply chain breach scenarios using an automated LLM-as-a-Judge benchmark framework:

| Evaluation Metric | Naive Vector RAG | ThreatGraphRAG | Improvement ($\Delta$) |
| :--- | :---: | :---: | :---: |
| **Multi-Hop Path Recall** | 24.0% | **88.0%** | **+64.0%** |
| **Answer Faithfulness (Zero Hallucination)** | 68.0% | **94.0%** | **+26.0%** |
| **Remediation & Patch Precision** | 42.0% | **92.0%** | **+50.0%** |
| **Query Latency (Traversal)** | 1.84s | **0.12s** | **15x Faster** |

Benchmark evaluation scripts and results are located in `evaluate_threat_rag.py` and `benchmark_results.csv`.

---

## Repository Structure

```
threatgraphrag/
├── api.py                     # FastAPI REST API with Swagger documentation and SSE streaming
├── app.py                     # Streamlit enterprise web dashboard with 2D Vis.js topology graph
├── ingest_threat_data.py       # Neo4j knowledge graph schema initialization and CTI seed loader
├── evaluate_threat_rag.py      # LLM-as-a-Judge quantitative evaluation benchmark suite
├── test_chokepoints.py         # Unit tests for cut-vertices, Bayesian TTC, and defense playbooks
├── test_cache_stream.py        # Unit tests for semantic caching and token streaming
├── benchmark_results.csv       # Comparative experimental results (Vector RAG vs ThreatGraphRAG)
├── requirements.txt            # Python production dependencies
├── Dockerfile                  # Container build recipe
├── docker-compose.yml          # Multi-container orchestration (FastAPI + Streamlit)
├── .env.example                # Template for environment configuration
└── src/                        # Core Python domain modules
    ├── __init__.py
    ├── graph_engine.py         # Cypher traversals, chokepoint math, and active defense generators
    ├── report_generator.py     # Gemini grounding prompt templates and SSE streaming synthesizers
    └── repo_evaluator.py       # Live GitHub repository manifest parser and dependency extractor
```

---

## Installation and Setup

### Prerequisites
* Python 3.10 or 3.11
* A Neo4j AuraDB instance (or local Neo4j 5.x database)
* A Google Gemini API key

### 1. Clone the Repository
```bash
git clone https://github.com/mdmujtaba0022-beep/threatgraphrag.git
cd threatgraphrag
```

### 2. Configure Environment Variables
Create a `.env` file in the project root:
```ini
GEMINI_API_KEY=your_gemini_api_key_here
NEO4J_URI=neo4j+ssc://your_instance.databases.neo4j.io
NEO4J_USERNAME=neo4j
NEO4J_PASSWORD=your_neo4j_password_here
```

### 3. Create and Activate a Virtual Environment
On Windows (PowerShell):
```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
```

On Linux / macOS:
```bash
python3 -m venv venv
source venv/bin/activate
```

### 4. Install Dependencies
```bash
pip install -r requirements.txt
```

### 5. Ingest Knowledge Graph Data
Initialize the Neo4j knowledge base with canonical threat actors, techniques, CVEs, dependencies, and crown-jewel assets:
```bash
python ingest_threat_data.py
```
*(Note: If Neo4j is offline or credentials are not supplied, the platform automatically activates an in-memory CTI traversal engine).*

---

## Execution and Usage

### Interactive Streamlit Console
Launch the web interface:
```bash
python -m streamlit run app.py
```
Navigate to `http://localhost:8501` to access:
* **Attack Graph Visualizer**: Pan, zoom, inspect entity metadata, switch between horizontal, vertical, and force-directed views, and export PNG/JSON topologies.
* **Tactical Entity HUD Inspector**: Click any node to display inbound/outbound attack vectors, CVSS/EPSS metrics, cloud subnet metadata, and remediation bulletins.
* **Active Defense Simulator**: Simulate vulnerability patching or pod isolation, verify mathematical kill-chain severance, and download generated Sigma, Kubernetes, Bash, Suricata, and Splunk playbooks.
* **Supply Chain Auditor**: Scan public GitHub repositories or upload CycloneDX SBOMs.
* **SOC Copilot Drawer**: Expand the draggable side pane for real-time natural language Q&A.

### Headless FastAPI REST Service
Start the REST API server:
```bash
python -m uvicorn api:app --host 127.0.0.1 --port 8000 --reload
```
Access the interactive documentation:
* **Swagger UI**: `http://127.0.0.1:8000/docs`
* **ReDoc**: `http://127.0.0.1:8000/redoc`

### Docker Container Deployment
Deploy the full stack using Docker Compose:
```bash
docker-compose up --build
```
* **Web UI**: `http://localhost:8501`
* **REST API**: `http://localhost:8000`

---

## REST API Reference

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/` | API Gateway status and service health |
| `GET` | `/health` | Connectivity verification for database and Gemini LLM |
| `POST` | `/api/threat-query` | Multi-hop attack path reasoning and AI SOC report generation |
| `POST` | `/api/threat-query-stream` | Server-Sent Events (SSE) token streaming for real-time report delivery |
| `POST` | `/api/graph/chokepoint-analysis` | Computes cut-vertices, betweenness centrality, and Bayesian TTC |
| `POST` | `/api/countermeasure/simulate` | Simulates mitigation, calculates risk deltas, and generates playbooks |
| `POST` | `/api/threat-query/chat` | Conversational SOC Forensics Copilot endpoint |
| `POST` | `/api/scan-github-repo` | Scans external GitHub repository dependencies against the CTI graph |
| `POST` | `/api/scan-sbom` | Audits CycloneDX / SPDX SBOM JSON manifests |
| `GET` | `/api/blast-radius` | Evaluates downstream lateral movement radius for an asset |
| `GET` | `/api/graph-summary` | Returns entity and relationship count telemetry |

### Example Request: Simulating Active Countermeasures
```bash
curl -X POST "http://127.0.0.1:8000/api/countermeasure/simulate" \
     -H "Content-Type: application/json" \
     -d '{
       "target_entity": "CVE-2021-44228",
       "action_type": "patch"
     }'
```

### Example Response
```json
{
  "target_entity": "CVE-2021-44228",
  "action_type": "patch",
  "kill_chain_broken": true,
  "risk_delta": 67,
  "before_risk_score": 89,
  "after_risk_score": 22,
  "severed_edges_count": 3,
  "protected_crown_jewels": [
    "payment-token-vault-service"
  ],
  "sigma_rule": "title: Detect APT29 Multi-Hop Exploitation...",
  "kubernetes_policy": "apiVersion: networking.k8s.io/v1\nkind: NetworkPolicy...",
  "quarantine_script": "#!/usr/bin/env bash\n# ThreatGraphRAG Incident Containment...",
  "suricata_rule": "# ThreatGraphRAG Network IDS Rule Set...",
  "splunk_query": "(index=k8s_audit OR index=web_ingress)..."
}
```

---

## Testing and Quality Assurance

Execute the automated test suite to validate algorithmic correctness, active defense generation, and API contract compliance:

```powershell
# Run Chokepoint & Countermeasure Unit Tests
python -m unittest test_chokepoints.py

# Run Semantic Cache & SSE Token Streaming Tests
python -m unittest test_cache_stream.py

# Run Full-Scale Quantitative Benchmark (LLM-as-a-Judge)
python evaluate_threat_rag.py
```

---

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details. Open-source for academic research, security operations, and enterprise evaluations.
