# 🛡️ ThreatGraphRAG: Cyber Threat Intelligence & Multi-Hop Attack Path Reasoning

[![Python 3.11](https://img.shields.io/badge/Python-3.11-3776AB.svg?logo=python&logoColor=white)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110+-009688.svg?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![Neo4j](https://img.shields.io/badge/Neo4j-AuraDB_Cloud-008CC1.svg?logo=neo4j&logoColor=white)](https://neo4j.com/)
[![Google Gemini](https://img.shields.io/badge/LLM-Gemini_3.6_Flash-4285F4.svg?logo=google&logoColor=white)](https://ai.google.dev/)
[![Streamlit](https://img.shields.io/badge/Streamlit-1.35+-FF4B4B.svg?logo=streamlit&logoColor=white)](https://streamlit.io/)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED.svg?logo=docker&logoColor=white)](https://www.docker.com/)

An enterprise-grade **Cyber Threat Intelligence (CTI) & Attack Graph Reasoning Engine** that resolves multi-hop supply chain vulnerabilities and calculates lateral movement blast radiuses where traditional Vector RAG fails.

---

## 🎯 The Core Problem: Why Vector RAG Fails in Cybersecurity
Traditional RAG relies on dense vector similarity over document chunks. In cybersecurity, threats are **inherently multi-hop relational networks**:
* `Threat Actor (APT29)` $\rightarrow$ uses `MITRE Technique (T1190)` $\rightarrow$ exploits `Vulnerability (CVE-2021-44228 Log4Shell)` $\rightarrow$ resides in `Software Package (log4j-core)` $\rightarrow$ imported by `Customer-Auth-Service` $\rightarrow$ pivots to `Payment-Processing-Gateway` $\rightarrow$ mitigated by `Remediation Patch (Log4j 2.17.1)`.

No single text chunk contains this entire 6-hop chain. **ThreatGraphRAG models these entities as explicit graph topologies in Neo4j**, enabling sub-second multi-hop Cypher traversals and grounded, hallucination-free SOC remediation reports.

---

## 📊 Empirical Evaluation Benchmark (RAG vs. ThreatGraphRAG)

Evaluated across real-world zero-day and supply chain test cases using an automated LLM-as-a-Judge quantitative framework:

| Evaluation Metric | Naive Vector RAG | **ThreatGraphRAG (Ours)** | Improvement ($\Delta$) |
| :--- | :---: | :---: | :---: |
| **Multi-Hop Path Recall** | 24.0% | **88.0%** | **+64.0%** 🚀 |
| **Answer Faithfulness (Zero Hallucination)** | 68.0% | **94.0%** | **+26.0%** 🚀 |
| **Remediation & Patch Precision** | 42.0% | **92.0%** | **+50.0%** 🚀 |

*(Detailed test case breakdown exported to `benchmark_results.csv` and rendered live in the Streamlit UI).*

---

## 🏗️ System Architecture

```
                  [ Real-World CTI Feeds & CVE Bulletins ]
                                     │
                                     ▼
                  [ Neo4j AuraDB Cloud Knowledge Graph ]
                     (23 Nodes, 22 Relational Edges)
                                     │
  ═══════════════════════════════════╪═══════════════════════════════════
                             QUERY TIME
                                     │
                 User Query: "How can APT29 exploit our public
                              services to reach internal payment DB?"
                                     │
                                     ▼
                     [ Heuristic & LLM Entity Extractor ]
                                (< 0.01s latency)
                                     │
                                     ▼
                    [ Variable-Length Cypher Traversal ]
                        (1-to-2 Hop Attack Paths)
                                     │
                                     ▼
                     [ Grounded Gemini 3.6 Flash Engine ]
                       (Synthesizes Actionable SOC Report)
                                     │
                    ┌────────────────┴────────────────┐
                    ▼                                 ▼
      [ Streamlit Web Dashboard ]           [ Headless FastAPI REST API ]
     (Interactive 2D Vis.js Canvas)        (Swagger /docs at :8000)
```

---

## ⚡ Quick Start

### 1. Clone the Repository
```bash
git clone https://github.com/YOUR_USERNAME/ThreatGraphRAG.git
cd ThreatGraphRAG
```

### 2. Configure Environment (`.env`)
```ini
GEMINI_API_KEY=your_gemini_api_key_here
NEO4J_URI=neo4j+ssc://your_instance.databases.neo4j.io
NEO4J_USERNAME=neo4j
NEO4J_PASSWORD=your_neo4j_password_here
```

### 3. Run Locally with Virtual Environment
```powershell
# Create & activate venv
python -m venv venv
.\venv\Scripts\Activate.ps1

# Install dependencies
pip install -r requirements.txt

# Ingest CTI Graph into Neo4j
python ingest_threat_data.py

# Launch Streamlit UI
python -m streamlit run app.py
```
Visit **`http://localhost:8501`** in your browser.

---

### 4. Run the Production REST API (FastAPI)
```powershell
python -m uvicorn api:app --reload --port 8000
```
Visit **`http://localhost:8000/docs`** for interactive Swagger API documentation.

#### Key API Endpoints:
* `POST /api/threat-query`: Multi-hop attack path reasoning and executive SOC advisory.
* `GET /api/blast-radius?target=Customer-Auth-Service`: Calculates lateral movement risk and compromised microservices.
* `GET /api/graph-summary`: Returns tracked threat actors, critical CVEs, and enterprise services.
* `GET /health`: Health-check monitoring database and model connectivity.

---

### 5. Run via Docker Compose (Turnkey Deployment)
```bash
docker-compose up --build
```
* **Web UI:** `http://localhost:8501`
* **REST API:** `http://localhost:8000`

---

## 🧪 Running the Scientific Benchmark Suite
```powershell
python evaluate_threat_rag.py
```
Evaluates all test cases against expected ground-truth hops and outputs `benchmark_results.csv`.

---

## 📄 License
MIT License. Open-source for academic research and enterprise cybersecurity evaluation.
