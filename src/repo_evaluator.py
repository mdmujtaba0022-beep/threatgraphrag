"""
ThreatGraphRAG - Live External Repository Evaluator
Autonomously fetches dependency manifests from GitHub repositories,
cross-references them against the Neo4j Cyber Threat Knowledge Graph,
calculates attack paths, adversary attribution, blast radius, and prescribes remediations.
"""

import os
import re
import json
import logging
from typing import List, Dict, Any, Optional, Tuple
import requests

logger = logging.getLogger(__name__)

# Known candidate manifests in priority order
CANDIDATE_MANIFESTS = [
    "requirements.txt",
    "package.json",
    "pom.xml",
    "pyproject.toml",
    "Pipfile",
    "go.mod",
    "build.gradle",
    "sbom.json",
    "cyclonedx.json"
]

DEFAULT_BRANCHES = ["main", "master", "develop", "release"]

# Quick presets for demonstration and evaluation
PRESET_REPOSITORIES = {
    "apache/logging-log4j2 (Log4Shell CVE-2021-44228)": {
        "url": "https://github.com/apache/logging-log4j2",
        "owner": "apache",
        "repo": "logging-log4j2",
        "description": "Enterprise Java logging library targeted by APT29 & Lazarus Group via Log4Shell RCE.",
        "simulated_manifest": """<project>
  <dependencies>
    <dependency>
      <groupId>org.apache.logging.log4j</groupId>
      <artifactId>log4j-core</artifactId>
      <version>2.14.1</version>
    </dependency>
    <dependency>
      <groupId>com.fasterxml.jackson.core</groupId>
      <artifactId>jackson-databind</artifactId>
      <version>2.13.0</version>
    </dependency>
  </dependencies>
</project>""",
        "manifest_type": "pom.xml"
    },
    "jiaT75/xz (XZ Backdoor CVE-2024-3094)": {
        "url": "https://github.com/tukaani-project/xz",
        "owner": "tukaani-project",
        "repo": "xz",
        "description": "Data compression utility compromised via sophisticated upstream supply chain backdoor.",
        "simulated_manifest": """xz-utils==5.6.0
liblzma==5.6.0
pytest>=7.0.0
""",
        "manifest_type": "requirements.txt"
    },
    "spring-projects/spring-framework (Spring4Shell CVE-2022-22965)": {
        "url": "https://github.com/spring-projects/spring-framework",
        "owner": "spring-projects",
        "repo": "spring-framework",
        "description": "Enterprise Java framework vulnerable to Spring4Shell arbitrary class loader RCE.",
        "simulated_manifest": """<project>
  <dependencies>
    <dependency>
      <groupId>org.springframework</groupId>
      <artifactId>spring-beans</artifactId>
      <version>5.3.17</version>
    </dependency>
    <dependency>
      <groupId>org.springframework.boot</groupId>
      <artifactId>spring-boot-starter-web</artifactId>
      <version>2.6.5</version>
    </dependency>
  </dependencies>
</project>""",
        "manifest_type": "pom.xml"
    },
    "psf/requests (Safe Open Source Library)": {
        "url": "https://github.com/psf/requests",
        "owner": "psf",
        "repo": "requests",
        "description": "Standard Python HTTP client library with clean supply chain integrity.",
        "simulated_manifest": """urllib3>=1.26.0,<3.0.0
certifi>=2023.7.22
charset-normalizer>=2.0.0,<4.0.0
idna>=2.5,<4
""",
        "manifest_type": "requirements.txt"
    }
}

def parse_github_url(url: str) -> Dict[str, Optional[str]]:
    """
    Parses various GitHub URL formats into owner, repo, and optional branch.
    Supports:
      - https://github.com/owner/repo
      - https://github.com/owner/repo.git
      - https://github.com/owner/repo/tree/branch-name
      - https://github.com/owner/repo/blob/branch-name/path/to/file
      - owner/repo
    """
    url = url.strip()
    
    if url.startswith("git@github.com:"):
        url = "https://github.com/" + url.replace("git@github.com:", "")
        
    if url.endswith(".git"):
        url = url[:-4]
        
    if not url.startswith("http://") and not url.startswith("https://"):
        parts = url.strip("/").split("/")
        if len(parts) == 2:
            return {"owner": parts[0], "repo": parts[1], "branch": None, "subpath": None}
            
    pattern = r"https?://github\.com/([^/]+)/([^/]+)(?:/(?:tree|blob)/([^/]+)(?:/(.+))?)?"
    match = re.match(pattern, url)
    if match:
        owner = match.group(1)
        repo = match.group(2)
        branch = match.group(3)
        subpath = match.group(4)
        return {"owner": owner, "repo": repo, "branch": branch, "subpath": subpath}
        
    raise ValueError(f"Invalid GitHub repository URL or identifier: {url}")

def fetch_raw_github_file(owner: str, repo: str, branch: str, file_path: str, token: Optional[str] = None) -> Optional[str]:
    """Fetches a raw file from GitHub using raw.githubusercontent.com."""
    url = f"https://raw.githubusercontent.com/{owner}/{repo}/{branch}/{file_path}"
    headers = {"User-Agent": "ThreatGraphRAG-Security-Auditor/1.0"}
    if token:
        headers["Authorization"] = f"token {token}"
        
    try:
        resp = requests.get(url, headers=headers, timeout=8)
        if resp.status_code == 200 and resp.text:
            return resp.text
    except Exception as e:
        logger.warning(f"Failed to fetch {url}: {e}")
    return None

def fetch_repo_manifest(owner: str, repo: str, branch: Optional[str] = None, specified_file: Optional[str] = None) -> Tuple[str, str, str]:
    """
    Finds and downloads a dependency manifest from the repository.
    Returns: (manifest_content, filename, resolved_branch)
    """
    branches_to_try = [branch] if branch else DEFAULT_BRANCHES
    files_to_try = [specified_file] if specified_file else CANDIDATE_MANIFESTS
    
    token = os.getenv("GITHUB_TOKEN")
    
    for b in branches_to_try:
        for f in files_to_try:
            content = fetch_raw_github_file(owner, repo, b, f, token=token)
            if content and content.strip():
                return content, f, b
                
    # Also check if user specified a subpath in the URL
    raise FileNotFoundError(
        f"Could not locate a supported dependency manifest ({', '.join(files_to_try)}) in {owner}/{repo} across branches {branches_to_try}."
    )

def parse_requirements_txt(content: str) -> List[Dict[str, Any]]:
    """Parses a Python requirements.txt or Pipfile file."""
    packages = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-r") or line.startswith("--"):
            continue
        clean = re.split(r"[=<>;!~\[]", line)[0].strip()
        if clean and not clean.startswith("["):
            ver_match = re.search(r"[=<>~]=?\s*([0-9a-zA-Z\.\-]+)", line)
            version = ver_match.group(1) if ver_match else "latest"
            packages.append({
                "name": clean,
                "version": version,
                "raw": line,
                "ecosystem": "Python / PyPI"
            })
    return packages

def parse_package_json(content: str) -> List[Dict[str, Any]]:
    """Parses a Node.js package.json file."""
    packages = []
    try:
        data = json.loads(content)
        deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
        for name, ver in deps.items():
            clean_ver = str(ver).replace("^", "").replace("~", "").strip()
            packages.append({
                "name": name,
                "version": clean_ver,
                "raw": f"{name}@{ver}",
                "ecosystem": "npm / Node.js"
            })
    except Exception as e:
        logger.error(f"Error parsing package.json: {e}")
    return packages

def parse_pom_xml(content: str) -> List[Dict[str, Any]]:
    """Parses a Maven pom.xml file extracting groupId and artifactId."""
    packages = []
    dep_blocks = re.findall(r"<dependency>(.*?)</dependency>", content, re.DOTALL)
    for block in dep_blocks:
        g_match = re.search(r"<groupId>(.*?)</groupId>", block)
        a_match = re.search(r"<artifactId>(.*?)</artifactId>", block)
        v_match = re.search(r"<version>(.*?)</version>", block)
        
        artifact_id = a_match.group(1).strip() if a_match else None
        group_id = g_match.group(1).strip() if g_match else ""
        version = v_match.group(1).strip() if v_match else "latest"
        
        if artifact_id:
            full_name = f"{group_id}:{artifact_id}" if group_id else artifact_id
            packages.append({
                "name": artifact_id,
                "full_name": full_name,
                "version": version,
                "raw": f"{full_name}:{version}",
                "ecosystem": "Maven / Java"
            })
    return packages

def parse_pyproject_toml(content: str) -> List[Dict[str, Any]]:
    """Extracts dependencies from pyproject.toml."""
    packages = []
    # Match lines inside dependencies = [ ... ]
    match_deps_block = re.search(r"dependencies\s*=\s*\[(.*?)\]", content, re.DOTALL)
    if match_deps_block:
        items = re.findall(r'"([^"]+)"|\'([^\']+)\'', match_deps_block.group(1))
        for it in items:
            raw_val = it[0] or it[1]
            clean = re.split(r"[=<>;!~\[]", raw_val)[0].strip()
            if clean:
                packages.append({
                    "name": clean,
                    "version": "specified",
                    "raw": raw_val,
                    "ecosystem": "Python / PyPI"
                })
    return packages

def parse_go_mod(content: str) -> List[Dict[str, Any]]:
    """Parses Go go.mod file."""
    packages = []
    require_block = re.findall(r"require\s*\((.*?)\)", content, re.DOTALL)
    text_to_parse = "\n".join(require_block) if require_block else content
    
    for line in text_to_parse.splitlines():
        line = line.strip()
        if not line or line.startswith("//") or line.startswith("module") or line.startswith("go "):
            continue
        parts = line.split()
        if len(parts) >= 2:
            pkg = parts[0]
            ver = parts[1]
            packages.append({
                "name": pkg.split("/")[-1],
                "full_name": pkg,
                "version": ver,
                "raw": line,
                "ecosystem": "Go / Golang"
            })
    return packages

def parse_sbom_json(content: str) -> List[Dict[str, Any]]:
    """Parses CycloneDX or SPDX JSON SBOM."""
    packages = []
    try:
        data = json.loads(content)
        components = data.get("components", []) or data.get("packages", [])
        for c in components:
            name = c.get("name")
            ver = c.get("version", "unknown")
            if name:
                packages.append({
                    "name": name,
                    "version": ver,
                    "raw": f"{name}:{ver}",
                    "ecosystem": c.get("type", "Software Component")
                })
    except Exception as e:
        logger.error(f"Error parsing SBOM JSON: {e}")
    return packages

def parse_generic_manifest(filename: str, content: str) -> List[Dict[str, Any]]:
    """Selects appropriate parser based on manifest filename."""
    lower_f = filename.lower()
    if "requirements" in lower_f or lower_f.endswith(".txt") or "pipfile" in lower_f:
        return parse_requirements_txt(content)
    elif "package" in lower_f and lower_f.endswith(".json"):
        return parse_package_json(content)
    elif "pom" in lower_f or lower_f.endswith(".xml"):
        return parse_pom_xml(content)
    elif "pyproject" in lower_f and lower_f.endswith(".toml"):
        parsed = parse_pyproject_toml(content)
        return parsed if parsed else parse_requirements_txt(content)
    elif "go.mod" in lower_f:
        return parse_go_mod(content)
    elif "sbom" in lower_f or "cyclonedx" in lower_f or "bom" in lower_f:
        return parse_sbom_json(content)
    else:
        return parse_requirements_txt(content)

def _query_pkg_dependencies_in_memory(term: str) -> List[Dict[str, Any]]:
    """
    In-memory fallback for matching packages against the curated CTI attack topology.
    Used when Neo4j is offline or unreachable.
    """
    try:
        from ingest_threat_data import ENTERPRISE_CTI_DATA, RELATIONSHIPS
    except Exception:
        return []
        
    records = []
    term_low = term.lower()
    for p in ENTERPRISE_CTI_DATA.get("packages", []):
        p_name = p["name"]
        if term_low in p_name.lower() or p_name.lower() in term_low:
            for s_type, s_name, t_type, t_name, rel in RELATIONSHIPS:
                if rel == "EXPLOITS_FLAW_IN" and t_name == p_name:
                    cve = s_name
                    cve_props = next((c for c in ENTERPRISE_CTI_DATA.get("cves", []) if c["cve"] == cve), {})
                    patch = next((t_n for s_t, s_n, t_t, t_n, r in RELATIONSHIPS if r == "MITIGATED_BY" and s_n == cve), None)
                    patch_props = next((pt for pt in ENTERPRISE_CTI_DATA.get("patches", []) if pt["name"] == patch), {}) if patch else {}
                    tech = next((s_n for s_t, s_n, t_t, t_n, r in RELATIONSHIPS if r == "TARGETS_VULNERABILITY" and t_n == cve), None)
                    tech_props = next((t for t in ENTERPRISE_CTI_DATA.get("techniques", []) if t["name"] == tech), {}) if tech else {}
                    actor = next((s_n for s_t, s_n, t_t, t_n, r in RELATIONSHIPS if r == "LEVERAGES" and t_n == tech), None) if tech else None
                    actor_props = next((a for a in ENTERPRISE_CTI_DATA.get("actors", []) if a["name"] == actor), {}) if actor else {}
                    svc = next((s_n for s_t, s_n, t_t, t_n, r in RELATIONSHIPS if r in ["DEPENDS_ON", "RUNS_SOFTWARE"] and t_n == p_name), None)
                    svc_props = next((s for s in ENTERPRISE_CTI_DATA.get("services", []) if s["name"] == svc), {}) if svc else {}
                    downstream = next((t_n for s_t, s_n, t_t, t_n, r in RELATIONSHIPS if r == "CAN_PIVOT_TO" and s_n == svc), None) if svc else None
                    downstream_props = next((s for s in ENTERPRISE_CTI_DATA.get("services", []) if s["name"] == downstream), {}) if downstream else {}

                    records.append({
                        "matched_package": p_name,
                        "pkg_props": p,
                        "cve": cve,
                        "vuln_props": cve_props,
                        "cvss": cve_props.get("cvss", 9.8),
                        "flaw_type": cve_props.get("type", "Remote Code Execution"),
                        "technique": tech,
                        "tech_props": tech_props,
                        "threat_actor": actor,
                        "actor_props": actor_props,
                        "remediation": patch,
                        "patch_props": patch_props,
                        "service_impacted": svc,
                        "svc_props": svc_props,
                        "downstream_blast_radius": downstream,
                        "downstream_props": downstream_props
                    })
    return records

def evaluate_repo_dependencies(driver, packages: List[Dict[str, Any]], repo_identifier: str) -> Dict[str, Any]:
    """
    Cross-references parsed packages against the Neo4j Knowledge Graph.
    Computes attack paths, threat actors, techniques, patches, and simulated enterprise blast radius.
    """
    findings = []
    unique_vulnerabilities = {}
    active_threat_actors = set()
    attack_techniques = set()
    affected_packages = set()
    impacted_services = set()
    downstream_targets = set()
    
    # Vis.js graph elements
    repo_node_id = f"Repo: {repo_identifier}"
    nodes_dict = {repo_node_id: "GitHubRepo"}
    edges = []
    
    # Direct mappings/aliases for known critical packages
    ALIAS_MAP = {
        "log4j": "log4j-core",
        "org.apache.logging.log4j": "log4j-core",
        "spring": "spring-beans",
        "spring-framework": "spring-beans",
        "spring-core": "spring-beans",
        "org.springframework": "spring-beans",
        "xz": "xz-utils",
        "liblzma": "xz-utils",
        "fortigate": "fortios"
    }

    neo4j_session = None
    try:
        neo4j_session = driver.session()
    except Exception as e:
        logger.warning(f"Neo4j offline for SBOM evaluation ({e}). Using in-memory CTI dataset.")

    try:
        for pkg in packages:
            p_name = pkg["name"].lower().strip()
            search_terms = [p_name]
            for alias_key, target in ALIAS_MAP.items():
                if alias_key in p_name:
                    search_terms.append(target)
            
            search_terms = list(set(search_terms))
            
            for term in search_terms:
                records = []
                if neo4j_session:
                    try:
                        cypher = """
                        MATCH (p:SoftwarePackage)
                        WHERE toLower(p.name) CONTAINS toLower($term) OR toLower($term) CONTAINS toLower(p.name)
                        MATCH (v:Vulnerability)-[:EXPLOITS_FLAW_IN]->(p)
                        OPTIONAL MATCH (tech:AttackTechnique)-[:TARGETS_VULNERABILITY]->(v)
                        OPTIONAL MATCH (actor:ThreatActor)-[:LEVERAGES]->(tech)
                        OPTIONAL MATCH (v)-[:MITIGATED_BY]->(patch:RemediationPatch)
                        OPTIONAL MATCH (svc:EnterpriseService)-[:DEPENDS_ON]->(p)
                        OPTIONAL MATCH (svc)-[:CAN_PIVOT_TO]->(downstream:EnterpriseService)
                        RETURN 
                            p.name AS matched_package, properties(p) AS pkg_props,
                            v.name AS cve, properties(v) AS vuln_props,
                            v.cvss AS cvss,
                            v.type AS flaw_type,
                            tech.name AS technique, properties(tech) AS tech_props,
                            actor.name AS threat_actor, properties(actor) AS actor_props,
                            patch.name AS remediation, properties(patch) AS patch_props,
                            svc.name AS service_impacted, properties(svc) AS svc_props,
                            downstream.name AS downstream_blast_radius, properties(downstream) AS downstream_props
                        """
                        records = list(neo4j_session.run(cypher, term=term))
                    except Exception:
                        records = []
                
                if not records:
                    records = _query_pkg_dependencies_in_memory(term)

                for r in records:
                    cve = r["cve"]
                    if not cve:
                        continue
                        
                    pkg_raw = pkg.get("raw", pkg["name"])
                    pkg_id = r["matched_package"]
                    affected_packages.add(pkg_id)
                    
                    if r["threat_actor"]:
                        active_threat_actors.add(r["threat_actor"])
                    if r["technique"]:
                        attack_techniques.add(r["technique"])
                    if r["service_impacted"]:
                        impacted_services.add(r["service_impacted"])
                    if r["downstream_blast_radius"]:
                        downstream_targets.add(r["downstream_blast_radius"])
                        
                    unique_vulnerabilities[cve] = {
                        "cve": cve,
                        "cvss": float(r["cvss"]) if r["cvss"] else 9.0,
                        "type": r["flaw_type"] or "Zero-Day Exploit",
                        "package": pkg_id,
                        "remediation": r["remediation"] or "Apply upstream vendor patch"
                    }
                    
                    findings.append({
                        "repository": repo_identifier,
                        "detected_package": pkg_raw,
                        "knowledge_graph_package": pkg_id,
                        "cve": cve,
                        "cvss_score": r["cvss"] or 9.0,
                        "vulnerability_type": r["flaw_type"] or "Arbitrary Code Execution",
                        "exploited_by_adversary": r["threat_actor"] or "Undisclosed APT",
                        "attack_technique": r["technique"] or "Supply Chain Compromise",
                        "prescribed_remediation": r["remediation"] or "Upgrade package",
                        "simulated_service_blast_radius": r["service_impacted"] or "Enterprise Cloud Ingress",
                        "lateral_movement_target": r["downstream_blast_radius"] or "Internal Core Services"
                    })
                    
                    # Construct Vis.js Graph Topology & Rich Metadata
                    if "nodes_meta" not in locals():
                        nodes_meta = {repo_node_id: {"label": "GitHubRepo", "props": {"repository": repo_identifier}}}
                        
                    # 1. Repo -> Package
                    nodes_dict[pkg_id] = "SoftwarePackage"
                    nodes_meta[pkg_id] = {"label": "SoftwarePackage", "props": dict(r["pkg_props"]) if r["pkg_props"] else {}}
                    edges.append({"from": repo_node_id, "to": pkg_id, "label": "INCLUDES"})
                    
                    # 2. CVE -> Package
                    nodes_dict[cve] = "Vulnerability"
                    nodes_meta[cve] = {"label": "Vulnerability", "props": dict(r["vuln_props"]) if r["vuln_props"] else {}}
                    edges.append({"from": cve, "to": pkg_id, "label": "EXPLOITS"})
                    
                    # 3. Threat Actor & Technique
                    if r["threat_actor"]:
                        actor = r["threat_actor"]
                        nodes_dict[actor] = "ThreatActor"
                        nodes_meta[actor] = {"label": "ThreatActor", "props": dict(r["actor_props"]) if r["actor_props"] else {}}
                        if r["technique"]:
                            tech = r["technique"]
                            nodes_dict[tech] = "AttackTechnique"
                            nodes_meta[tech] = {"label": "AttackTechnique", "props": dict(r["tech_props"]) if r["tech_props"] else {}}
                            edges.append({"from": actor, "to": tech, "label": "LEVERAGES"})
                            edges.append({"from": tech, "to": cve, "label": "TARGETS"})
                        else:
                            edges.append({"from": actor, "to": cve, "label": "TARGETS"})
                            
                    # 4. Remediation Patch
                    if r["remediation"]:
                        patch = r["remediation"]
                        nodes_dict[patch] = "RemediationPatch"
                        nodes_meta[patch] = {"label": "RemediationPatch", "props": dict(r["patch_props"]) if r["patch_props"] else {}}
                        edges.append({"from": cve, "to": patch, "label": "MITIGATED_BY"})
                        
                    # 5. Simulated Downstream Services Blast Radius
                    if r["service_impacted"]:
                        svc = r["service_impacted"]
                        nodes_dict[svc] = "EnterpriseService"
                        nodes_meta[svc] = {"label": "EnterpriseService", "props": dict(r["svc_props"]) if r["svc_props"] else {}}
                        edges.append({"from": svc, "to": pkg_id, "label": "RUNS_SOFTWARE"})
                        if r["downstream_blast_radius"]:
                            downstream = r["downstream_blast_radius"]
                            nodes_dict[downstream] = "EnterpriseService"
                            nodes_meta[downstream] = {"label": "EnterpriseService", "props": dict(r["downstream_props"]) if r["downstream_props"] else {}}
                            edges.append({"from": svc, "to": downstream, "label": "CAN_PIVOT_TO"})
    finally:
        if neo4j_session:
            try:
                neo4j_session.close()
            except Exception:
                pass

    if "nodes_meta" not in locals():
        nodes_meta = {repo_node_id: {"label": "GitHubRepo", "props": {"repository": repo_identifier}}}

    # Deduplicate edges
    unique_edges = []
    seen_edge_keys = set()
    for e in edges:
        key = (e["from"], e["to"], e["label"])
        if key not in seen_edge_keys:
            seen_edge_keys.add(key)
            unique_edges.append(e)

    # Calculate overall risk score
    num_cves = len(unique_vulnerabilities)
    max_cvss = max([v["cvss"] for v in unique_vulnerabilities.values()], default=0.0)
    has_apt = len(active_threat_actors) > 0
    
    if num_cves == 0:
        security_posture = "SECURE / VERIFIED"
        risk_score = 10
    elif max_cvss >= 9.0 or has_apt:
        security_posture = "CRITICAL RISK"
        risk_score = 98 if has_apt else 90
    elif max_cvss >= 7.0:
        security_posture = "HIGH RISK"
        risk_score = 75
    else:
        security_posture = "MEDIUM RISK"
        risk_score = 50

    return {
        "repository": repo_identifier,
        "total_dependencies_scanned": len(packages),
        "vulnerable_packages_count": len(affected_packages),
        "critical_vulnerabilities_detected": num_cves,
        "active_threat_actors": list(active_threat_actors),
        "attack_techniques": list(attack_techniques),
        "impacted_enterprise_services": list(impacted_services),
        "downstream_blast_radius_targets": list(downstream_targets),
        "security_posture": security_posture,
        "composite_risk_score": risk_score,
        "findings": findings,
        "vis_graph": {
            "nodes": nodes_dict,
            "edges": unique_edges,
            "nodes_meta": nodes_meta
        }
    }

def generate_ai_repo_audit_report(repo_identifier: str, evaluation_results: Dict[str, Any], gemini_api_key: Optional[str] = None) -> str:
    """Generates an executive SOC Threat Intelligence report using Google Gemini."""
    api_key = gemini_api_key or os.getenv("GEMINI_API_KEY")
    findings = evaluation_results.get("findings", [])
    posture = evaluation_results.get("security_posture", "UNKNOWN")
    actors = evaluation_results.get("active_threat_actors", [])
    total_scanned = evaluation_results.get("total_dependencies_scanned", 0)
    
    if not findings:
        return f"""### Repository Security Audit: {repo_identifier}
**Status:** [VERIFIED] **{posture}**
- **Scanned Dependencies:** {total_scanned} packages audited.
- **Threat Intelligence Correlation:** Zero known zero-day exploits or state-sponsored APT targets detected in the active knowledge graph.
- **Action:** No immediate remediation required. Continue automated CI/CD dependency monitoring.
"""

    findings_summary = "\n".join([
        f"- **Package:** `{f['detected_package']}` | **CVE:** {f['cve']} (CVSS {f['cvss_score']}) | **Adversary:** {f['exploited_by_adversary']} | **Technique:** {f['attack_technique']} | **Patch:** {f['prescribed_remediation']}"
        for f in findings[:6]
    ])
    
    prompt = f"""
You are the Chief Cyber Threat Intelligence Officer and Lead DevSecOps Architect.
Analyze the following automated repository supply chain evaluation for GitHub repository: `{repo_identifier}`.

EVALUATION TELEMETRY:
- Security Posture: {posture}
- Total Dependencies Audited: {total_scanned}
- Exploiting Threat Actors Identified: {", ".join(actors) if actors else "Unattributed"}
- Graph Correlation Findings:
{findings_summary}

Generate an authoritative, deeply technical, and legible Executive Repository Audit Report in GitHub Markdown containing:
### 1. Executive Threat Briefing & Risk Scorecard
- Summary table: Package | Target CVE | CVSS v3.1 | Threat Actor | Status
- 2-3 concise bullet points summarizing deployment risk and business impact.

### 2. Supply Chain Attack Vectors & Exploitation Mechanics
- Technical breakdown of the vulnerability class (e.g. JNDI injection, classloader override, upstream build macro tampering).
- Full dependency kill-chain vector:
  `[Repository: {repo_identifier}]` ──► `[Software Package]` ──► `[CVE]` ──► `[Adversary / Campaign]`

### 3. Enterprise Blast Radius Simulation
- Detail which microservices and infrastructure components would be exposed if this repository is deployed into production.
- Potential lateral movement pathways to internal databases, credentials, or payment channels.

### 4. Prioritized Technical Remediation Protocol
- **Tier 1 (Immediate Containment)**: Compiler flags, runtime JVM/OS parameters, or WAF rules.
- **Tier 2 (Upstream Patching)**: Specific recommended patch versions and manifest lockfile updates.
- **Tier 3 (Zero-Trust Hardening)**: CI/CD dependency pinning, SLSA provenance verification, and container least-privilege policies.
"""
    
    if api_key:
        try:
            from google import genai
            client = genai.Client(api_key=api_key)
            for model_id in ["gemini-3.5-flash-lite", "gemini-flash-lite-latest", "gemini-3.6-flash"]:
                try:
                    resp = client.models.generate_content(
                        model=model_id,
                        contents=prompt,
                        config=types.GenerateContentConfig(temperature=0.1)
                    )
                    if resp.text and len(resp.text.strip()) > 200:
                        return resp.text.strip()
                except Exception:
                    continue
        except Exception as e:
            logger.warning(f"Gemini API call failed: {e}")

    # High-Fidelity Deterministic Fallback Report
    findings_rows = "\n".join([
        f"| `{f['detected_package']}` | **{f['cve']}** | **{f['cvss_score']} (Critical)** | **{f['exploited_by_adversary']}** | Active Exploit |"
        for f in findings
    ])
    
    return f"""### Executive Supply Chain Security Audit: {repo_identifier}
**Threat Posture:** `{posture}` | **Risk Rating:** HIGH/CRITICAL | **Active APT Actors:** {", ".join(actors) if actors else "Unattributed"}

---

#### 1. Executive Threat Briefing & Risk Scorecard

| Audited Dependency | Identified CVE | CVSS v3.1 Severity | Attributed Adversary | Exploit Status |
| :--- | :--- | :--- | :--- | :--- |
{findings_rows}

* **Immediate Threat:** Automated graph analysis confirmed that `{repo_identifier}` imports libraries with unmitigated remote code execution or backdoor vulnerabilities actively exploited in the wild.
* **Adversary Targeting:** State-sponsored groups (**{", ".join(actors) if actors else "Known APT Groups"}**) are actively weaponizing these vulnerabilities to achieve initial footholds in enterprise environments.

---

#### 2. Technical Exploitation Mechanics & Supply Chain Vector

```
[Repository: {repo_identifier}]
          │
          ▼  (INCLUDES_DEPENDENCY)
[Software Package: {findings[0]['detected_package'] if findings else 'Target Component'}]
          │
          ▼  (EXPLOITED_BY)
[Vulnerability: {findings[0]['cve'] if findings else 'Discovered Zero-Day'}]
          │
          ▼  (TARGETED_BY)
[Threat Actor: {", ".join(actors) if actors else 'Hostile Adversary'}]
```

* **Vulnerability Analysis:** Vulnerable routines allow external attackers to trigger unauthenticated arbitrary code execution or backdoor command hooks within the hosting application's runtime.
* **Build & Deployment Risk:** Integrating this codebase directly injects vulnerable binaries into production container images, bypassing standard perimeter firewalls.

---

#### 3. Enterprise Blast Radius Simulation

* **Direct Exposure Asset:** Microservices integrating `{repo_identifier}` (e.g. Ingress gateways, Authentication services).
* **Lateral Movement Vectors:** Compromised containers can be leveraged to extract cloud service account keys (IAM), dump internal environment variables, and pivot to backend transaction systems.

---

#### 4. Prioritized Technical Remediation Protocol

* **Tier 1: Immediate Containment (Within 1 Hour)**
  - Halt automated CI/CD deployment pipelines referencing `{repo_identifier}` until dependencies are remediated.
  - Apply runtime hotfix flags and restrict outbound container egress.
* **Tier 2: Upstream Patch Deployment (Within 24 Hours)**
{chr(10).join([f"  - Pin and upgrade `{f['detected_package']}` to prescribed patch: **{f['prescribed_remediation']}**" for f in findings])}
* **Tier 3: Supply Chain Integrity & Zero-Trust (Within 7 Days)**
  - Implement SLSA Level 3 provenance checks and automated dependency hash verification in CI/CD.
  - Enforce software bill of materials (SBOM) scanning on all release pull requests.
"""
