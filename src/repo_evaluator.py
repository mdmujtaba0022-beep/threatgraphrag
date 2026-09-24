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

    with driver.session() as session:
        for pkg in packages:
            p_name = pkg["name"].lower().strip()
            search_terms = [p_name]
            for alias_key, target in ALIAS_MAP.items():
                if alias_key in p_name:
                    search_terms.append(target)
            
            search_terms = list(set(search_terms))
            
            for term in search_terms:
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
                    p.name AS matched_package,
                    v.name AS cve,
                    v.cvss AS cvss,
                    v.type AS flaw_type,
                    tech.name AS technique,
                    actor.name AS threat_actor,
                    patch.name AS remediation,
                    svc.name AS service_impacted,
                    downstream.name AS downstream_blast_radius
                """
                records = list(session.run(cypher, term=term))
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
                    
                    # Construct Vis.js Graph Topology
                    # 1. Repo -> Package
                    nodes_dict[pkg_id] = "SoftwarePackage"
                    edges.append({"from": repo_node_id, "to": pkg_id, "label": "INCLUDES"})
                    
                    # 2. CVE -> Package
                    nodes_dict[cve] = "Vulnerability"
                    edges.append({"from": cve, "to": pkg_id, "label": "EXPLOITS"})
                    
                    # 3. Threat Actor & Technique
                    if r["threat_actor"]:
                        actor = r["threat_actor"]
                        nodes_dict[actor] = "ThreatActor"
                        if r["technique"]:
                            tech = r["technique"]
                            nodes_dict[tech] = "AttackTechnique"
                            edges.append({"from": actor, "to": tech, "label": "LEVERAGES"})
                            edges.append({"from": tech, "to": cve, "label": "TARGETS"})
                        else:
                            edges.append({"from": actor, "to": cve, "label": "TARGETS"})
                            
                    # 4. Remediation Patch
                    if r["remediation"]:
                        patch = r["remediation"]
                        nodes_dict[patch] = "RemediationPatch"
                        edges.append({"from": cve, "to": patch, "label": "MITIGATED_BY"})
                        
                    # 5. Simulated Downstream Services Blast Radius
                    if r["service_impacted"]:
                        svc = r["service_impacted"]
                        nodes_dict[svc] = "EnterpriseService"
                        edges.append({"from": svc, "to": pkg_id, "label": "RUNS_SOFTWARE"})
                        if r["downstream_blast_radius"]:
                            downstream = r["downstream_blast_radius"]
                            nodes_dict[downstream] = "EnterpriseService"
                            edges.append({"from": svc, "to": downstream, "label": "CAN_PIVOT_TO"})

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
            "edges": unique_edges
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
        return f"""### 🛡️ Repository Security Audit: {repo_identifier}
**Status:** ✅ **{posture}**
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

Generate an authoritative, concise Executive Repository Audit Report in GitHub Markdown containing:
1. Executive Security Briefing: Risk summary and business impact if merged/deployed.
2. Adversary Attack Vectors & Exploitation Chain: How the identified threat actors exploit these vulnerabilities through the supply chain.
3. Enterprise Blast Radius Simulation: How this repository impacts downstream microservices and cloud infrastructure.
4. Prioritized Remediation Roadmap: Exact step-by-step actions, patches, and compiler/runtime workarounds.

Keep it direct, professional, and actionable. Do not use complex unicode characters that break cp1252.
"""
    
    if api_key:
        try:
            from google import genai
            client = genai.Client(api_key=api_key)
            for model_id in ["gemini-2.5-flash", "gemini-3.6-flash"]:
                try:
                    resp = client.models.generate_content(model=model_id, contents=prompt)
                    if resp.text:
                        return resp.text
                except Exception:
                    continue
        except Exception as e:
            logger.warning(f"Gemini API call failed: {e}")

    # Fallback template if Gemini is unavailable
    return f"""### Executive Repository Security Audit: {repo_identifier}
**Threat Posture:** {posture} | **Active Threat Actors:** {", ".join(actors) if actors else "Known APT Groups"}

#### 1. Threat Summary
Automated graph traversal discovered **{len(findings)} supply chain exposure(s)** across **{total_scanned}** audited packages. The repository imports components with unmitigated remote code execution or backdoor vulnerabilities actively exploited in the wild.

#### 2. Discovered Vulnerability Matrix
{findings_summary}

#### 3. Recommended Remediation
1. **Immediate Dependency Freeze**: Halt deployment pipelines referencing these dependencies.
2. **Apply Prescribed Upstream Patches**:
{chr(10).join([f"   - {f['cve']}: {f['prescribed_remediation']}" for f in findings[:4]])}
3. **Network Isolation**: Implement zero-trust egress filtering to block adversarial lateral movement and C2 communications.
"""
