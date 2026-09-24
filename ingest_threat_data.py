import os
from dotenv import load_dotenv
from neo4j import GraphDatabase

load_dotenv()

NEO4J_URI = os.getenv("NEO4J_URI", "neo4j+ssc://e6c68873.databases.neo4j.io")
NEO4J_USERNAME = os.getenv("NEO4J_USERNAME", "e6c68873")
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD", "your_neo4j_password_here")

driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USERNAME, NEO4J_PASSWORD))

# Real Cyber Threat Intelligence Dataset
CYBER_DATA = {
    "actors": [
        {"name": "APT29 (Cozy Bear)", "origin": "State-Sponsored", "motive": "Espionage"},
        {"name": "Lazarus Group", "origin": "State-Sponsored", "motive": "Financial Theft & Sabotage"},
        {"name": "LockBit Ransomware Cartel", "origin": "Cybercriminal", "motive": "Extortion"}
    ],
    "techniques": [
        {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
        {"id": "T1059", "name": "Command and Scripting Interpreter", "tactic": "Execution"},
        {"id": "T1195", "name": "Supply Chain Compromise", "tactic": "Initial Access"},
        {"id": "T1486", "name": "Data Encrypted for Impact", "tactic": "Impact"}
    ],
    "cves": [
        {"cve": "CVE-2021-44228 (Log4Shell)", "cvss": 10.0, "type": "Remote Code Execution (RCE)", "description": "JNDI lookup flaw in Apache Log4j allowing unauthenticated arbitrary code execution."},
        {"cve": "CVE-2024-3094 (XZ Backdoor)", "cvss": 10.0, "type": "Supply Chain SSH Bypass", "description": "Malicious backdoor inserted into liblzma/xz-utils allowing unauthorized SSH authentication bypass."},
        {"cve": "CVE-2022-22965 (Spring4Shell)", "cvss": 9.8, "type": "Remote Code Execution (RCE)", "description": "Class loader manipulation in Spring Framework via DataBinder leading to pipeline takeover."},
        {"cve": "CVE-2024-21762 (FortiOS Out-of-Bound)", "cvss": 9.8, "type": "Out-of-Bounds Write", "description": "Vulnerability in FortiOS SSL-VPN web portal allowing pre-auth code execution."}
    ],
    "packages": [
        {"name": "org.apache.logging.log4j:log4j-core:2.14.1", "language": "Java", "ecosystem": "Maven"},
        {"name": "xz-utils:5.6.0", "language": "C", "ecosystem": "Linux Package"},
        {"name": "org.springframework:spring-beans:5.3.17", "language": "Java", "ecosystem": "Maven"},
        {"name": "fortios:7.4.2", "language": "Firmware", "ecosystem": "Network OS"}
    ],
    "services": [
        {"name": "Customer-Auth-Service", "tier": "Public-Facing API", "cloud": "AWS EKS", "zone": "DMZ"},
        {"name": "Payment-Processing-Gateway", "tier": "Internal Core", "cloud": "GCP GKE", "zone": "PCI-Compliant"},
        {"name": "Enterprise-SSH-Bastion", "tier": "Infrastructure", "cloud": "On-Premises", "zone": "Management"},
        {"name": "Analytics-ETL-Pipeline", "tier": "Data Processing", "cloud": "AWS Lambda", "zone": "Internal"}
    ],
    "patches": [
        {"name": "Upgrade to Log4j 2.17.1 & Set log4j2.formatMsgNoLookups=true", "action": "Version Upgrade"},
        {"name": "Downgrade xz-utils to 5.4.6 Stable & Revoke SSH keys", "action": "Emergency Rollback"},
        {"name": "Upgrade Spring Framework to 5.3.18 / 5.2.20", "action": "Framework Patch"},
        {"name": "Apply Fortinet Patch 7.4.3 or Disable SSL-VPN Web Portal", "action": "Firmware Update"}
    ]
}

def ingest():
    print("==================================================")
    print("   Ingesting Cyber Threat Intelligence Graph      ")
    print("==================================================\n")
    
    with driver.session() as session:
        # Clear old database
        session.run("MATCH (n) DETACH DELETE n")
        print("[1/4] Cleared old toy data from Neo4j.")

        # Ingest Nodes
        for a in CYBER_DATA["actors"]:
            session.run("MERGE (n:ThreatActor {name: $name, origin: $origin, motive: $motive})", **a)
        for t in CYBER_DATA["techniques"]:
            session.run("MERGE (n:AttackTechnique {name: $name, id: $id, tactic: $tactic})", **t)
        for c in CYBER_DATA["cves"]:
            session.run("MERGE (n:Vulnerability {name: $cve, cvss: $cvss, type: $type, description: $description})", **c)
        for p in CYBER_DATA["packages"]:
            session.run("MERGE (n:SoftwarePackage {name: $name, language: $language, ecosystem: $ecosystem})", **p)
        for s in CYBER_DATA["services"]:
            session.run("MERGE (n:EnterpriseService {name: $name, tier: $tier, cloud: $cloud, zone: $zone})", **s)
        for pt in CYBER_DATA["patches"]:
            session.run("MERGE (n:RemediationPatch {name: $name, action: $action})", **pt)
        print("[2/4] Created Threat Actors, MITRE Techniques, CVEs, Packages, Services, and Patches.")

        # Multi-hop Attack Chains & Dependency Topology
        relationships = [
            # Actor -> Technique
            ("ThreatActor", "APT29 (Cozy Bear)", "AttackTechnique", "Exploit Public-Facing Application", "LEVERAGES"),
            ("ThreatActor", "APT29 (Cozy Bear)", "AttackTechnique", "Supply Chain Compromise", "LEVERAGES"),
            ("ThreatActor", "Lazarus Group", "AttackTechnique", "Command and Scripting Interpreter", "LEVERAGES"),
            ("ThreatActor", "LockBit Ransomware Cartel", "AttackTechnique", "Data Encrypted for Impact", "LEVERAGES"),
            
            # Technique -> CVE
            ("AttackTechnique", "Exploit Public-Facing Application", "Vulnerability", "CVE-2021-44228 (Log4Shell)", "TARGETS_VULNERABILITY"),
            ("AttackTechnique", "Supply Chain Compromise", "Vulnerability", "CVE-2024-3094 (XZ Backdoor)", "TARGETS_VULNERABILITY"),
            ("AttackTechnique", "Exploit Public-Facing Application", "Vulnerability", "CVE-2022-22965 (Spring4Shell)", "TARGETS_VULNERABILITY"),
            ("AttackTechnique", "Command and Scripting Interpreter", "Vulnerability", "CVE-2024-21762 (FortiOS Out-of-Bound)", "TARGETS_VULNERABILITY"),

            # CVE -> Package
            ("Vulnerability", "CVE-2021-44228 (Log4Shell)", "SoftwarePackage", "org.apache.logging.log4j:log4j-core:2.14.1", "EXPLOITS_FLAW_IN"),
            ("Vulnerability", "CVE-2024-3094 (XZ Backdoor)", "SoftwarePackage", "xz-utils:5.6.0", "EXPLOITS_FLAW_IN"),
            ("Vulnerability", "CVE-2022-22965 (Spring4Shell)", "SoftwarePackage", "org.springframework:spring-beans:5.3.17", "EXPLOITS_FLAW_IN"),
            ("Vulnerability", "CVE-2024-21762 (FortiOS Out-of-Bound)", "SoftwarePackage", "fortios:7.4.2", "EXPLOITS_FLAW_IN"),

            # Service -> Package (SBOM Dependencies)
            ("EnterpriseService", "Customer-Auth-Service", "SoftwarePackage", "org.apache.logging.log4j:log4j-core:2.14.1", "DEPENDS_ON"),
            ("EnterpriseService", "Customer-Auth-Service", "SoftwarePackage", "org.springframework:spring-beans:5.3.17", "DEPENDS_ON"),
            ("EnterpriseService", "Enterprise-SSH-Bastion", "SoftwarePackage", "xz-utils:5.6.0", "DEPENDS_ON"),
            ("EnterpriseService", "Payment-Processing-Gateway", "SoftwarePackage", "fortios:7.4.2", "PROTECTED_BY"),

            # Service Lateral Movement (Pivoting)
            ("EnterpriseService", "Customer-Auth-Service", "EnterpriseService", "Payment-Processing-Gateway", "CAN_PIVOT_TO"),
            ("EnterpriseService", "Enterprise-SSH-Bastion", "EnterpriseService", "Analytics-ETL-Pipeline", "CAN_PIVOT_TO"),

            # CVE -> Patch (Remediation)
            ("Vulnerability", "CVE-2021-44228 (Log4Shell)", "RemediationPatch", "Upgrade to Log4j 2.17.1 & Set log4j2.formatMsgNoLookups=true", "MITIGATED_BY"),
            ("Vulnerability", "CVE-2024-3094 (XZ Backdoor)", "RemediationPatch", "Downgrade xz-utils to 5.4.6 Stable & Revoke SSH keys", "MITIGATED_BY"),
            ("Vulnerability", "CVE-2022-22965 (Spring4Shell)", "RemediationPatch", "Upgrade Spring Framework to 5.3.18 / 5.2.20", "MITIGATED_BY"),
            ("Vulnerability", "CVE-2024-21762 (FortiOS Out-of-Bound)", "RemediationPatch", "Apply Fortinet Patch 7.4.3 or Disable SSL-VPN Web Portal", "MITIGATED_BY")
        ]

        for s_type, s_name, t_type, t_name, rel in relationships:
            query = f"""
            MATCH (s:{s_type} {{name: $s_name}})
            MATCH (t:{t_type} {{name: $t_name}})
            MERGE (s)-[r:{rel}]->(t)
            """
            session.run(query, s_name=s_name, t_name=t_name)
        print("[3/4] Successfully linked multi-hop attack paths, software dependencies, and remediation routes.")

        nodes = session.run("MATCH (n) RETURN count(n) AS count").single()["count"]
        edges = session.run("MATCH ()-[r]->() RETURN count(r) AS count").single()["count"]
        print(f"\n[4/4] Verification: Database now contains {nodes} nodes and {edges} relationships!")
        print("\n🎉 Real Cyber Threat Intelligence Graph successfully initialized in Neo4j!")

    driver.close()

if __name__ == "__main__":
    ingest()
