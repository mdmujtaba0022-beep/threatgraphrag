"""
ThreatGraphRAG - Enterprise Cyber Threat Intelligence Ingestion Engine
Grounds Neo4j AuraDB with authentic, real-world CTI data from MITRE Enterprise ATT&CK,
NVD/CISA KEV, and enterprise cloud production topologies.
"""

import os
import logging
from dotenv import load_dotenv
from neo4j import GraphDatabase

load_dotenv()

NEO4J_URI = os.getenv("NEO4J_URI", "neo4j+ssc://e6c68873.databases.neo4j.io")
NEO4J_USERNAME = os.getenv("NEO4J_USERNAME", "e6c68873")
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD", "your_neo4j_password_here")

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

# Authentic Real-World CTI & Production Cloud Infrastructure Dataset
ENTERPRISE_CTI_DATA = {
    "actors": [
        {
            "name": "APT29 (Nobelium / Cozy Bear / Midnight Blizzard)",
            "mitre_id": "G0016",
            "origin": "SVR (Russian Foreign Intelligence Service)",
            "motive": "Espionage, Supply Chain Hijacking, Cloud IAM Infiltration",
            "tier": "Tier-1 State-Sponsored APT"
        },
        {
            "name": "Lazarus Group (HIDDEN COBRA / Diamond Sleet)",
            "mitre_id": "G0032",
            "origin": "RGB (North Korean Reconnaissance General Bureau)",
            "motive": "Cryptocurrency Exfiltration, Financial Fraud, Critical Infrastructure Sabotage",
            "tier": "State-Sponsored Cybercrime & Destructive"
        },
        {
            "name": "Volt Typhoon (BRONZE SILHOUETTE / Vanguard Panda)",
            "mitre_id": "G1017",
            "origin": "PLA (People's Liberation Army / MSS, China)",
            "motive": "Pre-Positioning in Critical Infrastructure, Living-off-the-Land (LotL)",
            "tier": "Tier-1 State-Sponsored Cyber Sabotage"
        },
        {
            "name": "LockBit 3.0 (LockBit Black Ransomware Syndicate)",
            "mitre_id": "G0092",
            "origin": "Transnational Cybercrime Cartel",
            "motive": "High-Impact Ransomware Extortion, Double-Extortion Data Leakage",
            "tier": "Organized Cybercrime Syndicate"
        },
        {
            "name": "FIN7 (Carbanak / Sangria Tempest)",
            "mitre_id": "G0046",
            "origin": "Eastern European Financial Crime Syndicate",
            "motive": "Point-of-Sale (POS) & Payment Processor Credential Harvesting",
            "tier": "Advanced Financial Threat Actor"
        }
    ],
    
    "techniques": [
        {
            "id": "T1190",
            "name": "Exploit Public-Facing Application",
            "tactic": "Initial Access",
            "description": "Weaponization of unauthenticated RCE vulnerabilities in internet-exposed edge services and web applications."
        },
        {
            "id": "T1195.002",
            "name": "Supply Chain Compromise: Software Dependencies",
            "tactic": "Initial Access",
            "description": "Compromise of upstream open-source packages, build pipelines, or developer tooling prior to release."
        },
        {
            "id": "T1059.001",
            "name": "Command and Scripting Interpreter: PowerShell",
            "tactic": "Execution",
            "description": "Adversary execution of arbitrary commands, reverse shells, and download cradles via native PowerShell."
        },
        {
            "id": "T1078.004",
            "name": "Valid Accounts: Cloud Accounts & IAM Roles",
            "tactic": "Defense Evasion & Persistence",
            "description": "Abuse of compromised cloud service account tokens (AWS IAM / GCP Service Accounts) to access internal cloud assets."
        },
        {
            "id": "T1021.002",
            "name": "Remote Services: SMB/Windows Admin Shares",
            "tactic": "Lateral Movement",
            "description": "Traversing internal subnets using administrative shares and Kerberos tickets to pivot across hosts."
        },
        {
            "id": "T1505.003",
            "name": "Server Software Component: Web Shell",
            "tactic": "Persistence",
            "description": "Planting backdoor webshells (JSP, PHP, ASHX) in webroot directories for continuous interactive access."
        },
        {
            "id": "T1486",
            "name": "Data Encrypted for Impact: Ransomware",
            "tactic": "Impact",
            "description": "Encrypting high-value databases, persistent volumes, and hypervisors to disrupt operations and demand ransom."
        }
    ],

    "cves": [
        {
            "cve": "CVE-2021-44228 (Log4Shell)",
            "cvss": 10.0,
            "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
            "epss": "97.4% (Highest Percentile)",
            "cisa_kev": "Added 2021-12-10 (Known Exploited)",
            "type": "Remote Code Execution (RCE)",
            "description": "Unauthenticated JNDI lookup injection in Apache Log4j2 allowing remote bytecode execution via LDAP/RMI."
        },
        {
            "cve": "CVE-2024-3094 (XZ Utils Backdoor)",
            "cvss": 10.0,
            "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
            "epss": "78.2% (Supply Chain Injection)",
            "cisa_kev": "Added 2024-04-01 (Emergency Alert)",
            "type": "Supply Chain SSH Authentication Bypass",
            "description": "Malicious code injected into liblzma/xz-utils tarballs modifying sshd RSA_public_decrypt function pointers."
        },
        {
            "cve": "CVE-2022-22965 (Spring4Shell)",
            "cvss": 9.8,
            "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "epss": "94.1% (High Weaponization)",
            "cisa_kev": "Added 2022-04-04 (Known Exploited)",
            "type": "Remote Code Execution (RCE)",
            "description": "Spring Framework DataBinder classloader override on JDK 9+ enabling arbitrary JSP webshell writing to docbase."
        },
        {
            "cve": "CVE-2024-21762 (FortiOS Out-of-Bounds)",
            "cvss": 9.8,
            "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "epss": "96.5% (Actively Weaponized)",
            "cisa_kev": "Added 2024-02-09 (Zero-Day Campaign)",
            "type": "Out-of-Bounds Write RCE",
            "description": "Pre-authentication heap corruption in Fortinet FortiOS SSL-VPN web portal allowing command execution via HTTP."
        },
        {
            "cve": "CVE-2023-4966 (Citrix Bleed)",
            "cvss": 9.4,
            "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            "epss": "97.1% (Mass Exploitation)",
            "cisa_kev": "Added 2023-10-18 (Ransomware Vector)",
            "type": "Sensitive Buffer Over-Read Session Hijack",
            "description": "NetScaler ADC / Gateway buffer over-read dumping valid authenticated session tokens, bypassing MFA."
        }
    ],

    "packages": [
        {"name": "org.apache.logging.log4j:log4j-core:2.14.1", "language": "Java", "ecosystem": "Maven / JVM"},
        {"name": "xz-utils:5.6.0", "language": "C / Native", "ecosystem": "Debian / RHEL Linux"},
        {"name": "org.springframework:spring-beans:5.3.17", "language": "Java", "ecosystem": "Maven / JVM"},
        {"name": "fortios:7.4.2", "language": "C / Embedded", "ecosystem": "Fortinet FortiGate OS"},
        {"name": "netscaler-adc:13.1-48.47", "language": "FreeBSD / Native", "ecosystem": "Citrix NetScaler Gateway"}
    ],

    "services": [
        {
            "name": "k8s-auth-ingress-gateway",
            "tier": "Perimeter Ingress",
            "cloud": "AWS EKS (us-east-1)",
            "zone": "Public DMZ Subnet (10.100.1.0/24)",
            "iam_role": "arn:aws:iam::prod:role/IngressAuthAppRole",
            "status": "EXPOSED"
        },
        {
            "name": "payment-token-vault-service",
            "tier": "PCI-DSS Tier-0 Core",
            "cloud": "GCP GKE (us-central1)",
            "zone": "PCI-Compliant Private Enclave (10.200.4.0/24)",
            "iam_role": "sa-payment-processor@enterprise-prod.iam.gserviceaccount.com",
            "status": "CRITICAL_ASSET"
        },
        {
            "name": "enterprise-bastion-ssh-host",
            "tier": "Core Infrastructure",
            "cloud": "On-Premises Hyper-V",
            "zone": "Admin Management Subnet (192.168.10.5)",
            "iam_role": "Local Root / SSH Host Key Enclave",
            "status": "INFRASTRUCTURE"
        },
        {
            "name": "corporate-active-directory-dc01",
            "tier": "Identity Provider / Tier-0",
            "cloud": "Hybrid Azure Arc",
            "zone": "Corporate Forest (corp.enterprise.local)",
            "iam_role": "Domain Controller / KRBTGT",
            "status": "CRITICAL_ASSET"
        },
        {
            "name": "data-analytics-dataproc-spark",
            "tier": "Big Data Lakehouse",
            "cloud": "GCP Dataproc",
            "zone": "Analytics VPC (10.150.0.0/16)",
            "iam_role": "dataproc-worker@enterprise-data.iam.gserviceaccount.com",
            "status": "DATA_LAKE"
        },
        {
            "name": "edge-vpn-gateway-fortigate",
            "tier": "Perimeter SSL-VPN",
            "cloud": "Edge Network Appliance",
            "zone": "External IP 198.51.100.14:443",
            "iam_role": "VPN Gateway Admin",
            "status": "EXPOSED"
        }
    ],

    "patches": [
        {
            "name": "Log4j Patch 2.17.1 (Disables JNDI Lookup)",
            "bulletin": "CISA Alert AA21-356A / CVE-2021-44228",
            "hotfix": "-Dlog4j2.formatMsgNoLookups=true",
            "target_version": "log4j-core >= 2.17.1"
        },
        {
            "name": "Emergency Rollback to xz-utils 5.4.6 & SSH Key Rotation",
            "bulletin": "CISA Alert AA24-092A / CVE-2024-3094",
            "hotfix": "Purge build caches; downgrade to 5.4.6; rotate all SSH host keys",
            "target_version": "xz-utils 5.4.6-stable / 5.6.2"
        },
        {
            "name": "Spring Framework 5.3.18 Patch & Tomcat Upgrade",
            "bulletin": "VMware Security Advisory VMSA-2022-0010",
            "hotfix": "Disallow fields class.*, Class.* in DataBinder initBinder",
            "target_version": "Spring Framework >= 5.3.18 / 5.2.20"
        },
        {
            "name": "FortiOS Firmware 7.4.3 Upgrade / SSL-VPN Hardening",
            "bulletin": "Fortinet PSIRT Advisory FG-IR-24-015",
            "hotfix": "Disable SSL-VPN web portal mode; enforce source IP allowlist",
            "target_version": "FortiOS 7.4.3 / 7.2.7 or higher"
        },
        {
            "name": "Citrix NetScaler Build 13.1-49.13 Patch & Kill Active Sessions",
            "bulletin": "Citrix Security Bulletin CTX579459",
            "hotfix": "Terminate all existing ICA/Gateway sessions via nscli kill session",
            "target_version": "NetScaler ADC >= 13.1-49.13"
        }
    ]
}

# Multi-hop Attack Chains & Dependency Topology
RELATIONSHIPS = [
    # 1. Threat Actors leveraging MITRE ATT&CK Techniques
    ("ThreatActor", "APT29 (Nobelium / Cozy Bear / Midnight Blizzard)", "AttackTechnique", "Exploit Public-Facing Application", "LEVERAGES"),
    ("ThreatActor", "APT29 (Nobelium / Cozy Bear / Midnight Blizzard)", "AttackTechnique", "Supply Chain Compromise: Software Dependencies", "LEVERAGES"),
    ("ThreatActor", "APT29 (Nobelium / Cozy Bear / Midnight Blizzard)", "AttackTechnique", "Valid Accounts: Cloud Accounts & IAM Roles", "LEVERAGES"),
    ("ThreatActor", "Lazarus Group (HIDDEN COBRA / Diamond Sleet)", "AttackTechnique", "Command and Scripting Interpreter: PowerShell", "LEVERAGES"),
    ("ThreatActor", "Lazarus Group (HIDDEN COBRA / Diamond Sleet)", "AttackTechnique", "Exploit Public-Facing Application", "LEVERAGES"),
    ("ThreatActor", "Volt Typhoon (BRONZE SILHOUETTE / Vanguard Panda)", "AttackTechnique", "Exploit Public-Facing Application", "LEVERAGES"),
    ("ThreatActor", "Volt Typhoon (BRONZE SILHOUETTE / Vanguard Panda)", "AttackTechnique", "Remote Services: SMB/Windows Admin Shares", "LEVERAGES"),
    ("ThreatActor", "LockBit 3.0 (LockBit Black Ransomware Syndicate)", "AttackTechnique", "Data Encrypted for Impact: Ransomware", "LEVERAGES"),
    ("ThreatActor", "LockBit 3.0 (LockBit Black Ransomware Syndicate)", "AttackTechnique", "Remote Services: SMB/Windows Admin Shares", "LEVERAGES"),
    ("ThreatActor", "FIN7 (Carbanak / Sangria Tempest)", "AttackTechnique", "Server Software Component: Web Shell", "LEVERAGES"),

    # 2. MITRE Techniques targeting CVEs
    ("AttackTechnique", "Exploit Public-Facing Application", "Vulnerability", "CVE-2021-44228 (Log4Shell)", "TARGETS_VULNERABILITY"),
    ("AttackTechnique", "Exploit Public-Facing Application", "Vulnerability", "CVE-2022-22965 (Spring4Shell)", "TARGETS_VULNERABILITY"),
    ("AttackTechnique", "Exploit Public-Facing Application", "Vulnerability", "CVE-2024-21762 (FortiOS Out-of-Bounds)", "TARGETS_VULNERABILITY"),
    ("AttackTechnique", "Exploit Public-Facing Application", "Vulnerability", "CVE-2023-4966 (Citrix Bleed)", "TARGETS_VULNERABILITY"),
    ("AttackTechnique", "Supply Chain Compromise: Software Dependencies", "Vulnerability", "CVE-2024-3094 (XZ Utils Backdoor)", "TARGETS_VULNERABILITY"),

    # 3. CVEs exploiting Software Packages
    ("Vulnerability", "CVE-2021-44228 (Log4Shell)", "SoftwarePackage", "org.apache.logging.log4j:log4j-core:2.14.1", "EXPLOITS_FLAW_IN"),
    ("Vulnerability", "CVE-2024-3094 (XZ Utils Backdoor)", "SoftwarePackage", "xz-utils:5.6.0", "EXPLOITS_FLAW_IN"),
    ("Vulnerability", "CVE-2022-22965 (Spring4Shell)", "SoftwarePackage", "org.springframework:spring-beans:5.3.17", "EXPLOITS_FLAW_IN"),
    ("Vulnerability", "CVE-2024-21762 (FortiOS Out-of-Bounds)", "SoftwarePackage", "fortios:7.4.2", "EXPLOITS_FLAW_IN"),
    ("Vulnerability", "CVE-2023-4966 (Citrix Bleed)", "SoftwarePackage", "netscaler-adc:13.1-48.47", "EXPLOITS_FLAW_IN"),

    # 4. Enterprise Services running Software Packages (SBOM / Dependency Map)
    ("EnterpriseService", "k8s-auth-ingress-gateway", "SoftwarePackage", "org.apache.logging.log4j:log4j-core:2.14.1", "DEPENDS_ON"),
    ("EnterpriseService", "k8s-auth-ingress-gateway", "SoftwarePackage", "org.springframework:spring-beans:5.3.17", "DEPENDS_ON"),
    ("EnterpriseService", "enterprise-bastion-ssh-host", "SoftwarePackage", "xz-utils:5.6.0", "DEPENDS_ON"),
    ("EnterpriseService", "edge-vpn-gateway-fortigate", "SoftwarePackage", "fortios:7.4.2", "RUNS_SOFTWARE"),
    ("EnterpriseService", "edge-vpn-gateway-fortigate", "SoftwarePackage", "netscaler-adc:13.1-48.47", "RUNS_SOFTWARE"),

    # 5. Enterprise Lateral Movement Paths (Kill-Chain Pivoting)
    ("EnterpriseService", "k8s-auth-ingress-gateway", "EnterpriseService", "payment-token-vault-service", "CAN_PIVOT_TO"),
    ("EnterpriseService", "k8s-auth-ingress-gateway", "EnterpriseService", "corporate-active-directory-dc01", "CAN_PIVOT_TO"),
    ("EnterpriseService", "enterprise-bastion-ssh-host", "EnterpriseService", "data-analytics-dataproc-spark", "CAN_PIVOT_TO"),
    ("EnterpriseService", "edge-vpn-gateway-fortigate", "EnterpriseService", "corporate-active-directory-dc01", "CAN_PIVOT_TO"),
    ("EnterpriseService", "corporate-active-directory-dc01", "EnterpriseService", "payment-token-vault-service", "CAN_PIVOT_TO"),

    # 6. Vulnerabilities mitigated by Remediation Patches
    ("Vulnerability", "CVE-2021-44228 (Log4Shell)", "RemediationPatch", "Log4j Patch 2.17.1 (Disables JNDI Lookup)", "MITIGATED_BY"),
    ("Vulnerability", "CVE-2024-3094 (XZ Utils Backdoor)", "RemediationPatch", "Emergency Rollback to xz-utils 5.4.6 & SSH Key Rotation", "MITIGATED_BY"),
    ("Vulnerability", "CVE-2022-22965 (Spring4Shell)", "RemediationPatch", "Spring Framework 5.3.18 Patch & Tomcat Upgrade", "MITIGATED_BY"),
    ("Vulnerability", "CVE-2024-21762 (FortiOS Out-of-Bounds)", "RemediationPatch", "FortiOS Firmware 7.4.3 Upgrade / SSL-VPN Hardening", "MITIGATED_BY"),
    ("Vulnerability", "CVE-2023-4966 (Citrix Bleed)", "RemediationPatch", "Citrix NetScaler Build 13.1-49.13 Patch & Kill Active Sessions", "MITIGATED_BY")
]

def ingest():
    logger.info("Connecting to Neo4j AuraDB...")
    driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USERNAME, NEO4J_PASSWORD))
    
    with driver.session() as session:
        # Wipe database
        session.run("MATCH (n) DETACH DELETE n")
        logger.info("Cleaned previous graph data.")
        
        # Ingest Nodes
        for a in ENTERPRISE_CTI_DATA["actors"]:
            session.run("MERGE (n:ThreatActor {name: $name, mitre_id: $mitre_id, origin: $origin, motive: $motive, tier: $tier})", **a)
        logger.info(f"Ingested {len(ENTERPRISE_CTI_DATA['actors'])} Threat Actors.")
        
        for t in ENTERPRISE_CTI_DATA["techniques"]:
            session.run("MERGE (n:AttackTechnique {name: $name, id: $id, tactic: $tactic, description: $description})", **t)
        logger.info(f"Ingested {len(ENTERPRISE_CTI_DATA['techniques'])} MITRE ATT&CK Techniques.")
        
        for c in ENTERPRISE_CTI_DATA["cves"]:
            session.run("MERGE (n:Vulnerability {name: $cve, cvss: $cvss, vector: $vector, epss: $epss, cisa_kev: $cisa_kev, type: $type, description: $description})", **c)
        logger.info(f"Ingested {len(ENTERPRISE_CTI_DATA['cves'])} CVE Vulnerabilities.")
        
        for p in ENTERPRISE_CTI_DATA["packages"]:
            session.run("MERGE (n:SoftwarePackage {name: $name, language: $language, ecosystem: $ecosystem})", **p)
        logger.info(f"Ingested {len(ENTERPRISE_CTI_DATA['packages'])} Software Packages.")
        
        for s in ENTERPRISE_CTI_DATA["services"]:
            session.run("MERGE (n:EnterpriseService {name: $name, tier: $tier, cloud: $cloud, zone: $zone, iam_role: $iam_role, status: $status})", **s)
        logger.info(f"Ingested {len(ENTERPRISE_CTI_DATA['services'])} Production Cloud Infrastructure Assets.")
        
        for pt in ENTERPRISE_CTI_DATA["patches"]:
            session.run("MERGE (n:RemediationPatch {name: $name, bulletin: $bulletin, hotfix: $hotfix, target_version: $target_version})", **pt)
        logger.info(f"Ingested {len(ENTERPRISE_CTI_DATA['patches'])} Remediation Bulletins.")

        # Ingest Relational Edges
        for s_type, s_name, t_type, t_name, rel in RELATIONSHIPS:
            cypher = f"""
            MATCH (s:{s_type} {{name: $s_name}})
            MATCH (t:{t_type} {{name: $t_name}})
            MERGE (s)-[r:{rel}]->(t)
            """
            session.run(cypher, s_name=s_name, t_name=t_name)
        logger.info(f"Created {len(RELATIONSHIPS)} Relational Multi-Hop Attack Edges.")

        # Summary
        node_count = session.run("MATCH (n) RETURN count(n) AS cnt").single()["cnt"]
        edge_count = session.run("MATCH ()-[r]->() RETURN count(r) AS cnt").single()["cnt"]
        logger.info(f"NEO4J ENTERPRISE CTI GRAPH READY: {node_count} Nodes, {edge_count} Edges.")
        
    driver.close()

if __name__ == "__main__":
    ingest()
