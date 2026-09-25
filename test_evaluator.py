import os
import sys
import dotenv
from neo4j import GraphDatabase

dotenv.load_dotenv()
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from src.repo_evaluator import (
    parse_github_url,
    fetch_repo_manifest,
    parse_generic_manifest,
    evaluate_repo_dependencies,
    generate_ai_repo_audit_report,
    PRESET_REPOSITORIES
)

def test_pipeline():
    driver = GraphDatabase.driver(
        os.getenv("NEO4J_URI"),
        auth=(os.getenv("NEO4J_USERNAME"), os.getenv("NEO4J_PASSWORD"))
    )
    
    print("[1] Testing Preset Repository Evaluation (Log4j)...")
    preset = PRESET_REPOSITORIES["apache/logging-log4j2 (Log4Shell CVE-2021-44228)"]
    pkgs = parse_generic_manifest(preset["manifest_type"], preset["simulated_manifest"])
    print(f"    Parsed {len(pkgs)} packages: {[p['name'] for p in pkgs]}")
    
    res = evaluate_repo_dependencies(driver, pkgs, "apache/logging-log4j2")
    print(f"    Security Posture: {res['security_posture']}")
    print(f"    Critical CVEs: {res['critical_vulnerabilities_detected']}")
    print(f"    Adversaries: {res['active_threat_actors']}")
    print(f"    Impacted Services: {res['impacted_enterprise_services']}")
    print(f"    Downstream Targets: {res['downstream_blast_radius_targets']}")
    print(f"    Vis Graph Nodes: {len(res['vis_graph']['nodes'])}")
    print(f"    Vis Graph Edges: {len(res['vis_graph']['edges'])}")
    
    assert any("APT29" in actor or "Lazarus" in actor or "Volt Typhoon" in actor for actor in res['active_threat_actors'])
    
    print("\n[2] Testing Safe Repository (psf/requests)...")
    safe_preset = PRESET_REPOSITORIES["psf/requests (Safe Open Source Library)"]
    safe_pkgs = parse_generic_manifest(safe_preset["manifest_type"], safe_preset["simulated_manifest"])
    safe_res = evaluate_repo_dependencies(driver, safe_pkgs, "psf/requests")
    print(f"    Security Posture: {safe_res['security_posture']}")
    print(f"    Critical CVEs: {safe_res['critical_vulnerabilities_detected']}")
    assert safe_res['security_posture'] == "SECURE / VERIFIED"
    
    driver.close()
    print("\nALL REPO EVALUATION TESTS PASSED SUCCESSFULLY!")

if __name__ == "__main__":
    test_pipeline()
