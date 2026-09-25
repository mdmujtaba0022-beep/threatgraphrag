"""
Automated Unit & Integration Test Suite for:
1. Graph-Theoretic Chokepoint & Articulation Point Engine
2. Bayesian Cumulative Path Exploitability & Time-to-Compromise (TTC)
3. Active Countermeasure Simulation & Defense Playbook Generation
4. FastAPI Programmatic REST Endpoints
"""
import sys
import unittest
from src.graph_engine import (
    compute_graph_chokepoints,
    compute_quantitative_path_risk,
    simulate_countermeasure
)

class TestChokepointsAndCountermeasures(unittest.TestCase):

    def setUp(self):
        # Realistic multi-hop attack graph topology
        self.nodes = {
            "Volt Typhoon": "ThreatActor",
            "CVE-2024-21762": "Vulnerability",
            "k8s-auth-ingress-gateway": "EnterpriseService",
            "spark-analytics-core": "EnterpriseService",
            "customer-data-vault": "EnterpriseService"
        }
        self.edges = [
            {"from": "Volt Typhoon", "to": "CVE-2024-21762", "label": "EXPLOITS"},
            {"from": "CVE-2024-21762", "to": "k8s-auth-ingress-gateway", "label": "TARGETS"},
            {"from": "k8s-auth-ingress-gateway", "to": "spark-analytics-core", "label": "CAN_PIVOT_TO"},
            {"from": "spark-analytics-core", "to": "customer-data-vault", "label": "LATERAL_MOVEMENT"}
        ]
        self.meta = {
            "CVE-2024-21762": {"props": {"cvss": "9.8", "epss": "95.4%"}},
            "k8s-auth-ingress-gateway": {"props": {"zone": "DMZ", "tier": "Perimeter"}},
            "customer-data-vault": {"props": {"zone": "Core", "tier": "Tier-0"}}
        }

    def test_articulation_point_detection(self):
        """Verify S-T cut-vertex algorithm accurately identifies single point of failure."""
        res = compute_graph_chokepoints(self.nodes, self.edges, self.meta)
        self.assertIsNotNone(res["primary_chokepoint"])
        self.assertEqual(res["primary_chokepoint"], "k8s-auth-ingress-gateway")
        self.assertTrue(res["is_perfect_cut"])
        self.assertGreaterEqual(res["total_active_paths"], 1)

    def test_quantitative_risk_and_ttc(self):
        """Verify Bayesian cumulative exploitability and TTC calculations."""
        res = compute_graph_chokepoints(self.nodes, self.edges, self.meta)
        risk = res["risk_modeling"]
        self.assertIn("cumulative_breach_probability", risk)
        self.assertGreater(risk["cumulative_breach_probability"], 50.0)
        self.assertIn("fastest_time_to_compromise", risk)
        self.assertIn("Minutes", risk["fastest_time_to_compromise"])
        self.assertEqual(risk["exploit_maturity_tier"], "WEAPONIZED_IN_THE_WILD")

    def test_countermeasure_simulation_patch(self):
        """Verify simulated patching severs the attack chain and generates playbooks."""
        sim = simulate_countermeasure(
            nodes_dict=self.nodes,
            edges=self.edges,
            nodes_meta=self.meta,
            target_entity="CVE-2024-21762",
            action_type="patch"
        )
        self.assertTrue(sim["kill_chain_broken"])
        self.assertGreater(sim["risk_delta"], 0)
        self.assertGreaterEqual(sim["severed_edges_count"], 1)
        self.assertIn("sigma_rule", sim["defense_artifacts"])
        self.assertIn("kubernetes_policy", sim["defense_artifacts"])
        self.assertIn("quarantine_script", sim["defense_artifacts"])
        self.assertIn("CVE-2024-21762", sim["defense_artifacts"]["sigma_rule"])

    def test_countermeasure_simulation_isolate(self):
        """Verify pod isolation severs ingress pivot and generates NetworkPolicy."""
        sim = simulate_countermeasure(
            nodes_dict=self.nodes,
            edges=self.edges,
            nodes_meta=self.meta,
            target_entity="k8s-auth-ingress-gateway",
            action_type="isolate"
        )
        self.assertTrue(sim["kill_chain_broken"])
        self.assertIn("NetworkPolicy", sim["defense_artifacts"]["kubernetes_policy"])

if __name__ == "__main__":
    unittest.main(verbosity=2)
