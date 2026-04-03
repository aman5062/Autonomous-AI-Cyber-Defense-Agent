import logging
import networkx as nx
from typing import List, Dict

logger = logging.getLogger(__name__)


class KnowledgeGraph:
    """
    Attack relationship graph using NetworkX.
    Nodes: AttackType, Vulnerability, Software, Mitigation, AttackStage
    Edges: exploits, affects, mitigates, leads_to
    """

    def __init__(self):
        self.G = nx.DiGraph()
        self._build_default_graph()

    def _build_default_graph(self):
        G = self.G
        # Attack types
        for a in ["SQL_INJECTION", "XSS", "PATH_TRAVERSAL", "BRUTE_FORCE",
                  "COMMAND_INJECTION", "DDOS", "CSRF", "BOT_SCAN"]:
            G.add_node(a, type="AttackType")

        # Vulnerabilities
        vulns = {
            "CWE-89": "SQL Injection",
            "CWE-79": "Cross-site Scripting",
            "CWE-22": "Path Traversal",
            "CWE-307": "Improper Restriction of Auth Attempts",
            "CWE-78": "OS Command Injection",
            "CWE-352": "CSRF",
        }
        for cwe, desc in vulns.items():
            G.add_node(cwe, type="Vulnerability", description=desc)

        # Software
        for sw in ["MySQL", "PostgreSQL", "Apache", "NGINX", "PHP", "Python/Flask", "Node.js"]:
            G.add_node(sw, type="Software")

        # Mitigations
        mitigations = {
            "M_PARAMETERIZED_QUERIES": "Use parameterized queries / ORM",
            "M_INPUT_VALIDATION": "Validate and sanitize all user input",
            "M_CSP": "Implement Content Security Policy",
            "M_RATE_LIMITING": "Apply rate limiting",
            "M_MFA": "Enable multi-factor authentication",
            "M_WAF": "Deploy Web Application Firewall",
            "M_LEAST_PRIVILEGE": "Apply principle of least privilege",
        }
        for mid, desc in mitigations.items():
            G.add_node(mid, type="Mitigation", description=desc)

        # Attack stages (kill chain)
        for stage in ["Reconnaissance", "Scanning", "Exploitation", "Persistence", "Exfiltration"]:
            G.add_node(stage, type="AttackStage")

        # Edges: attack exploits vulnerability
        G.add_edge("SQL_INJECTION", "CWE-89", relation="exploits")
        G.add_edge("XSS", "CWE-79", relation="exploits")
        G.add_edge("PATH_TRAVERSAL", "CWE-22", relation="exploits")
        G.add_edge("BRUTE_FORCE", "CWE-307", relation="exploits")
        G.add_edge("COMMAND_INJECTION", "CWE-78", relation="exploits")
        G.add_edge("CSRF", "CWE-352", relation="exploits")

        # Vulnerability affects software
        G.add_edge("CWE-89", "MySQL", relation="affects")
        G.add_edge("CWE-89", "PostgreSQL", relation="affects")
        G.add_edge("CWE-79", "PHP", relation="affects")
        G.add_edge("CWE-22", "Apache", relation="affects")
        G.add_edge("CWE-22", "NGINX", relation="affects")

        # Mitigations
        G.add_edge("M_PARAMETERIZED_QUERIES", "CWE-89", relation="mitigates")
        G.add_edge("M_INPUT_VALIDATION", "CWE-79", relation="mitigates")
        G.add_edge("M_INPUT_VALIDATION", "CWE-89", relation="mitigates")
        G.add_edge("M_CSP", "CWE-79", relation="mitigates")
        G.add_edge("M_RATE_LIMITING", "CWE-307", relation="mitigates")
        G.add_edge("M_MFA", "CWE-307", relation="mitigates")
        G.add_edge("M_WAF", "CWE-79", relation="mitigates")
        G.add_edge("M_WAF", "CWE-89", relation="mitigates")
        G.add_edge("M_LEAST_PRIVILEGE", "CWE-78", relation="mitigates")

        # Kill chain
        for a, b in [("Reconnaissance", "Scanning"), ("Scanning", "Exploitation"),
                     ("Exploitation", "Persistence"), ("Persistence", "Exfiltration")]:
            G.add_edge(a, b, relation="leads_to")

        G.add_edge("BOT_SCAN", "Reconnaissance", relation="leads_to")
        G.add_edge("SQL_INJECTION", "Exploitation", relation="leads_to")
        G.add_edge("BRUTE_FORCE", "Exploitation", relation="leads_to")

    def get_mitigations(self, attack_type: str) -> List[Dict]:
        """Return mitigation nodes for a given attack type."""
        results = []
        try:
            # Find vulnerability node
            vuln_nodes = [
                v for u, v, d in self.G.edges(data=True)
                if u == attack_type and d.get("relation") == "exploits"
            ]
            for vuln in vuln_nodes:
                mits = [
                    u for u, v, d in self.G.edges(data=True)
                    if v == vuln and d.get("relation") == "mitigates"
                ]
                for m in mits:
                    results.append({
                        "mitigation_id": m,
                        "description": self.G.nodes[m].get("description", m),
                        "targets_vulnerability": vuln,
                    })
        except Exception as e:
            logger.error(f"Graph query error: {e}")
        return results

    def get_attack_chain(self, attack_type: str) -> List[str]:
        """Return likely kill chain stages for an attack."""
        try:
            stages = []
            for _, v, d in self.G.edges(data=True):
                if _ == attack_type and d.get("relation") == "leads_to":
                    stages.append(v)
                    # Follow chain one more level
                    for _, v2, d2 in self.G.edges(data=True):
                        if _ == v and d2.get("relation") == "leads_to":
                            stages.append(v2)
            return list(dict.fromkeys(stages))
        except Exception:
            return []

    def get_related_attacks(self, attack_type: str) -> List[str]:
        """Return attacks that share the same vulnerability."""
        related = set()
        try:
            vulns = [
                v for u, v, d in self.G.edges(data=True)
                if u == attack_type and d.get("relation") == "exploits"
            ]
            for vuln in vulns:
                for u, v, d in self.G.edges(data=True):
                    if v == vuln and d.get("relation") == "exploits" and u != attack_type:
                        related.add(u)
        except Exception:
            pass
        return list(related)
