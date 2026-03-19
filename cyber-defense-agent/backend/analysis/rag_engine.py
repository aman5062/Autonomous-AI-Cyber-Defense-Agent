import logging
from backend.intelligence.threat_db import ThreatDB
from backend.analysis.knowledge_graph import KnowledgeGraph

logger = logging.getLogger(__name__)

_threat_db = ThreatDB()
_kg = KnowledgeGraph()


def get_enriched_context(attack_type: str) -> dict:
    """
    Returns CVE context and graph mitigations for a given attack type.
    Used to enrich LLM prompts.
    """
    cve_context = _threat_db.get_context_for_attack(attack_type)

    graph_mits = _kg.get_mitigations(attack_type)
    graph_text = "\n".join(
        f"- {m['description']} (targets {m['targets_vulnerability']})"
        for m in graph_mits
    ) or "No graph mitigations available."

    related = _kg.get_related_attacks(attack_type)
    chain = _kg.get_attack_chain(attack_type)

    return {
        "cve_context": cve_context,
        "graph_mitigations": graph_text,
        "related_attacks": related,
        "attack_chain": chain,
    }
