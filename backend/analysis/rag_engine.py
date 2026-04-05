import logging
from typing import Optional

logger = logging.getLogger(__name__)

# Lazy singletons — not instantiated at import time so Qdrant/NetworkX
# failures during startup don't crash the whole backend.
_threat_db = None
_kg = None


def _get_threat_db():
    global _threat_db
    if _threat_db is None:
        try:
            from backend.intelligence.threat_db import ThreatDB
            _threat_db = ThreatDB()
        except Exception as e:
            logger.warning("ThreatDB unavailable: %s", e)
    return _threat_db


def _get_kg():
    global _kg
    if _kg is None:
        try:
            from backend.analysis.knowledge_graph import KnowledgeGraph
            _kg = KnowledgeGraph()
        except Exception as e:
            logger.warning("KnowledgeGraph unavailable: %s", e)
    return _kg


def get_enriched_context(attack_type: str) -> dict:
    """Returns CVE context and graph mitigations for a given attack type."""
    cve_context = "No CVE context available."
    graph_text = "No graph mitigations available."
    related = []
    chain = []

    threat_db = _get_threat_db()
    if threat_db:
        try:
            cve_context = threat_db.get_context_for_attack(attack_type)
        except Exception as e:
            logger.warning("ThreatDB query failed: %s", e)

    kg = _get_kg()
    if kg:
        try:
            graph_mits = kg.get_mitigations(attack_type)
            graph_text = "\n".join(
                f"- {m['description']} (targets {m['targets_vulnerability']})"
                for m in graph_mits
            ) or "No graph mitigations available."
            related = kg.get_related_attacks(attack_type)
            chain = kg.get_attack_chain(attack_type)
        except Exception as e:
            logger.warning("KnowledgeGraph query failed: %s", e)

    return {
        "cve_context": cve_context,
        "graph_mitigations": graph_text,
        "related_attacks": related,
        "attack_chain": chain,
    }
