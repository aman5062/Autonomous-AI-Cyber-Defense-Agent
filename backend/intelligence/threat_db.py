import logging
from typing import List, Optional
from backend.config import settings
from backend.intelligence.embeddings import embed_text

logger = logging.getLogger(__name__)


class ThreatDB:
    """Query Qdrant for relevant threat intelligence."""

    def __init__(self):
        self._client = None

    def _get_client(self):
        if self._client is None:
            try:
                from qdrant_client import QdrantClient
                self._client = QdrantClient(host=settings.QDRANT_HOST, port=settings.QDRANT_PORT)
            except Exception as e:
                logger.warning(f"Qdrant not available: {e}")
        return self._client

    def search(self, query: str, limit: int = 5) -> List[dict]:
        client = self._get_client()
        if client is None:
            return []

        try:
            vector = embed_text(query)
            if not vector:
                return []

            results = client.search(
                collection_name=settings.QDRANT_COLLECTION,
                query_vector=vector,
                limit=limit,
            )
            return [
                {
                    "cve_id": r.payload.get("cve_id", ""),
                    "description": r.payload.get("description", ""),
                    "cvss_score": r.payload.get("cvss_score"),
                    "score": r.score,
                }
                for r in results
            ]
        except Exception as e:
            logger.warning(f"Qdrant search failed: {e}")
            return []

    def get_context_for_attack(self, attack_type: str) -> str:
        """Return formatted CVE context string for LLM prompt injection."""
        query_map = {
            "SQL_INJECTION": "SQL injection vulnerability database authentication bypass",
            "XSS": "cross-site scripting XSS vulnerability web application",
            "PATH_TRAVERSAL": "path traversal directory traversal file inclusion vulnerability",
            "BRUTE_FORCE": "brute force authentication password attack",
            "COMMAND_INJECTION": "command injection OS command execution vulnerability",
            "DDOS": "denial of service DDoS rate limiting flood attack",
        }
        query = query_map.get(attack_type, attack_type)
        results = self.search(query)

        if not results:
            return "No specific CVE context available."

        lines = []
        for r in results:
            score_str = f"CVSS: {r['cvss_score']}" if r.get("cvss_score") else ""
            lines.append(f"- {r['cve_id']} {score_str}: {r['description'][:200]}")

        return "\n".join(lines)
