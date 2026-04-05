import logging
import asyncio
import aiohttp
from backend.config import settings
from backend.intelligence.embeddings import embed_texts

logger = logging.getLogger(__name__)

KEYWORDS = [
    "SQL injection", "XSS cross-site scripting", "path traversal",
    "brute force authentication", "command injection", "CSRF",
    "remote code execution", "buffer overflow", "NGINX Apache",
]


class CVEFetcher:
    def __init__(self):
        self.api_url = settings.NVD_API_URL
        self.api_key = settings.NVD_API_KEY

    async def fetch_and_store(self):
        """Fetch CVEs from NVD and store in Qdrant."""
        try:
            from qdrant_client import QdrantClient
            from qdrant_client.models import Distance, VectorParams, PointStruct

            client = QdrantClient(host=settings.QDRANT_HOST, port=settings.QDRANT_PORT)

            # Create collection if not exists
            collections = [c.name for c in client.get_collections().collections]
            if settings.QDRANT_COLLECTION not in collections:
                client.create_collection(
                    collection_name=settings.QDRANT_COLLECTION,
                    vectors_config=VectorParams(size=384, distance=Distance.COSINE),
                )
                logger.info(f"Created Qdrant collection: {settings.QDRANT_COLLECTION}")

            all_docs = []
            for keyword in KEYWORDS:
                docs = await self._fetch_cves_for_keyword(keyword)
                all_docs.extend(docs)
                await asyncio.sleep(0.5)  # NVD rate limit

            if not all_docs:
                logger.warning("No CVE documents fetched.")
                return

            # Embed and store
            texts = [d["text"] for d in all_docs]
            vectors = embed_texts(texts)

            points = [
                PointStruct(id=i, vector=vectors[i], payload=all_docs[i])
                for i in range(len(all_docs))
                if vectors[i]
            ]

            client.upsert(collection_name=settings.QDRANT_COLLECTION, points=points)
            logger.info(f"Stored {len(points)} CVE documents in Qdrant.")

        except Exception as e:
            logger.error(f"CVE fetch/store failed: {e}")

    async def _fetch_cves_for_keyword(self, keyword: str) -> list:
        headers = {}
        if self.api_key:
            headers["apiKey"] = self.api_key

        params = {"keywordSearch": keyword, "resultsPerPage": 20}

        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(self.api_url, params=params, headers=headers, timeout=aiohttp.ClientTimeout(total=30)) as resp:
                    if resp.status != 200:
                        logger.warning(f"NVD API returned {resp.status} for '{keyword}'")
                        return []
                    data = await resp.json()
        except Exception as e:
            logger.warning(f"NVD fetch error for '{keyword}': {e}")
            return []

        docs = []
        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            cve_id = cve.get("id", "")
            descriptions = cve.get("descriptions", [])
            desc = next((d["value"] for d in descriptions if d.get("lang") == "en"), "")
            if not desc:
                continue

            metrics = cve.get("metrics", {})
            cvss_score = None
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                if key in metrics and metrics[key]:
                    cvss_score = metrics[key][0].get("cvssData", {}).get("baseScore")
                    break

            docs.append({
                "cve_id": cve_id,
                "text": f"{cve_id}: {desc}",
                "description": desc,
                "cvss_score": cvss_score,
                "keyword": keyword,
            })

        return docs
