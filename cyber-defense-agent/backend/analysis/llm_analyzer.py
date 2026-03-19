import json
import logging
import asyncio
import aiohttp
from backend.config import settings
from backend.analysis.prompts import get_prompt
from backend.analysis.rag_engine import get_enriched_context

logger = logging.getLogger(__name__)

_FALLBACK = {
    "explanation": "Attack detected. LLM analysis unavailable.",
    "impact": "Potential security breach.",
    "mitigation": ["IP has been blocked automatically.", "Review logs for further activity."],
    "code_fix": {},
    "references": [],
}


class LLMAnalyzer:
    def __init__(self):
        self.base_url = settings.OLLAMA_BASE_URL
        self.model = settings.OLLAMA_MODEL
        self.temperature = settings.OLLAMA_TEMPERATURE
        self.max_tokens = settings.OLLAMA_MAX_TOKENS
        self.timeout = settings.OLLAMA_TIMEOUT

    async def analyze_attack(self, attack_info: dict, request_data: dict) -> dict:
        attack_type = attack_info.get("attack_type", "UNKNOWN")

        # Get RAG context
        context = get_enriched_context(attack_type)

        prompt = get_prompt(
            attack_type=attack_type,
            severity=attack_info.get("severity", "UNKNOWN"),
            confidence=attack_info.get("confidence", 0),
            pattern=attack_info.get("pattern", "N/A"),
            ip=request_data.get("ip", "unknown"),
            method=request_data.get("method", "GET"),
            path=request_data.get("path", "/"),
            status=request_data.get("status", 200),
            user_agent=request_data.get("user_agent", "unknown"),
            attempt_count=attack_info.get("attempt_count", 0),
            time_window=attack_info.get("time_window", 60),
            details=attack_info.get("details", ""),
            cve_context=context["cve_context"],
            graph_mitigations=context["graph_mitigations"],
        )

        raw_response = await self._call_ollama(prompt)
        parsed = self._parse_json(raw_response)

        # Enrich with graph data
        parsed["related_attacks"] = context.get("related_attacks", [])
        parsed["attack_chain"] = context.get("attack_chain", [])

        return parsed

    async def _call_ollama(self, prompt: str) -> str:
        url = f"{self.base_url}/api/generate"
        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": self.temperature,
                "num_predict": self.max_tokens,
            },
        }
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    url, json=payload,
                    timeout=aiohttp.ClientTimeout(total=self.timeout)
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        return data.get("response", "")
                    else:
                        logger.warning(f"Ollama returned {resp.status}")
                        return ""
        except asyncio.TimeoutError:
            logger.warning("Ollama request timed out.")
            return ""
        except Exception as e:
            logger.error(f"Ollama call failed: {e}")
            return ""

    def _parse_json(self, text: str) -> dict:
        if not text:
            return _FALLBACK.copy()
        start = text.find("{")
        end = text.rfind("}") + 1
        if start == -1 or end == 0:
            return {**_FALLBACK, "explanation": text[:500]}
        try:
            return json.loads(text[start:end])
        except json.JSONDecodeError:
            try:
                cleaned = text[start:end].replace("\n", " ").replace("\t", " ")
                return json.loads(cleaned)
            except Exception:
                return {**_FALLBACK, "explanation": text[:500]}
