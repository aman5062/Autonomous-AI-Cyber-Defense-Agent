"""
Bot / scanner user-agent detector.
"""

import logging
from typing import Dict

from backend.detection.patterns import BOT_USER_AGENTS

logger = logging.getLogger(__name__)

_BOT_LOWER = [b.lower() for b in BOT_USER_AGENTS]


class BotDetector:
    """Identify known scanning tools by User-Agent string."""

    def detect(self, user_agent: str) -> Dict:
        ua_lower = (user_agent or "").lower()

        for bot in _BOT_LOWER:
            if bot in ua_lower:
                return {
                    "detected": True,
                    "attack_type": "BOT_SCAN",
                    "severity": "MEDIUM",
                    "pattern": bot,
                    "confidence": 0.85,
                    "details": f"Known scanner/bot UA: {user_agent[:200]}",
                    "recommended_action": "RATE_LIMIT",
                }

        return {"detected": False, "attack_type": "BOT_SCAN"}
