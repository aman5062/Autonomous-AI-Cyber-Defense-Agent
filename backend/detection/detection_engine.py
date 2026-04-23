"""
Attack Detection Engine – orchestrates all detectors and produces unified results.
"""

import asyncio
import logging
from datetime import datetime
from typing import Dict, List

from backend.detection.sql_injection import SQLInjectionDetector
from backend.detection.brute_force import BruteForceDetector
from backend.detection.path_traversal import PathTraversalDetector
from backend.detection.xss_detector import XSSDetector
from backend.detection.command_injection import CommandInjectionDetector
from backend.detection.bot_detector import BotDetector

logger = logging.getLogger(__name__)

_SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}


class AttackDetectionEngine:
    """
    Run all detectors against a parsed request and return every
    detection that fired, sorted by severity (highest first).
    """

    def __init__(self):
        self.sql_detector = SQLInjectionDetector()
        self.brute_force_detector = BruteForceDetector()
        self.path_traversal_detector = PathTraversalDetector()
        self.xss_detector = XSSDetector()
        self.cmd_detector = CommandInjectionDetector()
        self.bot_detector = BotDetector()

    def analyze_request(self, request_data: Dict) -> List[Dict]:
        """
        Run all detectors synchronously.

        *request_data* keys expected:
          ip, path, method, status, user_agent, [body]

        Returns list of detection dicts (may be empty).
        """
        path = request_data.get("path", "")
        method = request_data.get("method", "GET")
        ip = request_data.get("ip", "")
        status = request_data.get("status", 200)
        user_agent = request_data.get("user_agent", "")
        body = request_data.get("body", "")

        # Combine path + body so POST body injection is also detected
        combined = f"{path} {body}".strip() if body else path

        detections: List[Dict] = []

        # SQL Injection — check path AND body
        result = self.sql_detector.detect(combined, method)
        if result["detected"]:
            result["ip"] = ip
            result["timestamp"] = datetime.utcnow().isoformat()
            detections.append(result)

        # Brute Force
        result = self.brute_force_detector.detect(ip, path, status)
        if result["detected"]:
            result["ip"] = ip
            result["timestamp"] = datetime.utcnow().isoformat()
            detections.append(result)

        # Path Traversal
        result = self.path_traversal_detector.detect(combined)
        if result["detected"]:
            result["ip"] = ip
            result["timestamp"] = datetime.utcnow().isoformat()
            detections.append(result)

        # XSS
        result = self.xss_detector.detect(combined, body)
        if result["detected"]:
            result["ip"] = ip
            result["timestamp"] = datetime.utcnow().isoformat()
            detections.append(result)

        # Command Injection — check path AND body
        result = self.cmd_detector.detect(combined)
        if result["detected"]:
            result["ip"] = ip
            result["timestamp"] = datetime.utcnow().isoformat()
            detections.append(result)

        # Bot / Scanner
        result = self.bot_detector.detect(user_agent)
        if result["detected"]:
            result["ip"] = ip
            result["timestamp"] = datetime.utcnow().isoformat()
            detections.append(result)

        # Sort by severity
        detections.sort(
            key=lambda d: _SEVERITY_ORDER.get(d.get("severity", "LOW"), 0),
            reverse=True,
        )

        if detections:
            logger.info(
                "Attack detected: ip=%s type=%s severity=%s",
                ip,
                detections[0].get("attack_type"),
                detections[0].get("severity"),
            )

        return detections

    async def analyze_request_async(self, request_data: Dict) -> List[Dict]:
        """Async wrapper – runs detection in thread pool to avoid blocking."""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self.analyze_request, request_data)

    def highest_severity(self, detections: List[Dict]) -> str:
        """Return the highest severity level from a list of detections."""
        if not detections:
            return "NONE"
        return max(
            (d.get("severity", "LOW") for d in detections),
            key=lambda s: _SEVERITY_ORDER.get(s, 0),
        )
