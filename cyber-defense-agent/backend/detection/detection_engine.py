import logging
import time
from collections import defaultdict
from backend.config import settings
from backend.detection.sql_injection import SQLInjectionDetector
from backend.detection.brute_force import BruteForceDetector
from backend.detection.path_traversal import PathTraversalDetector
from backend.detection.xss_detector import XSSDetector

logger = logging.getLogger(__name__)

_SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}


class AttackDetectionEngine:
    def __init__(self):
        self.sql = SQLInjectionDetector()
        self.brute_force = BruteForceDetector()
        self.path_traversal = PathTraversalDetector()
        self.xss = XSSDetector()

        # DDoS tracking: ip -> [timestamps]
        self._request_counts: dict = defaultdict(list)
        self._ddos_threshold = settings.DDOS_THRESHOLD
        self._ddos_window = settings.DDOS_WINDOW

        # Bot user-agent patterns
        self._bot_agents = [
            "sqlmap", "nikto", "nmap", "masscan", "zgrab",
            "python-requests", "go-http-client", "curl/", "wget/",
            "dirbuster", "dirb", "gobuster", "hydra",
        ]

    def analyze_request(self, request: dict) -> list:
        detections = []
        path = request.get("path", "")
        method = request.get("method", "GET")
        ip = request.get("ip", "")
        status = request.get("status", 200)
        user_agent = (request.get("user_agent") or "").lower()

        # SQL Injection
        r = self.sql.detect(path, method)
        if r.get("detected"):
            detections.append(r)

        # Path Traversal
        r = self.path_traversal.detect(path)
        if r.get("detected"):
            detections.append(r)

        # XSS
        r = self.xss.detect(path, method)
        if r.get("detected"):
            detections.append(r)

        # Brute Force
        r = self.brute_force.detect(ip, path, status)
        if r.get("detected"):
            detections.append(r)

        # DDoS detection
        r = self._detect_ddos(ip)
        if r.get("detected"):
            detections.append(r)

        # Bot detection
        r = self._detect_bot(ip, user_agent)
        if r.get("detected"):
            detections.append(r)

        return detections

    def _detect_ddos(self, ip: str) -> dict:
        now = time.time()
        self._request_counts[ip].append(now)
        self._request_counts[ip] = [
            t for t in self._request_counts[ip] if now - t <= self._ddos_window
        ]
        count = len(self._request_counts[ip])
        if count >= self._ddos_threshold:
            return {
                "detected": True,
                "attack_type": "DDOS",
                "severity": "CRITICAL",
                "confidence": 0.85,
                "recommended_action": "RATE_LIMIT",
                "details": f"{count} requests in {self._ddos_window}s from {ip}",
            }
        return {"detected": False}

    def _detect_bot(self, ip: str, user_agent: str) -> dict:
        for bot in self._bot_agents:
            if bot in user_agent:
                return {
                    "detected": True,
                    "attack_type": "BOT_SCAN",
                    "severity": "HIGH",
                    "confidence": 0.92,
                    "recommended_action": "BLOCK_IP",
                    "details": f"Known attack tool detected in User-Agent: {bot}",
                }
        return {"detected": False}
