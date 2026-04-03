"""
Unit tests for attack detection modules.
"""

import sys
import os
import pytest

# Allow importing from project root
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))


# ──────────────────────────────────────────────────────────────────
# SQL Injection
# ──────────────────────────────────────────────────────────────────

class TestSQLInjectionDetector:
    def setup_method(self):
        from backend.detection.sql_injection import SQLInjectionDetector
        self.detector = SQLInjectionDetector()

    def test_detects_classic_or_injection(self):
        result = self.detector.detect("/login?user=' OR '1'='1--", "GET")
        assert result["detected"] is True
        assert result["attack_type"] == "SQL_INJECTION"

    def test_detects_union_select(self):
        result = self.detector.detect("/products?id=1 UNION SELECT username,password FROM users", "GET")
        assert result["detected"] is True
        assert result["severity"] == "CRITICAL"

    def test_detects_drop_table(self):
        result = self.detector.detect("/update?id=1; DROP TABLE users", "GET")
        assert result["detected"] is True

    def test_detects_url_encoded(self):
        result = self.detector.detect("/login?user=%27%20OR%20%271%27%3D%271", "GET")
        assert result["detected"] is True

    def test_benign_path_not_detected(self):
        result = self.detector.detect("/products?id=42", "GET")
        assert result["detected"] is False

    def test_benign_search_not_detected(self):
        result = self.detector.detect("/search?q=blue+shirt", "GET")
        assert result["detected"] is False

    def test_returns_pattern_on_detection(self):
        result = self.detector.detect("/login?user=' OR '1'='1--", "GET")
        assert "pattern" in result
        assert result["confidence"] > 0.5


# ──────────────────────────────────────────────────────────────────
# Brute Force
# ──────────────────────────────────────────────────────────────────

class TestBruteForceDetector:
    def setup_method(self):
        from backend.detection.brute_force import BruteForceDetector
        self.detector = BruteForceDetector(threshold=5, time_window=60)

    def test_no_detection_below_threshold(self):
        for _ in range(4):
            result = self.detector.detect("10.0.0.1", "/login", 401)
        assert result["detected"] is False

    def test_detects_at_threshold(self):
        d = __import__("backend.detection.brute_force", fromlist=["BruteForceDetector"]).BruteForceDetector(threshold=5, time_window=60)
        result = None
        for _ in range(5):
            result = d.detect("10.0.0.2", "/login", 401)
        assert result["detected"] is True
        assert result["attack_type"] == "BRUTE_FORCE"

    def test_different_ips_independent(self):
        for _ in range(5):
            self.detector.detect("10.0.0.10", "/login", 401)
        result = self.detector.detect("10.0.0.11", "/login", 401)
        assert result["detected"] is False

    def test_no_detection_on_success_status(self):
        result = self.detector.detect("10.0.0.3", "/login", 200)
        assert result["detected"] is False

    def test_no_detection_on_non_login_path(self):
        result = self.detector.detect("10.0.0.4", "/api/data", 401)
        assert result["detected"] is False

    def test_reset_clears_attempts(self):
        d = __import__("backend.detection.brute_force", fromlist=["BruteForceDetector"]).BruteForceDetector(threshold=5, time_window=60)
        for _ in range(5):
            d.detect("10.0.0.5", "/login", 401)
        d.reset_attempts("10.0.0.5")
        assert d.get_attempt_count("10.0.0.5") == 0


# ──────────────────────────────────────────────────────────────────
# Path Traversal
# ──────────────────────────────────────────────────────────────────

class TestPathTraversalDetector:
    def setup_method(self):
        from backend.detection.path_traversal import PathTraversalDetector
        self.detector = PathTraversalDetector()

    def test_detects_etc_passwd(self):
        result = self.detector.detect("/files?name=../../../../etc/passwd")
        assert result["detected"] is True
        assert result["severity"] == "CRITICAL"

    def test_detects_dotdot_slash(self):
        result = self.detector.detect("/download?file=../../secret.txt")
        assert result["detected"] is True

    def test_detects_url_encoded(self):
        result = self.detector.detect("/files?name=%2e%2e%2fetc%2fpasswd")
        assert result["detected"] is True

    def test_detects_null_byte(self):
        result = self.detector.detect("/files?name=image.jpg%00.php")
        assert result["detected"] is True

    def test_benign_path(self):
        result = self.detector.detect("/images/logo.png")
        assert result["detected"] is False

    def test_detects_ssh_key(self):
        result = self.detector.detect("/../../../../.ssh/id_rsa")
        assert result["detected"] is True


# ──────────────────────────────────────────────────────────────────
# XSS
# ──────────────────────────────────────────────────────────────────

class TestXSSDetector:
    def setup_method(self):
        from backend.detection.xss_detector import XSSDetector
        self.detector = XSSDetector()

    def test_detects_script_tag(self):
        result = self.detector.detect("/search?q=<script>alert(1)</script>")
        assert result["detected"] is True

    def test_detects_javascript_protocol(self):
        result = self.detector.detect("/redirect?url=javascript:alert(document.cookie)")
        assert result["detected"] is True

    def test_detects_event_handler(self):
        result = self.detector.detect("/page?name=<img onerror=alert(1)>")
        assert result["detected"] is True

    def test_detects_eval(self):
        result = self.detector.detect("/page?data=eval('alert(1)')")
        assert result["detected"] is True

    def test_benign_search(self):
        result = self.detector.detect("/search?q=hello+world")
        assert result["detected"] is False

    def test_encoded_xss(self):
        result = self.detector.detect("/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E")
        assert result["detected"] is True


# ──────────────────────────────────────────────────────────────────
# Command Injection
# ──────────────────────────────────────────────────────────────────

class TestCommandInjectionDetector:
    def setup_method(self):
        from backend.detection.command_injection import CommandInjectionDetector
        self.detector = CommandInjectionDetector()

    def test_detects_semicolon_command(self):
        result = self.detector.detect("/ping?host=localhost; cat /etc/passwd")
        assert result["detected"] is True

    def test_detects_pipe(self):
        result = self.detector.detect("/ping?host=127.0.0.1 | ls")
        assert result["detected"] is True

    def test_detects_bash(self):
        result = self.detector.detect("/run?cmd=/bin/bash")
        assert result["detected"] is True

    def test_benign_path(self):
        result = self.detector.detect("/ping?host=localhost")
        assert result["detected"] is False


# ──────────────────────────────────────────────────────────────────
# Detection Engine
# ──────────────────────────────────────────────────────────────────

class TestDetectionEngine:
    def setup_method(self):
        from backend.detection.detection_engine import AttackDetectionEngine
        self.engine = AttackDetectionEngine()

    def test_sql_injection_detected(self):
        req = {
            "ip": "1.2.3.4",
            "path": "/login?user=' OR '1'='1--",
            "method": "GET",
            "status": 401,
            "user_agent": "Mozilla/5.0",
        }
        results = self.engine.analyze_request(req)
        assert len(results) > 0
        types = [r["attack_type"] for r in results]
        assert "SQL_INJECTION" in types

    def test_clean_request_no_detections(self):
        req = {
            "ip": "1.2.3.4",
            "path": "/index.html",
            "method": "GET",
            "status": 200,
            "user_agent": "Mozilla/5.0",
        }
        results = self.engine.analyze_request(req)
        assert results == []

    def test_brute_force_multi_requests(self):
        engine = __import__(
            "backend.detection.detection_engine",
            fromlist=["AttackDetectionEngine"]
        ).AttackDetectionEngine()
        req = {
            "ip": "5.5.5.5",
            "path": "/login",
            "method": "POST",
            "status": 401,
            "user_agent": "python-requests",
        }
        result = None
        for _ in range(5):
            detections = engine.analyze_request(req)
            if detections:
                result = detections
        # Should detect brute force OR bot scan
        assert result is not None

    def test_highest_severity(self):
        detections = [
            {"attack_type": "XSS", "severity": "MEDIUM"},
            {"attack_type": "SQL_INJECTION", "severity": "CRITICAL"},
            {"attack_type": "BRUTE_FORCE", "severity": "HIGH"},
        ]
        sev = self.engine.highest_severity(detections)
        assert sev == "CRITICAL"

    def test_bot_detected_by_ua(self):
        req = {
            "ip": "9.9.9.9",
            "path": "/",
            "method": "GET",
            "status": 200,
            "user_agent": "sqlmap/1.7.8",
        }
        results = self.engine.analyze_request(req)
        types = [r["attack_type"] for r in results]
        assert "BOT_SCAN" in types
