import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
from unittest.mock import patch

# Patch config paths before importing detectors
with patch("backend.detection.patterns._PATTERNS_PATH") as mock_path:
    mock_path.exists.return_value = False

from backend.detection.sql_injection import SQLInjectionDetector
from backend.detection.brute_force import BruteForceDetector
from backend.detection.path_traversal import PathTraversalDetector
from backend.detection.xss_detector import XSSDetector


class TestSQLInjection:
    def setup_method(self):
        self.detector = SQLInjectionDetector()

    def test_detects_or_injection(self):
        r = self.detector.detect("/login?user=' OR '1'='1--")
        assert r["detected"] is True
        assert r["attack_type"] == "SQL_INJECTION"

    def test_detects_union_select(self):
        r = self.detector.detect("/search?q=1 UNION SELECT username,password FROM users--")
        assert r["detected"] is True
        assert r["severity"] == "CRITICAL"

    def test_detects_drop_table(self):
        r = self.detector.detect("/api?id=1; DROP TABLE users--")
        assert r["detected"] is True
        assert r["severity"] == "CRITICAL"

    def test_clean_request(self):
        r = self.detector.detect("/login?user=admin&pass=secret")
        assert r["detected"] is False


class TestBruteForce:
    def setup_method(self):
        self.detector = BruteForceDetector()

    def test_detects_after_threshold(self):
        for _ in range(5):
            result = self.detector.detect("10.0.0.1", "/login", 401)
        assert result["detected"] is True
        assert result["attack_type"] == "BRUTE_FORCE"

    def test_no_detection_below_threshold(self):
        d = BruteForceDetector()
        for _ in range(3):
            result = d.detect("10.0.0.2", "/login", 401)
        assert result["detected"] is False

    def test_ignores_non_login_paths(self):
        result = self.detector.detect("10.0.0.3", "/api/data", 401)
        assert result["detected"] is False


class TestPathTraversal:
    def setup_method(self):
        self.detector = PathTraversalDetector()

    def test_detects_etc_passwd(self):
        r = self.detector.detect("/file?name=../../../../etc/passwd")
        assert r["detected"] is True
        assert r["severity"] == "CRITICAL"

    def test_detects_dotdot(self):
        r = self.detector.detect("/download?path=../../../secret")
        assert r["detected"] is True

    def test_clean_path(self):
        r = self.detector.detect("/static/image.png")
        assert r["detected"] is False


class TestXSS:
    def setup_method(self):
        self.detector = XSSDetector()

    def test_detects_script_tag(self):
        r = self.detector.detect("/search?q=<script>alert('xss')</script>")
        assert r["detected"] is True
        assert r["attack_type"] == "XSS"

    def test_detects_javascript_protocol(self):
        r = self.detector.detect("/redirect?url=javascript:alert(1)")
        assert r["detected"] is True

    def test_clean_input(self):
        r = self.detector.detect("/search?q=hello+world")
        assert r["detected"] is False
