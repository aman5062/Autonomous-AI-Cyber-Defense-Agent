"""
Unit tests for LLM analysis and log parsing.
"""

import sys
import os
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))


class TestNginxLogParser:
    def setup_method(self):
        from backend.monitoring.log_parser import NginxLogParser
        self.parser = NginxLogParser()

    def test_parse_standard_line(self):
        line = '192.168.1.1 - - [19/Mar/2024:14:23:45 +0000] "GET /index.html HTTP/1.1" 200 1234 "-" "Mozilla/5.0"'
        result = self.parser.parse(line)
        assert result is not None
        assert result["ip"] == "192.168.1.1"
        assert result["method"] == "GET"
        assert result["path"] == "/index.html"
        assert result["status"] == 200
        assert result["size"] == 1234

    def test_parse_post_request(self):
        line = '10.0.0.1 - - [20/Mar/2024:10:00:00 +0000] "POST /login HTTP/1.1" 401 256 "-" "curl/7.68"'
        result = self.parser.parse(line)
        assert result is not None
        assert result["method"] == "POST"
        assert result["status"] == 401

    def test_parse_invalid_line_returns_none(self):
        result = self.parser.parse("this is not a log line")
        assert result is None

    def test_parse_empty_line_returns_none(self):
        result = self.parser.parse("")
        assert result is None

    def test_parse_sql_injection_path(self):
        line = '192.168.1.50 - - [19/Mar/2024:14:23:45 +0000] "GET /login?user=admin HTTP/1.1" 401 512 "-" "sqlmap/1.7"'
        result = self.parser.parse(line)
        assert result is not None
        assert "login" in result["path"]

    def test_parses_user_agent(self):
        line = '1.2.3.4 - - [01/Jan/2024:00:00:00 +0000] "GET / HTTP/1.1" 200 100 "-" "Googlebot/2.1"'
        result = self.parser.parse(line)
        assert result is not None
        assert "Googlebot" in result["user_agent"]


class TestLLMAnalyzer:
    def setup_method(self):
        from backend.analysis.llm_analyzer import LLMAnalyzer
        self.analyzer = LLMAnalyzer()

    def test_fallback_sql_injection(self):
        attack = {"attack_type": "SQL_INJECTION", "severity": "CRITICAL"}
        request = {"ip": "1.2.3.4", "path": "/login?user='--", "method": "GET"}
        # Force fallback by setting available to False
        self.analyzer._available = False
        result = self.analyzer.analyze_attack(attack, request)
        assert "explanation" in result
        assert "mitigation" in result
        assert isinstance(result["mitigation"], list)

    def test_fallback_brute_force(self):
        self.analyzer._available = False
        attack = {"attack_type": "BRUTE_FORCE", "severity": "HIGH", "attempt_count": 10}
        result = self.analyzer.analyze_attack(attack, {})
        assert "explanation" in result

    def test_fallback_xss(self):
        self.analyzer._available = False
        attack = {"attack_type": "XSS", "severity": "MEDIUM"}
        result = self.analyzer.analyze_attack(attack, {})
        assert "explanation" in result

    def test_fallback_unknown_type(self):
        self.analyzer._available = False
        attack = {"attack_type": "UNKNOWN_TYPE", "severity": "LOW"}
        result = self.analyzer.analyze_attack(attack, {})
        assert "explanation" in result

    def test_parse_json_response_clean(self):
        raw = '{"explanation": "test", "impact": "test", "mitigation": [], "code_fix": {}, "references": []}'
        result = self.analyzer._parse_json_response(raw)
        assert result["explanation"] == "test"

    def test_parse_json_response_with_surrounding_text(self):
        raw = 'Here is the analysis:\n{"explanation": "attack", "impact": "bad"}\nEnd.'
        result = self.analyzer._parse_json_response(raw)
        assert result["explanation"] == "attack"


class TestPrompts:
    def test_sql_injection_prompt_fills(self):
        from backend.analysis.prompts import get_prompt
        ctx = {
            "attack_type": "SQL_INJECTION",
            "severity": "CRITICAL",
            "confidence": 0.9,
            "pattern": "union select",
            "ip": "1.2.3.4",
            "method": "GET",
            "path": "/login?q=1",
            "status": 401,
            "user_agent": "sqlmap",
            "attempt_count": 0,
            "time_window": 60,
            "action": "BLOCK_IP",
        }
        prompt = get_prompt("SQL_INJECTION", ctx)
        assert "SQL injection" in prompt
        assert "1.2.3.4" in prompt

    def test_unknown_attack_uses_generic(self):
        from backend.analysis.prompts import get_prompt
        ctx = {"attack_type": "UNKNOWN", "severity": "LOW", "ip": "1.1.1.1",
               "path": "/", "user_agent": "", "action": "ALERT"}
        prompt = get_prompt("TOTALLY_UNKNOWN", ctx)
        assert len(prompt) > 50
