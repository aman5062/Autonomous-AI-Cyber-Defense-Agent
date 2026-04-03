"""
Unit tests for the defense engine components.
"""

import sys
import os
import pytest
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))


class TestIPBlocker:
    def setup_method(self):
        with patch.dict(os.environ, {"DRY_RUN_MODE": "true"}):
            from backend.defense.ip_blocker import IPBlocker
            from backend.config import settings
            settings.defense.dry_run_mode = True
            self.blocker = IPBlocker()

    def test_block_valid_ip(self):
        result = self.blocker.block_ip("192.168.1.100", "test")
        assert result is True

    def test_block_invalid_ip(self):
        result = self.blocker.block_ip("not_an_ip", "test")
        assert result is False

    def test_block_localhost_allowed_by_blocker(self):
        # IPBlocker itself allows localhost; WhitelistManager prevents it upstream
        result = self.blocker.block_ip("127.0.0.1", "test")
        assert result is True  # blocker doesn't have whitelist logic

    def test_unblock_ip(self):
        self.blocker.block_ip("10.0.0.1", "test")
        result = self.blocker.unblock_ip("10.0.0.1")
        assert result is True

    def test_is_blocked(self):
        self.blocker.block_ip("10.0.0.2", "test")
        assert self.blocker.is_blocked("10.0.0.2") is True

    def test_list_blocked(self):
        self.blocker.block_ip("10.0.0.3", "test")
        blocked = self.blocker.list_blocked_ips()
        assert "10.0.0.3" in blocked


class TestWhitelistManager:
    def setup_method(self):
        from backend.defense.whitelist_manager import WhitelistManager
        self.wl = WhitelistManager()

    def test_localhost_always_whitelisted(self):
        assert self.wl.is_whitelisted("127.0.0.1") is True
        assert self.wl.is_whitelisted("::1") is True

    def test_non_whitelisted_ip(self):
        assert self.wl.is_whitelisted("203.0.113.99") is False

    def test_add_and_check(self):
        self.wl.add("192.0.2.1", "test")
        assert self.wl.is_whitelisted("192.0.2.1") is True

    def test_remove(self):
        self.wl.add("192.0.2.2", "test")
        self.wl.remove("192.0.2.2")
        assert self.wl.is_whitelisted("192.0.2.2") is False


class TestDefenseEngine:
    def setup_method(self):
        from backend.monitoring.storage import init_db
        init_db()
        with patch.dict(os.environ, {"DRY_RUN_MODE": "true", "ENABLE_AUTO_BLOCK": "true"}):
            from backend.config import settings
            settings.defense.dry_run_mode = True
            settings.defense.enable_auto_block = True
            from backend.defense.defense_engine import DefenseEngine
            self.engine = DefenseEngine()
            self.engine.set_dry_run(True)

    def test_whitelist_protection(self):
        result = self.engine.execute_defense({
            "ip": "127.0.0.1",
            "attack_type": "SQL_INJECTION",
            "severity": "CRITICAL",
        })
        assert result["action"] == "WHITELISTED"

    def test_block_malicious_ip(self):
        result = self.engine.execute_defense({
            "ip": "203.0.113.5",
            "attack_type": "SQL_INJECTION",
            "severity": "CRITICAL",
        })
        assert result["action"] in ("BLOCK_IP", "ALREADY_BLOCKED")

    def test_rate_limit_xss(self):
        result = self.engine.execute_defense({
            "ip": "203.0.113.6",
            "attack_type": "XSS",
            "severity": "MEDIUM",
        })
        assert result["action"] in ("RATE_LIMIT", "BLOCK_IP", "ALREADY_BLOCKED")

    def test_no_ip_returns_failure(self):
        result = self.engine.execute_defense({
            "attack_type": "SQL_INJECTION",
            "severity": "CRITICAL",
        })
        assert result["success"] is False

    def test_manual_block_and_unblock(self):
        test_ip = "203.0.113.50"
        block_result = self.engine.manual_block(test_ip, "Test block", 60)
        assert block_result["action"] in ("BLOCK_IP", "ALREADY_BLOCKED")

        unblock_result = self.engine.manual_unblock(test_ip)
        assert unblock_result["success"] is True

    def test_dry_run_returns_success(self):
        self.engine.set_dry_run(True)
        result = self.engine.execute_defense({
            "ip": "203.0.113.7",
            "attack_type": "BRUTE_FORCE",
            "severity": "HIGH",
        })
        assert result["success"] is True
