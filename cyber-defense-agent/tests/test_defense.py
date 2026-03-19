import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
from unittest.mock import MagicMock, AsyncMock, patch


class TestWhitelistManager:
    def test_localhost_whitelisted(self):
        with patch("backend.defense.whitelist_manager.settings") as mock_settings:
            mock_settings.WHITELIST = ["127.0.0.1", "::1"]
            mock_settings.WHITELIST_PATH = "/nonexistent"
            from backend.defense.whitelist_manager import WhitelistManager
            wm = WhitelistManager()
            assert wm.is_whitelisted("127.0.0.1") is True

    def test_unknown_ip_not_whitelisted(self):
        with patch("backend.defense.whitelist_manager.settings") as mock_settings:
            mock_settings.WHITELIST = ["127.0.0.1"]
            mock_settings.WHITELIST_PATH = "/nonexistent"
            from backend.defense.whitelist_manager import WhitelistManager
            wm = WhitelistManager()
            assert wm.is_whitelisted("1.2.3.4") is False


class TestRateLimiter:
    def test_rate_limit_triggered(self):
        from backend.defense.rate_limiter import RateLimiter
        rl = RateLimiter(max_requests=5, window=60)
        for _ in range(6):
            result = rl.check("1.2.3.4")
        assert result is True

    def test_no_rate_limit_below_threshold(self):
        from backend.defense.rate_limiter import RateLimiter
        rl = RateLimiter(max_requests=10, window=60)
        for _ in range(5):
            result = rl.check("5.6.7.8")
        assert result is False
