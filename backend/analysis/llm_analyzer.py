"""
LLM Analyzer – sends attack details to Ollama and returns structured analysis.
Falls back to a rule-based analysis when Ollama is unavailable.
"""

import json
import logging
import re
import threading
from typing import Dict, Optional

import requests

from backend.config import settings
from backend.analysis.prompts import get_prompt

logger = logging.getLogger(__name__)

_FALLBACK_ANALYSES = {
    "SQL_INJECTION": {
        "explanation": (
            "A SQL injection attack was detected where the attacker attempted "
            "to inject malicious SQL code into a query parameter. "
            "This could allow authentication bypass or data exfiltration."
        ),
        "impact": "Potential database compromise, authentication bypass, data theft.",
        "mitigation": [
            "Immediate: IP blocked automatically",
            "Short-term: Use parameterized queries / prepared statements",
            "Short-term: Validate and sanitize all user inputs",
            "Long-term: Regular security audits and code reviews",
        ],
        "code_fix": {
            "vulnerable": "query = 'SELECT * FROM users WHERE id=' + user_id",
            "secure": "cursor.execute('SELECT * FROM users WHERE id=?', (user_id,))",
        },
        "references": ["OWASP A03:2021", "CWE-89"],
    },
    "BRUTE_FORCE": {
        "explanation": (
            "A brute force attack was detected with multiple failed login attempts "
            "from the same IP in a short time window."
        ),
        "impact": "Risk of unauthorized account access if successful.",
        "mitigation": [
            "Immediate: IP blocked",
            "Add account lockout after failed attempts",
            "Implement CAPTCHA",
            "Enforce MFA",
        ],
        "code_fix": {"recommendation": "Implement rate limiting and account lockout"},
        "references": ["OWASP A07:2021", "CWE-307"],
    },
    "PATH_TRAVERSAL": {
        "explanation": (
            "A path traversal attack was detected attempting to access "
            "files outside the web root directory."
        ),
        "impact": "Exposure of sensitive system files, configuration, credentials.",
        "mitigation": [
            "Immediate: IP blocked",
            "Validate file paths using os.path.realpath()",
            "Run server as least-privilege user",
        ],
        "code_fix": {
            "vulnerable": "open(request.args.get('file'))",
            "secure": "Validate path is within allowed SAFE_ROOT directory",
        },
        "references": ["OWASP A01:2021", "CWE-22"],
    },
    "XSS": {
        "explanation": "A Cross-Site Scripting payload was detected in the request.",
        "impact": "Cookie theft, session hijacking, defacement.",
        "mitigation": [
            "HTML-encode all output",
            "Implement Content Security Policy (CSP)",
            "Use auto-escaping template engines",
        ],
        "code_fix": {
            "vulnerable": "return '<p>' + user_input + '</p>'",
            "secure": "from markupsafe import escape; return '<p>' + escape(user_input) + '</p>'",
        },
        "references": ["OWASP A03:2021", "CWE-79"],
    },
    "COMMAND_INJECTION": {
        "explanation": "OS command injection attempt detected.",
        "impact": "Full server compromise possible.",
        "mitigation": [
            "Never pass user input to shell commands",
            "Use subprocess with list args, never shell=True",
            "Whitelist allowed input values",
        ],
        "code_fix": {
            "vulnerable": "os.system('ping ' + user_input)",
            "secure": "subprocess.run(['ping', '-c', '1', validated_host])",
        },
        "references": ["OWASP A03:2021", "CWE-78"],
    },
}


class LLMAnalyzer:
    """
    Analyze attacks using a local Ollama LLM.
    Gracefully degrades to rule-based fallback when Ollama is unavailable.
    """

    def __init__(self):
        self._api_url = settings.ollama.api_url.rstrip("/")
        self._model = settings.ollama.model
        self._temperature = settings.ollama.temperature
        self._max_tokens = settings.ollama.max_tokens
        self._timeout = settings.ollama.timeout
        self._available: Optional[bool] = None  # cached check
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def analyze_attack(self, attack_data: Dict, request_data: Dict) -> Dict:
        """
        Produce a structured analysis for the detected attack.
        Uses Ollama if available, otherwise returns a rule-based response.
        """
        attack_type = attack_data.get("attack_type", "UNKNOWN")

        context = {
            "attack_type": attack_type,
            "severity": attack_data.get("severity", "MEDIUM"),
            "confidence": attack_data.get("confidence", 0.8),
            "pattern": attack_data.get("pattern", ""),
            "ip": request_data.get("ip", ""),
            "method": request_data.get("method", "GET"),
            "path": request_data.get("path", ""),
            "status": request_data.get("status", 0),
            "user_agent": request_data.get("user_agent", ""),
            "attempt_count": attack_data.get("attempt_count", 0),
            "time_window": attack_data.get("time_window", 60),
            "action": attack_data.get("recommended_action", "BLOCK_IP"),
        }

        if self._is_ollama_available():
            try:
                return self._ollama_analyze(attack_type, context)
            except Exception as exc:  # noqa: BLE001
                logger.warning("Ollama analysis failed, using fallback: %s", exc)

        return self._fallback_analysis(attack_type)

    def check_ollama_health(self) -> Dict:
        """Return Ollama service health status."""
        try:
            r = requests.get(f"{self._api_url}/api/tags", timeout=5)
            models = [m["name"] for m in r.json().get("models", [])]
            return {
                "available": True,
                "models": models,
                "target_model": self._model,
                "model_ready": any(self._model in m for m in models),
            }
        except Exception as exc:
            return {"available": False, "error": str(exc)}

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _is_ollama_available(self) -> bool:
        with self._lock:
            if self._available is None:
                try:
                    r = requests.get(f"{self._api_url}/api/tags", timeout=3)
                    self._available = r.status_code == 200
                except Exception:
                    self._available = False
            return self._available

    def _ollama_analyze(self, attack_type: str, context: Dict) -> Dict:
        prompt = get_prompt(attack_type, context)

        payload = {
            "model": self._model,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": self._temperature,
                "num_predict": self._max_tokens,
            },
        }

        response = requests.post(
            f"{self._api_url}/api/generate",
            json=payload,
            timeout=self._timeout,
        )
        response.raise_for_status()
        raw = response.json().get("response", "")
        return self._parse_json_response(raw)

    def _parse_json_response(self, raw: str) -> Dict:
        """Extract JSON from LLM response (may contain surrounding text)."""
        # Try direct parse
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            pass

        # Find JSON block with regex
        match = re.search(r"\{[\s\S]*\}", raw)
        if match:
            try:
                return json.loads(match.group(0))
            except json.JSONDecodeError:
                pass

        # Return raw text wrapped in structure
        return {
            "explanation": raw[:500] if raw else "Analysis unavailable",
            "impact": "",
            "mitigation": [],
            "code_fix": {},
            "references": [],
        }

    def _fallback_analysis(self, attack_type: str) -> Dict:
        analysis = _FALLBACK_ANALYSES.get(attack_type)
        if analysis:
            return dict(analysis)
        return {
            "explanation": f"Attack of type {attack_type} was detected and blocked.",
            "impact": "Potential system compromise.",
            "mitigation": [
                "Review and harden affected endpoints",
                "Keep software up to date",
                "Monitor logs for further activity",
            ],
            "code_fix": {},
            "references": ["OWASP Top 10", "NIST Cybersecurity Framework"],
        }
