"""
Prompt templates for LLM attack analysis.
"""

SQL_INJECTION_PROMPT = """\
You are a senior cybersecurity expert analyzing a detected SQL injection attack.

ATTACK DETAILS:
- Type: {attack_type}
- Severity: {severity}
- Confidence: {confidence}
- Matched Pattern: {pattern}

REQUEST DETAILS:
- IP Address: {ip}
- HTTP Method: {method}
- Request Path: {path}
- Status Code: {status}
- User Agent: {user_agent}

Defense Action Already Taken: IP has been blocked automatically.

TASK: Provide a comprehensive security analysis in valid JSON format:
{{
    "explanation": "2-3 sentence plain-English description of what was attempted",
    "impact": "What data or systems could be compromised",
    "mitigation": [
        "Immediate: IP blocked automatically",
        "Short-term: Implement parameterized queries / prepared statements",
        "Short-term: Enable WAF with SQL injection rules",
        "Long-term: Code audit + ORM adoption",
        "Long-term: Regular penetration testing"
    ],
    "code_fix": {{
        "vulnerable": "Example vulnerable code snippet",
        "secure": "Fixed secure code snippet"
    }},
    "references": ["OWASP A03:2021 - Injection", "CWE-89", "CVE examples"]
}}

Respond ONLY with the JSON object, no other text.
"""

BRUTE_FORCE_PROMPT = """\
You are a senior cybersecurity expert analyzing a brute force attack.

ATTACK DETAILS:
- Type: BRUTE_FORCE
- Failed Attempts: {attempt_count}
- Time Window: {time_window} seconds
- Target Endpoint: {path}

REQUEST DETAILS:
- IP Address: {ip}
- User Agent: {user_agent}

Defense Action Already Taken: IP has been blocked automatically.

TASK: Provide analysis in valid JSON format:
{{
    "explanation": "Description of the brute force attack pattern",
    "impact": "Risk of unauthorized access, account compromise",
    "mitigation": [
        "Immediate: IP blocked automatically",
        "Short-term: Implement account lockout after N failed attempts",
        "Short-term: Add CAPTCHA to login endpoint",
        "Long-term: Enforce Multi-Factor Authentication (MFA)",
        "Long-term: Deploy anomaly-based login monitoring"
    ],
    "code_fix": {{
        "recommendation": "Implement rate limiting + account lockout logic",
        "example": "Use Flask-Limiter or Django ratelimit decorator"
    }},
    "references": ["OWASP A07:2021 - Auth Failures", "CWE-307", "NIST 800-63B"]
}}

Respond ONLY with the JSON object.
"""

PATH_TRAVERSAL_PROMPT = """\
You are a senior cybersecurity expert analyzing a path traversal attack.

ATTACK DETAILS:
- Type: PATH_TRAVERSAL
- Severity: {severity}
- Matched Pattern: {pattern}

REQUEST DETAILS:
- IP Address: {ip}
- Request Path: {path}
- User Agent: {user_agent}

Defense Action Already Taken: IP blocked automatically.

TASK: Provide analysis in valid JSON format:
{{
    "explanation": "Description of what file or directory the attacker targeted",
    "impact": "Sensitive files that could be read (passwd, SSH keys, config files)",
    "mitigation": [
        "Immediate: IP blocked",
        "Short-term: Validate and sanitize all file path inputs",
        "Short-term: Use os.path.realpath() and verify paths stay within allowed root",
        "Long-term: Run web server as least-privilege user",
        "Long-term: Deploy a WAF with path traversal rules"
    ],
    "code_fix": {{
        "vulnerable": "open(request.args.get('file'))",
        "secure": "safe_path = os.path.realpath(os.path.join(SAFE_ROOT, filename)); assert safe_path.startswith(SAFE_ROOT)"
    }},
    "references": ["OWASP A01:2021 - Broken Access Control", "CWE-22"]
}}

Respond ONLY with the JSON object.
"""

XSS_PROMPT = """\
You are a senior cybersecurity expert analyzing a Cross-Site Scripting (XSS) attack.

ATTACK DETAILS:
- Type: XSS
- Severity: {severity}
- Matched Pattern: {pattern}

REQUEST DETAILS:
- IP Address: {ip}
- Request Path: {path}
- User Agent: {user_agent}

Defense Action: IP rate-limited automatically.

TASK: Provide analysis in valid JSON format:
{{
    "explanation": "XSS payload type and what it could execute in a victim's browser",
    "impact": "Cookie theft, session hijacking, defacement, credential harvesting",
    "mitigation": [
        "Immediate: IP rate-limited",
        "Short-term: HTML-encode all user-supplied output (escape <, >, &, quotes)",
        "Short-term: Implement Content Security Policy (CSP) header",
        "Long-term: Use template engines with auto-escaping (Jinja2 autoescaping)",
        "Long-term: Regular security scanning (ZAP/Burp Suite)"
    ],
    "code_fix": {{
        "vulnerable": "return '<p>' + user_input + '</p>'",
        "secure": "from markupsafe import escape; return '<p>' + escape(user_input) + '</p>'"
    }},
    "references": ["OWASP A03:2021 - Injection", "CWE-79", "OWASP XSS Prevention Cheat Sheet"]
}}

Respond ONLY with the JSON object.
"""

COMMAND_INJECTION_PROMPT = """\
You are a senior cybersecurity expert analyzing a command injection attack.

ATTACK DETAILS:
- Type: COMMAND_INJECTION
- Severity: CRITICAL
- Matched Pattern: {pattern}

REQUEST DETAILS:
- IP Address: {ip}
- Request Path: {path}
- User Agent: {user_agent}

Defense Action: IP blocked automatically.

TASK: Provide analysis in valid JSON format:
{{
    "explanation": "OS command injection attempt allowing arbitrary code execution",
    "impact": "Full server compromise, data exfiltration, ransomware deployment",
    "mitigation": [
        "Immediate: IP blocked",
        "Critical: Never pass user input to shell commands",
        "Short-term: Use subprocess with list arguments, never shell=True",
        "Short-term: Whitelist allowed input values",
        "Long-term: Run application in sandboxed container with minimal permissions"
    ],
    "code_fix": {{
        "vulnerable": "os.system('ping ' + user_input)",
        "secure": "subprocess.run(['ping', '-c', '1', validated_host], capture_output=True)"
    }},
    "references": ["OWASP A03:2021 - Injection", "CWE-78"]
}}

Respond ONLY with the JSON object.
"""

BOT_SCAN_PROMPT = """\
You are a senior cybersecurity expert analyzing a security scanner / bot activity.

ATTACK DETAILS:
- Type: BOT_SCAN
- Scanner Signature: {pattern}

REQUEST DETAILS:
- IP Address: {ip}
- User Agent: {user_agent}

Defense Action: IP rate-limited automatically.

TASK: Provide analysis in valid JSON format:
{{
    "explanation": "Automated security scanner detected probing the server",
    "impact": "Reconnaissance phase – attacker mapping vulnerabilities before exploitation",
    "mitigation": [
        "Immediate: IP rate-limited",
        "Short-term: Block scanner IPs via WAF/firewall",
        "Short-term: Implement robots.txt with Disallow: /",
        "Long-term: Honeypot endpoints to detect and track scanners",
        "Long-term: Subscribe to threat intelligence feeds for scanner IP lists"
    ],
    "code_fix": {{
        "recommendation": "No code fix required – harden server configuration"
    }},
    "references": ["OWASP Testing Guide", "NIST Cybersecurity Framework"]
}}

Respond ONLY with the JSON object.
"""

GENERIC_PROMPT = """\
You are a senior cybersecurity expert analyzing a detected attack.

ATTACK DETAILS:
- Type: {attack_type}
- Severity: {severity}

REQUEST DETAILS:
- IP Address: {ip}
- Request Path: {path}
- User Agent: {user_agent}

Defense Action Taken: {action}

Provide a security analysis in valid JSON:
{{
    "explanation": "What happened",
    "impact": "Potential damage",
    "mitigation": ["Step 1", "Step 2", "Step 3"],
    "code_fix": {{"recommendation": "How to fix"}},
    "references": ["Relevant standards"]
}}

Respond ONLY with the JSON object.
"""

PROMPT_REGISTRY = {
    "SQL_INJECTION": SQL_INJECTION_PROMPT,
    "BRUTE_FORCE": BRUTE_FORCE_PROMPT,
    "PATH_TRAVERSAL": PATH_TRAVERSAL_PROMPT,
    "XSS": XSS_PROMPT,
    "COMMAND_INJECTION": COMMAND_INJECTION_PROMPT,
    "BOT_SCAN": BOT_SCAN_PROMPT,
}


def get_prompt(attack_type: str, context: dict) -> str:
    """Return a filled prompt string for the given attack type."""
    template = PROMPT_REGISTRY.get(attack_type, GENERIC_PROMPT)
    # Fill available keys, leave missing ones as empty strings
    safe_ctx = {k: (v if v is not None else "") for k, v in context.items()}
    try:
        return template.format_map(safe_ctx)
    except KeyError:
        return GENERIC_PROMPT.format_map(safe_ctx)
