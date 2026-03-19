SQL_INJECTION_PROMPT = """You are a senior cybersecurity expert. Analyze this SQL injection attack and respond ONLY with valid JSON.

ATTACK:
- Type: {attack_type}
- Severity: {severity}
- Confidence: {confidence}
- Pattern matched: {pattern}

REQUEST:
- IP: {ip}
- Method: {method}
- Path: {path}
- Status: {status}
- User-Agent: {user_agent}

THREAT INTELLIGENCE (CVE context):
{cve_context}

GRAPH MITIGATIONS:
{graph_mitigations}

Respond with this exact JSON structure:
{{
    "explanation": "2-3 sentence plain English explanation of what was attempted",
    "impact": "What data or systems could be compromised",
    "mitigation": ["Immediate action 1", "Short-term fix 2", "Long-term improvement 3"],
    "code_fix": {{"vulnerable": "example vulnerable code snippet", "secure": "fixed version using parameterized queries"}},
    "references": ["OWASP A03:2021", "CWE-89"]
}}"""

BRUTE_FORCE_PROMPT = """You are a senior cybersecurity expert. Analyze this brute force attack and respond ONLY with valid JSON.

ATTACK:
- Type: BRUTE_FORCE
- Severity: {severity}
- Failed attempts: {attempt_count} in {time_window}s
- Target path: {path}

REQUEST:
- IP: {ip}
- User-Agent: {user_agent}

THREAT INTELLIGENCE:
{cve_context}

Respond with this exact JSON structure:
{{
    "explanation": "Description of the brute force pattern observed",
    "impact": "Risk of account compromise or unauthorized access",
    "mitigation": ["Immediate: IP blocked", "Implement account lockout after N attempts", "Enable MFA", "Use CAPTCHA"],
    "code_fix": {{"recommendation": "Implement rate limiting and account lockout logic"}},
    "references": ["OWASP A07:2021", "CWE-307"]
}}"""

PATH_TRAVERSAL_PROMPT = """You are a senior cybersecurity expert. Analyze this path traversal attack and respond ONLY with valid JSON.

ATTACK:
- Type: PATH_TRAVERSAL
- Severity: {severity}
- Pattern: {pattern}

REQUEST:
- IP: {ip}
- Method: {method}
- Path: {path}

THREAT INTELLIGENCE:
{cve_context}

Respond with this exact JSON structure:
{{
    "explanation": "What file or directory the attacker was trying to access",
    "impact": "Sensitive files that could be exposed (credentials, configs, system files)",
    "mitigation": ["Immediate: IP blocked", "Validate and sanitize file paths", "Use allowlist for accessible paths", "Run app with minimal filesystem permissions"],
    "code_fix": {{"vulnerable": "open(user_input)", "secure": "validate path is within allowed directory using os.path.realpath"}},
    "references": ["OWASP A01:2021", "CWE-22"]
}}"""

XSS_PROMPT = """You are a senior cybersecurity expert. Analyze this XSS attack and respond ONLY with valid JSON.

ATTACK:
- Type: XSS
- Severity: {severity}
- Pattern: {pattern}

REQUEST:
- IP: {ip}
- Method: {method}
- Path: {path}

THREAT INTELLIGENCE:
{cve_context}

Respond with this exact JSON structure:
{{
    "explanation": "Type of XSS attempted and what the payload could do",
    "impact": "Session hijacking, credential theft, malicious redirects",
    "mitigation": ["Encode all output", "Implement Content Security Policy", "Use HTTPOnly cookies", "Validate input server-side"],
    "code_fix": {{"vulnerable": "innerHTML = userInput", "secure": "textContent = userInput  // or use DOMPurify"}},
    "references": ["OWASP A03:2021", "CWE-79"]
}}"""

GENERIC_PROMPT = """You are a senior cybersecurity expert. Analyze this security event and respond ONLY with valid JSON.

ATTACK:
- Type: {attack_type}
- Severity: {severity}
- Details: {details}

REQUEST:
- IP: {ip}
- Method: {method}
- Path: {path}

THREAT INTELLIGENCE:
{cve_context}

Respond with this exact JSON structure:
{{
    "explanation": "What happened and what the attacker was trying to do",
    "impact": "Potential consequences if attack succeeded",
    "mitigation": ["Immediate action", "Short-term fix", "Long-term improvement"],
    "code_fix": {{"recommendation": "Security improvement recommendation"}},
    "references": ["Relevant OWASP or CWE reference"]
}}"""

PROMPT_MAP = {
    "SQL_INJECTION": SQL_INJECTION_PROMPT,
    "BRUTE_FORCE": BRUTE_FORCE_PROMPT,
    "PATH_TRAVERSAL": PATH_TRAVERSAL_PROMPT,
    "XSS": XSS_PROMPT,
}


def get_prompt(attack_type: str, **kwargs) -> str:
    template = PROMPT_MAP.get(attack_type, GENERIC_PROMPT)
    # Fill in defaults for missing keys
    defaults = {
        "attack_type": attack_type,
        "severity": "UNKNOWN",
        "confidence": "N/A",
        "pattern": "N/A",
        "ip": "unknown",
        "method": "GET",
        "path": "/",
        "status": 200,
        "user_agent": "unknown",
        "attempt_count": 0,
        "time_window": 60,
        "details": "",
        "cve_context": "No CVE context available.",
        "graph_mitigations": "No graph data available.",
    }
    defaults.update(kwargs)
    return template.format(**defaults)
