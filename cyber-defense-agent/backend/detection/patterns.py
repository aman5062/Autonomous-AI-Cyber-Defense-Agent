"""
Attack pattern database used by multiple detectors.
"""

# SQL Injection patterns
SQL_INJECTION_PATTERNS = [
    r"(\%27)|(')|(\-\-)|(\%23)|(#)",
    r"(=)[^\n]*((\%27)|(')|(\-\-)|(\%3B)|(;))",
    r"\w*((\%27)|('))((\%6F)|o|(\%4F))((\%72)|r|(\%52))",
    r"((\%27)|('))union",
    r"union[\s\+]+select",
    r"select[\s\+]+.*from",
    r"insert[\s\+]+into",
    r"delete[\s\+]+from",
    r"drop[\s\+]+(table|database|index|view)",
    r"update[\s\+]+\w+[\s\+]+set",
    r"exec(\s|\+)+(s|x)p\w+",
    r"'[\s]*or[\s]*'?[\d]+'?[\s]*=[\s]*'?[\d]+",
    r"'[\s]*or[\s]+'1'[\s]*=[\s]*'1",
    r"admin'[\s]*--",
    r"';[\s]*(drop|delete|insert|update|create)",
    r"/\*.*\*/",
    r"xp_cmdshell",
    r"information_schema",
    r"sys\.tables",
    r"char\s*\(\s*\d+",
    r"0x[0-9a-f]{2,}",
    r"benchmark\s*\(",
    r"sleep\s*\(\s*\d+",
    r"waitfor\s+delay",
    r"load_file\s*\(",
    r"into\s+outfile",
]

# XSS patterns
XSS_PATTERNS = [
    r"<script[\s>]",
    r"</script>",
    r"javascript\s*:",
    r"vbscript\s*:",
    r"on(load|click|mouseover|error|focus|blur|change|submit|reset|"
    r"keypress|keydown|keyup|mousedown|mouseup|dblclick|"
    r"contextmenu|wheel|drag|drop)\s*=",
    r"<img[^>]+src[^>]*=",
    r"<iframe[\s>]",
    r"<object[\s>]",
    r"<embed[\s>]",
    r"<svg[\s>]",
    r"<link[\s>]",
    r"expression\s*\(",
    r"document\.(cookie|write|location)",
    r"window\.(location|open)",
    r"eval\s*\(",
    r"alert\s*\(",
    r"confirm\s*\(",
    r"prompt\s*\(",
    r"fromcharcode",
    r"&#\d+;",
    r"%3cscript",
    r"<\s*/?\s*script",
]

# Path Traversal patterns
PATH_TRAVERSAL_PATTERNS = [
    r"\.\./",
    r"\.\.\%2f",
    r"\.\.\%5c",
    r"%2e%2e/",
    r"%2e%2e%2f",
    r"\.\.\\",
    r"/etc/passwd",
    r"/etc/shadow",
    r"/etc/hosts",
    r"/proc/self/",
    r"\.ssh/",
    r"\.htpasswd",
    r"web\.config",
    r"\.git/",
    r"C:\\windows\\",
    r"C:\\winnt\\",
    r"boot\.ini",
    r"\x00",
    r"%00",
    r"\.\.;",
    r"\.%2e",
    r"%2e\.",
]

# Command Injection patterns
COMMAND_INJECTION_PATTERNS = [
    r";\s*(ls|cat|pwd|whoami|id|uname|wget|curl|nc|netcat|bash|sh|python|perl|php)\b",
    r"\|\s*(ls|cat|pwd|whoami|id|uname|wget|curl|bash|sh)\b",
    r"`[^`]+`",
    r"\$\([^)]+\)",
    r"&&\s*(ls|cat|pwd|whoami|id|uname|wget|curl|bash|sh)\b",
    r"/bin/(bash|sh|csh|zsh|ksh)",
    r"cmd\.exe",
    r"powershell",
    r"system\s*\(",
    r"exec\s*\(",
    r"passthru\s*\(",
    r"shell_exec\s*\(",
    r"popen\s*\(",
    r"proc_open\s*\(",
]

# Sensitive file targets for path traversal
SENSITIVE_FILES = [
    "/etc/passwd", "/etc/shadow", "/etc/hosts", "/etc/fstab",
    "/proc/self/environ", "/.ssh/id_rsa", "/.ssh/authorized_keys",
    "/var/www/html/.htpasswd", "/root/.bash_history",
    "C:/windows/system32/config/sam",
    "C:/winnt/system32/config/sam",
    "/boot.ini",
]

# Bot / scanner user-agent signatures
BOT_USER_AGENTS = [
    "sqlmap", "nikto", "nmap", "masscan", "acunetix",
    "nessus", "openvas", "metasploit", "burpsuite",
    "havij", "pangolin", "w3af", "skipfish", "dirb",
    "dirbuster", "gobuster", "wfuzz", "ffuf",
    "python-requests", "python-urllib", "libwww-perl",
    "zgrab", "shodan",
]

# Known malicious patterns (high confidence)
CRITICAL_PATTERNS = {
    "SQL_INJECTION": [
        r"union[\s\+]+select",
        r"exec(\s|\+)+(s|x)p\w+",
        r"drop[\s\+]+(table|database)",
        r"into\s+outfile",
        r"load_file\s*\(",
        r"xp_cmdshell",
        r"sleep\s*\(\s*\d+",
        r"benchmark\s*\(",
        r"waitfor\s+delay",
    ],
    "XSS": [
        r"<script[\s>].*</script>",
        r"javascript\s*:",
        r"on\w+\s*=\s*[\"']?\s*(alert|eval|document\.|window\.)",
    ],
    "PATH_TRAVERSAL": [
        r"/etc/passwd",
        r"/etc/shadow",
        r"\.ssh/id_rsa",
    ],
    "COMMAND_INJECTION": [
        r";\s*(wget|curl|bash|python|perl)\b",
        r"/bin/(bash|sh)",
        r"cmd\.exe",
    ],
}
