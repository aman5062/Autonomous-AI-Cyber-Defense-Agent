"""
Email Reporter – sends AI-generated attack reports via SMTP.

Triggered automatically whenever an attack is detected and an IP is blocked.
Falls back to console logging when SMTP is not configured.
"""

import logging
import smtplib
import threading
from datetime import datetime, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Dict, Optional

from backend.config import settings

logger = logging.getLogger(__name__)


class EmailReporter:
    """
    Send HTML attack-report emails to the configured alert address.

    Thread-safe: every call to ``send_attack_report`` runs in its own
    daemon thread so it never blocks the detection / defense pipeline.
    """

    def __init__(self):
        self._cfg = settings.email
        self._enabled = self._cfg.enabled

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def send_attack_report(
        self,
        attack_data: Dict,
        request_data: Dict,
        analysis: Optional[Dict] = None,
    ) -> None:
        """
        Dispatch an attack report email (non-blocking).

        Parameters
        ----------
        attack_data:
            Detection result dict (attack_type, severity, ip, …).
        request_data:
            Parsed request dict (path, method, user_agent, …).
        analysis:
            LLM / fallback analysis dict (explanation, mitigation, …).
        """
        if not self._enabled:
            logger.debug("Email reporting disabled – skipping report")
            return
        if not self._cfg.alert_email:
            logger.warning("ALERT_EMAIL not set – cannot send report")
            return

        t = threading.Thread(
            target=self._send,
            args=(attack_data, request_data, analysis or {}),
            daemon=True,
        )
        t.start()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _send(self, attack_data: Dict, request_data: Dict, analysis: Dict) -> None:
        try:
            msg = self._build_message(attack_data, request_data, analysis)
            with smtplib.SMTP(self._cfg.smtp_host, self._cfg.smtp_port, timeout=15) as smtp:
                smtp.ehlo()
                smtp.starttls()
                smtp.login(self._cfg.smtp_user, self._cfg.smtp_password)
                smtp.send_message(msg)
            logger.info(
                "Attack report emailed to %s (attack=%s ip=%s)",
                self._cfg.alert_email,
                attack_data.get("attack_type"),
                attack_data.get("ip") or request_data.get("ip"),
            )
        except Exception as exc:
            logger.warning("Failed to send attack report email: %s", exc)

    def _build_message(
        self, attack_data: Dict, request_data: Dict, analysis: Dict
    ) -> MIMEMultipart:
        attack_type = attack_data.get("attack_type", "UNKNOWN")
        severity = attack_data.get("severity", "UNKNOWN")
        ip = attack_data.get("ip") or request_data.get("ip", "unknown")
        path = request_data.get("path", "-")
        method = request_data.get("method", "-")
        user_agent = request_data.get("user_agent", "-")
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        severity_color = {
            "CRITICAL": "#dc2626",
            "HIGH": "#ea580c",
            "MEDIUM": "#ca8a04",
            "LOW": "#16a34a",
        }.get(severity, "#6b7280")

        attack_icon = {
            "SQL_INJECTION": "💉",
            "COMMAND_INJECTION": "⚡",
            "XSS": "🕷️",
            "PATH_TRAVERSAL": "📁",
            "BRUTE_FORCE": "🔨",
            "BOT_SCAN": "🤖",
            "DDOS": "🌊",
        }.get(attack_type, "⚠️")

        mitigation = analysis.get("mitigation", [])
        if isinstance(mitigation, str):
            mitigation = [mitigation]
        mitigation_html = "".join(f"<li>{m}</li>" for m in mitigation)

        code_fix = analysis.get("code_fix", {})
        code_fix_html = ""
        if code_fix.get("vulnerable"):
            code_fix_html += f"""
            <h3 style="color:#ef4444;">❌ Vulnerable Code</h3>
            <pre style="background:#1f2937;color:#f9fafb;padding:12px;border-radius:6px;overflow-x:auto;">{code_fix['vulnerable']}</pre>
            """
        if code_fix.get("secure"):
            code_fix_html += f"""
            <h3 style="color:#22c55e;">✅ Secure Fix</h3>
            <pre style="background:#1f2937;color:#f9fafb;padding:12px;border-radius:6px;overflow-x:auto;">{code_fix['secure']}</pre>
            """

        mitigation_section = (
            f"""
  <tr>
    <td style="padding:0 24px 20px;">
      <h2 style="color:#fff;font-size:16px;margin:0 0 12px;">🔧 Mitigation Steps</h2>
      <div style="background:#0f172a;border-radius:8px;border:1px solid #334155;padding:16px;">
        <ul style="margin:0;padding-left:20px;font-size:13px;line-height:1.8;color:#e2e8f0;">
          {mitigation_html}
        </ul>
      </div>
    </td>
  </tr>"""
            if mitigation_html
            else ""
        )

        code_fix_section = (
            f"""
  <tr>
    <td style="padding:0 24px 20px;">
      <h2 style="color:#fff;font-size:16px;margin:0 0 12px;">💻 Code Fix</h2>
      <div style="background:#0f172a;border-radius:8px;border:1px solid #334155;padding:16px;">
        {code_fix_html}
      </div>
    </td>
  </tr>"""
            if code_fix_html
            else ""
        )

        html = f"""
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
</head>
<body style="margin:0;padding:0;background:#0f172a;font-family:Arial,sans-serif;color:#e2e8f0;">
<table width="100%" cellpadding="0" cellspacing="0" style="background:#0f172a;padding:20px;">
<tr><td align="center">
<table width="600" style="background:#1e293b;border-radius:12px;overflow:hidden;border:1px solid #334155;">

  <!-- Header -->
  <tr>
    <td style="background:linear-gradient(135deg,#dc2626,#7c3aed);padding:24px;text-align:center;">
      <div style="font-size:40px;margin-bottom:8px;">🛡️</div>
      <h1 style="margin:0;font-size:22px;color:#fff;">AI Cyber Defense Alert</h1>
      <p style="margin:6px 0 0;color:#fca5a5;font-size:13px;">Autonomous AI Cyber Defense Agent</p>
    </td>
  </tr>

  <!-- Severity Badge -->
  <tr>
    <td style="padding:20px;text-align:center;">
      <span style="background:{severity_color};color:#fff;padding:8px 24px;border-radius:20px;font-weight:bold;font-size:14px;">
        {attack_icon} {attack_type.replace('_',' ')} — {severity}
      </span>
    </td>
  </tr>

  <!-- Attack Details -->
  <tr>
    <td style="padding:0 24px 20px;">
      <table width="100%" style="background:#0f172a;border-radius:8px;border:1px solid #334155;">
        <tr><td colspan="2" style="padding:12px 16px;border-bottom:1px solid #334155;">
          <strong style="color:#94a3b8;font-size:12px;text-transform:uppercase;letter-spacing:1px;">Attack Details</strong>
        </td></tr>
        <tr>
          <td style="padding:10px 16px;color:#94a3b8;font-size:13px;width:130px;">🕐 Time</td>
          <td style="padding:10px 16px;font-size:13px;font-weight:600;">{ts}</td>
        </tr>
        <tr style="background:#1e293b;">
          <td style="padding:10px 16px;color:#94a3b8;font-size:13px;">🌐 Attacker IP</td>
          <td style="padding:10px 16px;font-size:13px;font-weight:600;color:#f87171;">{ip}</td>
        </tr>
        <tr>
          <td style="padding:10px 16px;color:#94a3b8;font-size:13px;">🎯 Target Path</td>
          <td style="padding:10px 16px;font-size:13px;font-family:monospace;color:#7dd3fc;">{path}</td>
        </tr>
        <tr style="background:#1e293b;">
          <td style="padding:10px 16px;color:#94a3b8;font-size:13px;">📋 Method</td>
          <td style="padding:10px 16px;font-size:13px;">{method}</td>
        </tr>
        <tr>
          <td style="padding:10px 16px;color:#94a3b8;font-size:13px;">🔍 User-Agent</td>
          <td style="padding:10px 16px;font-size:12px;color:#94a3b8;word-break:break-all;">{user_agent}</td>
        </tr>
        <tr style="background:#1e293b;">
          <td style="padding:10px 16px;color:#94a3b8;font-size:13px;">🚫 Action</td>
          <td style="padding:10px 16px;font-size:13px;font-weight:600;color:#4ade80;">IP BLOCKED — Automated Defense Triggered</td>
        </tr>
      </table>
    </td>
  </tr>

  <!-- AI Analysis -->
  <tr>
    <td style="padding:0 24px 20px;">
      <h2 style="color:#fff;font-size:16px;margin:0 0 12px;">🤖 AI Analysis</h2>
      <div style="background:#0f172a;border-radius:8px;border:1px solid #334155;padding:16px;">
        <p style="margin:0 0 12px;line-height:1.6;font-size:13px;">
          {analysis.get("explanation", "Attack detected and blocked automatically.")}
        </p>
        <p style="margin:0;font-size:13px;">
          <strong style="color:#f87171;">Impact:</strong>
          <span style="color:#94a3b8;">{analysis.get("impact", "Potential system compromise.")}</span>
        </p>
      </div>
    </td>
  </tr>

  <!-- Mitigation -->
  {mitigation_section}

  <!-- Code Fix -->
  {code_fix_section}

  <!-- Footer -->
  <tr>
    <td style="background:#0f172a;padding:16px 24px;text-align:center;border-top:1px solid #334155;">
      <p style="margin:0;font-size:11px;color:#475569;">
        This report was generated automatically by the
        <strong style="color:#7c3aed;">Autonomous AI Cyber Defense Agent</strong><br>
        IP {ip} has been blocked and will be automatically unblocked after the ban duration expires.
      </p>
    </td>
  </tr>

</table>
</td></tr>
</table>
</body>
</html>
        """

        subject = (
            f"[CYBER ALERT] {attack_icon} {attack_type.replace('_', ' ')} Detected – "
            f"{severity} Severity – IP {ip} Blocked"
        )

        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = f"AI Cyber Defense Agent <{self._cfg.smtp_user}>"
        msg["To"] = self._cfg.alert_email
        msg.attach(MIMEText(html, "html"))
        return msg
