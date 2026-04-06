# 🛡️ AI Cyber Defense Shield — Standalone Extension

Plug-and-play Chrome extension. No backend, no Docker, no setup.

## Install

1. Open Chrome → `chrome://extensions/`
2. Enable **Developer mode** (top-right toggle)
3. Click **Load unpacked**
4. Select this `shield-extension/` folder
5. Done — the 🛡️ icon appears in your toolbar

## What it does

Every page you visit is automatically scanned. Results show as:
- Colored badge on the toolbar icon (✓ green = safe, ✕ red = critical)
- In-page popup sliding in from top-right
- Bottom toast showing how many threats were masked on the page

## Detects

| Threat | Severity |
|--------|----------|
| HTTP site (no encryption) | HIGH |
| Password field on HTTP | CRITICAL |
| Payment form on HTTP | CRITICAL |
| Phishing domain patterns | CRITICAL |
| High-risk TLDs (.tk .ml .ga .cf) | MEDIUM |
| IP address as domain | HIGH |
| Executable file downloads | HIGH |
| Homograph/punycode domains | HIGH |
| Mixed content (HTTP on HTTPS) | MEDIUM |
| Suspicious form actions | HIGH |
| Cryptominer scripts | CRITICAL |
| Clickjacking (iframe) | MEDIUM |
| Phishing links on page | CRITICAL |
| Scam text patterns | HIGH |
| Tracking pixels | LOW |

## Popup tabs

- **Issues** — security issues on current page
- **History** — all scanned sites with risk scores
- **Blocked** — sites you've blocked (click Unblock to remove)
- **Stats** — lifetime scan statistics

## All data stored locally

Everything is in `chrome.storage.local` — no server, no account, no tracking.
