# DVWA + Burp Suite — Web Application Security Lab Guide

A hands-on, chapter-wise guide to learning web application security using **DVWA (Damn Vulnerable Web Application)** and **Burp Suite**. Every module covers the vulnerability at **Low, Medium, High, and Impossible** security levels, with source-code analysis explaining *why the attack works* and *why it stops working* as the security level increases.

> ⚠️ **Legal & Ethical Notice**
> DVWA is intentionally vulnerable software. Only run it in an isolated lab (local VM / Docker / private network) that you own. Never point these techniques at systems you do not have explicit written authorization to test. Unauthorized access to computer systems is illegal in most jurisdictions (e.g., Computer Misuse Act, CFAA, IT Act 2000). This repo is for **educational purposes only** — practicing on your own local DVWA instance.

---

## 📁 Repo Structure

```
dvwa-burpsuite-guide/
├── README.md                          # You are here
└── docs/
    ├── 00-setup.md                    # Lab setup: DVWA + Burp Suite + Proxy config
    ├── 01-brute-force.md
    ├── 02-command-injection.md
    ├── 03-csrf.md
    ├── 04-file-inclusion.md
    ├── 05-file-upload.md
    ├── 06-insecure-captcha.md
    ├── 07-sql-injection.md
    ├── 08-sql-injection-blind.md
    ├── 09-weak-session-ids.md
    ├── 10-xss-reflected.md
    ├── 11-xss-stored.md
    ├── 12-xss-dom.md
    ├── 13-csp-bypass.md
    ├── 14-javascript-attacks.md
    └── 15-burp-suite-cheatsheet.md
```

---

## 🎯 What This Guide Covers

| # | Chapter | OWASP Category |
|---|---------|-----------------|
| 00 | Lab Setup (DVWA + Burp Suite) | — |
| 01 | Brute Force | A07: Identification & Auth Failures |
| 02 | Command Injection | A03: Injection |
| 03 | CSRF | A01: Broken Access Control |
| 04 | File Inclusion (LFI/RFI) | A03/A05 |
| 05 | File Upload | A05: Security Misconfiguration |
| 06 | Insecure CAPTCHA | A07 |
| 07 | SQL Injection | A03: Injection |
| 08 | Blind SQL Injection | A03: Injection |
| 09 | Weak Session IDs | A07 |
| 10 | XSS — Reflected | A03: Injection |
| 11 | XSS — Stored | A03: Injection |
| 12 | XSS — DOM Based | A03: Injection |
| 13 | Content Security Policy Bypass | A05 |
| 14 | JavaScript Attacks | A03/A04 |
| 15 | Burp Suite Cheatsheet | Tooling reference |

Each chapter follows the same format:

1. **Objective** — what vulnerability class is being demonstrated
2. **Prerequisites** — DVWA module, Burp settings needed
3. **Low Security** — walkthrough with Burp (Repeater/Intruder/Proxy), payloads, commands
4. **Medium Security** — what filter/sanitization was added, how to bypass it
5. **High Security** — stronger mitigation and (where applicable) bypass technique
6. **Impossible Security** — secure source code, why the attack fails
7. **Root Cause Analysis** — the underlying secure-coding principle
8. **Defensive Takeaways** — how to fix it in real applications

---

## 🧰 Prerequisites

- A Linux host or VM (Kali Linux recommended) or Docker
- [DVWA](https://github.com/digininja/DVWA) (via XAMPP/LAMP or Docker)
- [Burp Suite Community/Pro](https://portswigger.net/burp)
- Firefox/Chrome with FoxyProxy (for switching proxy on/off quickly)
- Basic familiarity with HTTP, PHP, and MySQL

Start with **[`docs/00-setup.md`](docs/00-setup.md)** before anything else — it walks through installing DVWA, configuring Burp as an intercepting proxy, installing Burp's CA certificate, and setting DVWA's security level.

---

## 🗺️ Suggested Learning Path

```
00-setup → 01-brute-force → 07-sql-injection → 08-sql-injection-blind →
10-xss-reflected → 11-xss-stored → 12-xss-dom → 02-command-injection →
04-file-inclusion → 05-file-upload → 03-csrf → 06-insecure-captcha →
09-weak-session-ids → 13-csp-bypass → 14-javascript-attacks
```

---

## 🔑 DVWA Security Levels (quick reference)

| Level | Description |
|-------|-------------|
| **Low** | No security controls. Vulnerability fully exploitable, ideal for learning the raw attack. |
| **Medium** | Basic, usually flawed, filtering (blacklists, `str_replace`, weak escaping). Teaches filter-bypass technique. |
| **High** | Stronger validation/whitelisting, still sometimes bypassable with advanced technique or logic flaws. |
| **Impossible** | Secure coding reference implementation — parameterized queries, output encoding, CSRF tokens, strict whitelisting. Used to study *why* the fix works. |

---

## 📜 License / Disclaimer

Educational content only. Use responsibly, in isolated lab environments you control. The author/repo maintainers are not responsible for misuse.
