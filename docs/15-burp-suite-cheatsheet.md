# Chapter 15 — Burp Suite Cheatsheet

Quick reference for the Burp Suite features used throughout this guide.

---

## Proxy

| Action | How |
|--------|-----|
| Toggle intercept | Proxy → Intercept → "Intercept is on/off" button |
| Forward a held request | "Forward" button |
| Drop a held request | "Drop" button |
| View history | Proxy → HTTP history |
| Edit request before forwarding | Edit the raw request pane directly while intercepted |

## Repeater

| Action | How |
|--------|-----|
| Send request here | Right-click request → "Send to Repeater" or `Ctrl+R` |
| Resend | Click "Send" button (or `Ctrl+Enter`) |
| Compare responses | Send multiple times, use tabs, or send to Comparer |

## Intruder

| Attack type | Use case |
|-------------|----------|
| **Sniper** | Single parameter, one payload set — e.g., brute-forcing one password field |
| **Battering ram** | Same payload inserted into multiple positions simultaneously |
| **Pitchfork** | Multiple positions, paired payload lists (e.g., password + matching CSRF token) |
| **Cluster bomb** | Multiple positions, all combinations of payload lists — e.g., blind SQLi char-by-char brute force |

Common workflow:
1. `Ctrl+I` to send a request to Intruder.
2. **Positions** tab → clear (`Clear §`) then mark (`Add §`) only the parameters you want fuzzed.
3. **Payloads** tab → choose payload type (Simple list, Numbers, Brute forcer, etc.) and load/generate values.
4. **Options** tab → set **Grep - Match** to auto-flag responses containing a string (e.g., "User ID exists").
5. **Start attack**.

## Sequencer
Used to statistically evaluate token/session-ID randomness (Chapter 09):
1. Send a request that returns a token/cookie to Sequencer (`Ctrl+E` or right-click → "Send to Sequencer").
2. Select the token location (cookie or response body).
3. Click **Start live capture** to gather hundreds/thousands of samples.
4. Click **Analyze now** for an entropy/randomness report.

## Decoder
For quickly encoding/decoding payloads (URL, Base64, HTML entities, Hex, ASCII hex):
- Paste text → select encode/decode operation from the dropdown chain.

## Comparer
Diff two requests/responses word-by-word or byte-by-byte — useful for spotting subtle differences (e.g., session cookie changes, response length differences in Boolean-blind SQLi).

## Engagement Tools
- **Generate CSRF PoC**: right-click a request → auto-builds an HTML auto-submit form (Chapter 03).
- **Analyze target**: crawls & summarizes discovered content.

## Session Handling Rules & Macros
Used when tokens rotate per request (e.g., Brute Force High, Chapter 01):
1. **Project options → Sessions → Macros → Add** — record a sequence of requests (e.g., GET login page → extract token).
2. **Session Handling Rules → Add** — scope the macro to specific URLs, set it to run **before** each request in that scope (e.g., before every Intruder request).

## Match and Replace
`Proxy → Options → Match and Replace` — automatically rewrite request/response content matching a pattern (e.g., force `security=low` cookie on every request without manually editing each time).

---

## Useful Keyboard Shortcuts

| Shortcut | Action |
|----------|--------|
| `Ctrl+R` | Send to Repeater |
| `Ctrl+I` | Send to Intruder |
| `Ctrl+E` | Send to Sequencer/Comparer (context menu) |
| `Ctrl+Enter` | Send request (in Repeater) |
| `Ctrl+Shift+D` | Deactivate/reactivate intercept (varies by version) |

---

## Companion CLI Tools Referenced in This Guide

```bash
# sqlmap
sqlmap -u "<url>" --cookie="PHPSESSID=...; security=low" --dbs

# hydra
hydra -l admin -P wordlist.txt <target> http-get-form "path:params:fail_string"

# simple HTTP listener for XSS/RFI PoCs
python3 -m http.server 9000
```

---
⬅ [Back: JavaScript Attacks](14-javascript-attacks.md) | 🏠 [Back to README](../README.md)
