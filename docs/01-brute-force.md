# Chapter 01 — Brute Force (DVWA Module: Brute Force)

## Objective
Use Burp Suite **Intruder** to automate login attempts and defeat weak authentication controls.

## Prerequisites
- Wordlist, e.g. `/usr/share/wordlists/rockyou.txt` or a small custom list
- Burp Proxy intercepting `http://localhost/dvwa/vulnerabilities/brute/`

---

## 🟢 LOW

### Source logic
```php
$user = $_GET[ 'username' ];
$pass = $_GET[ 'password' ];
$pass = md5( $pass );
$query = "SELECT * FROM users WHERE user = '$user' AND password = '$pass';";
```
No rate limiting, no lockout, no CAPTCHA, no delay.

### Burp Suite steps
1. Turn on **Proxy Intercept**, submit a login attempt (`username=admin&password=test`) via the form.
2. Forward the captured `GET` request to **Intruder** (`Ctrl+I`).
3. In **Intruder → Positions**, clear auto-marked positions, then mark only the password value:
   `username=admin&password=§test§`
4. Set **Attack type** = `Sniper`.
5. **Payloads** tab → Payload type: `Simple list` → load your wordlist.
6. Click **Start attack**.
7. Sort results by **Length** or **Status code** — the correct password produces a different response length (look for the "Welcome to the password protected area" string, or absence of "Username and/or password incorrect").

### Command-line alternative (Hydra)
```bash
hydra -l admin -P /usr/share/wordlists/rockyou.txt \
  127.0.0.1 http-get-form \
  "/dvwa/vulnerabilities/brute/:username=^USER^&password=^PASS^&Login=Login:Username and/or password incorrect.:H=Cookie: PHPSESSID=<your_sessid>; security=low"
```

### Why it works
No account lockout, no CAPTCHA, no rate-limiting, predictable GET-based form, and a distinguishable "incorrect" error string that lets Intruder auto-detect success/failure.

---

## 🟡 MEDIUM

### Source logic
```php
if( ( isset( $_GET[ 'Login' ] ) ) && ( strlen( $user ) > 0 ) && ( strlen( $pass ) > 0 ) ) {
    sleep( 2 ); // Added a delay
    ...
}
```
Adds `sleep(2)` after each attempt — a crude rate-limit.

### Burp Suite steps
Same Intruder attack as Low, but:
1. **Intruder → Resource Pool**: create/select a resource pool with limited **concurrent connections** (e.g., 1) since the app itself doesn't block you — only slows you down.
2. Expect the attack to take `2 seconds × number_of_payloads`. For a 3000-word list that's ~100 minutes — still feasible, just slower.
3. Optionally use **Turbo Intruder** (Burp extension) with multiple threads to partially parallelize around the `sleep()`, since `sleep()` blocks per-request but Apache/PHP-FPM can still serve concurrent requests on separate threads/processes.

### Why the "fix" is weak
`sleep(2)` only throttles a *single-threaded* attacker. It does not:
- Track failed attempts per-account or per-IP
- Lock the account
- Prevent concurrent/multi-threaded requests

An attacker with enough parallel connections (multiple Intruder threads, distributed IPs) bypasses the delay almost entirely.

---

## 🔴 HIGH

### Source logic
High level in DVWA adds a **CSRF token** requirement (`user_token`) issued per page load, plus keeps the `sleep(2)`.

```php
if( ! isset( $_SESSION[ 'session_token' ] ) || ( $_SESSION[ 'session_token' ] != $_GET[ 'user_token' ] ) ) {
    // token invalid
}
```

### Burp Suite steps
1. The token changes on every page load — a static Intruder payload set will fail after the first attempt since the token becomes stale.
2. Use **Intruder → Positions** with attack type `Pitchfork`: mark both `§password§` and `§user_token§`.
3. Because `user_token` must be freshly scraped from the login page each time, this single-request brute force no longer works directly. Instead:
   - Use **Burp Macros** (Project options → Sessions → Macros): record a macro that `GET`s the login page, extracts the fresh `user_token` via a regex, and injects it into the next request automatically.
   - Attach the macro as a **Session Handling Rule** scoped to the brute force URL, applied *before each Intruder request*.
4. Re-run Intruder — now each request fetches a valid token first, then submits the guess.

### Why it's harder
A rotating anti-CSRF token forces the attacker to make **two requests per guess** (fetch token, then submit), significantly slowing raw brute force and defeating naive replay — but it's still automatable with session-handling rules, so this is mitigation, not prevention.

---

## ⚪ IMPOSSIBLE

### Source logic
```php
// Sanitize + parameterized query
$user = $db->real_escape_string( $_GET[ 'username' ] );
$pass = $db->real_escape_string( $_GET[ 'password' ] );
...
// Account lockout logic
$query = "SELECT failed_login FROM users WHERE user = '$user';";
if ($failed_login >= 3) {
    // lock account for a time window
}
// CSRF token required
checkToken( $_REQUEST[ 'user_token' ], $_SESSION[ 'session_token' ], 'login.php' );
```

### Why the attack fails
- **Account lockout** after N failed attempts (time-boxed) stops unlimited guessing per account.
- **CSRF token** stops scripted/replayed submissions without a live session.
- **Prepared statements** prevent any injection-based auth bypass alongside brute force.
- Failed attempts are logged, enabling detection/alerting.

### Burp Suite exercise
Try the same Intruder attack — you'll see the account lock after ~3 failed attempts regardless of thread count, and the token/session macro requirement remains. Document the response difference (e.g., "account locked" message) as your proof of mitigation.

---

## Root Cause Analysis
Brute force is an **authentication design failure**, not a code injection bug. The fix is layered: rate limiting done *correctly* (server/account-based, not per-request sleep), account lockout, CAPTCHA, MFA, and anti-automation tokens — not any single control alone.

## Defensive Takeaways
- Implement server-side, account/IP-based lockout with exponential backoff.
- Never rely on `sleep()` as your only defense.
- Add CAPTCHA after N failures.
- Log and alert on repeated auth failures.
- Consider MFA for sensitive accounts.

---
⬅ [Back to Setup](00-setup.md) | ➡ [Next: Command Injection](02-command-injection.md)
