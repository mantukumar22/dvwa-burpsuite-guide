# Chapter 09 — Weak Session IDs (DVWA Module: Weak Session IDs)

## Objective
Analyze session/cookie token generation patterns using Burp's **Sequencer** tool to determine predictability, then forge a valid session token.

## Prerequisites
- Target: `http://localhost/dvwa/vulnerabilities/weak_id/`
- Burp **Sequencer** tab

---

## 🟢 LOW

### Source logic
```php
// Cookie value is simply an incrementing integer
$cookie_value = $last_session_id + 1;
setcookie( 'dvwaSession', $cookie_value );
```
Session identifier is a **sequential integer** — trivially predictable.

### Burp Suite steps
1. Refresh the page multiple times, capturing the `dvwaSession` cookie value each time in Proxy → **HTTP history**.
2. Observe the pattern: `1000, 1001, 1002, ...`
3. In Repeater, manually set `Cookie: dvwaSession=999` (a plausible earlier value) and resend — if session validation is weak, this may hijack a prior/different session context.
4. Use **Sequencer**: send many refresh requests to it, analyze token — Sequencer will rate the "incrementing integer" scheme as having effectively **zero entropy/randomness**.

### Why it works
Sequential IDs allow trivial guessing of *other users'* session identifiers by simply incrementing/decrementing the observed value — no cryptographic randomness at all.

---

## 🟡 MEDIUM

### Source logic
```php
// Cookie value = current unix timestamp
$cookie_value = time();
setcookie( 'dvwaSession', $cookie_value );
```
Session ID is the **server's Unix timestamp** at generation.

### Burp Suite bypass
1. Note the response's `Date` header (server time) alongside the issued `dvwaSession` cookie value — they'll closely correlate.
2. Since Unix time is public knowledge (`date +%s` matches within a few seconds), an attacker can compute/guess a victim's likely session value if they know roughly *when* the victim logged in (e.g., via a phishing link timestamp, or a narrow enough window brute-forced with Intruder):
   ```bash
   date +%s
   ```
3. Use **Intruder** with a numeric payload range of ±60 seconds around the estimated login time to brute-force the exact cookie value.

### Why the bypass works
Time-based tokens have very low effective entropy — the *search space* is small (seconds within a plausible window), not cryptographically large, and the generation logic is publicly known (it's just `time()`).

---

## 🔴 HIGH

### Source logic
```php
// Cookie value = md5( time() )
$cookie_value = md5( time() );
```
Hashes the timestamp with MD5 before use.

### Burp Suite exercise
1. Hashing does **not** add entropy to the underlying secret — it only obscures the *format*. The actual input space is still just Unix timestamps (a small, guessable range).
2. Precompute `md5(time())` for every second in a plausible window and compare against the Sequencer/Intruder-captured hash:
   ```bash
   for i in $(seq -60 60); do
     ts=$(( $(date +%s) + i ))
     echo "$ts -> $(echo -n $ts | md5sum)"
   done
   ```
3. Match the computed hash against the target's cookie to recover the exact seed instantly.

### Why it's still risky
"Hashing a weak secret" is a common but ineffective mitigation — MD5 is deterministic and fast to brute-force over a small keyspace; hashing doesn't convert a low-entropy timestamp into a high-entropy token.

---

## ⚪ IMPOSSIBLE

### Source logic
```php
// Cryptographically secure random token, sufficiently long
$cookie_value = md5( uniqid( mt_rand(), true ) );
// Bound to server-side session store, validated with session regeneration on login,
// HttpOnly + Secure flags set, short expiry
```
Uses `uniqid()` seeded with `mt_rand()` plus extra entropy, though DVWA's own note admits even this isn't perfectly cryptographically secure — the key lesson is the **use of unpredictable, high-entropy seeds** vs. purely time-based ones, combined with proper cookie flags.

### Why the attack fails
The token's generation input is no longer derivable from public information (no simple relationship to server time), and the search space is large enough that Sequencer will rate it with much higher effective entropy — brute-forcing becomes computationally infeasible within any practical time window.

### Burp Suite exercise
Run Burp **Sequencer** against tokens from all four levels back-to-back and compare the entropy/quality reports — Low and Medium will score "poor," High marginally better but still weak, Impossible should score meaningfully higher (though for true production security you'd want a CSPRNG like `random_bytes()`).

---

## Root Cause Analysis
Weak session ID generation stems from using predictable seeds (sequential counters, timestamps) instead of a **Cryptographically Secure Pseudo-Random Number Generator (CSPRNG)**. Hashing a weak seed does not fix weak entropy — entropy must come from the randomness source itself.

## Defensive Takeaways
- Generate session tokens with a CSPRNG (`random_bytes()` in PHP, `crypto.randomBytes()` in Node, `secrets` module in Python) — never `time()`, incrementing counters, or `rand()`.
- Use sufficiently long tokens (128+ bits of entropy).
- Set `HttpOnly`, `Secure`, and `SameSite` cookie flags.
- Regenerate session IDs on privilege change (e.g., login) to prevent session fixation.
- Use Burp Sequencer regularly during development to statistically validate token randomness.

---
⬅ [Back: Blind SQL Injection](08-sql-injection-blind.md) | ➡ [Next: XSS Reflected](10-xss-reflected.md)
