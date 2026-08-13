# Chapter 12 — XSS DOM-Based (DVWA Module: XSS (DOM))

## Objective
Exploit a client-side JavaScript sink that inserts URL/query data directly into the DOM without ever sending it back through the server — meaning **Burp's Proxy alone won't reveal the vulnerability**; you must read client-side JS.

## Prerequisites
- Target: `http://localhost/dvwa/vulnerabilities/xss_d/?default=English`
- Browser DevTools + Burp Proxy (to view/modify requests) + manual source review

---

## 🟢 LOW

### Source logic (client-side JavaScript, `page-source.php`)
```php
<?php
$default = 'English';
if( array_key_exists( "default", $_GET ) ) {
    $default = $_GET[ 'default' ];
}
?>
<select name="default">
    <script>
        document.write('<option value="' + document.location.href.substring(document.location.href.indexOf('default=')+8) + '">' + '...' + '</option>');
    </script>
</select>
```
The vulnerable sink is pure client-side: JavaScript reads `document.location.href` directly and writes it into the DOM via `document.write()` — the server-rendered PHP portion (`$default`) is actually a red herring; the **real** sink never touches the server.

### Burp Suite / browser steps
1. Because this is DOM-based, use Burp mainly to confirm the request/response doesn't reflect the payload server-side (proving it's a client sink) — then craft the payload directly in the browser address bar or via Repeater to view the raw HTML/JS delivered:
   ```
   http://localhost/dvwa/vulnerabilities/xss_d/?default=English</option></select><script>alert(document.cookie)</script>
   ```
2. Load this URL directly in the browser — the injected `<script>` executes, confirming client-side DOM injection (view-source will show the *unmodified* template; the payload never appears server-side, only reconstructed by JS at runtime in the DOM).

### Why it works
`document.write()` combined with an unsanitized read from `location.href` is a classic **DOM XSS sink→source** pair. No server-side output encoding can protect this, because the data flow never revisits the server.

---

## 🟡 MEDIUM

### Source logic
```php
$default = str_replace( '<script>', '', $default );
```
Still a server-rendered blacklist, but — crucially — this filtering happens in **PHP**, and the actual vulnerable *client-side* concatenation logic (`document.write(... location.href ...)`) is unchanged, so the fix is misapplied to the wrong layer.

### Burp Suite bypass
```
http://localhost/dvwa/vulnerabilities/xss_d/?default=English</option></select><img src=x onerror=alert(1)>
```
Since the filter only strips `<script>`, any other tag/event-handler vector (as in earlier XSS chapters) works, and — more importantly — since the sink reads from `location.href` client-side, even a hypothetical fully-effective *server-side* filter on the `default` GET parameter's initial PHP-echoed value would be irrelevant to what JavaScript independently re-reads from the URL bar.

### Why the bypass works
The fix targets the server-rendered `$default` PHP variable, but the vulnerable sink pulls fresh data directly from `document.location.href` in the browser — completely bypassing any server-side processing of `default`.

---

## 🔴 HIGH

### Source logic
```php
if (preg_match('/<script>/i', $default)) {... reject at PHP layer ...}
```
Still a server-side regex check on the *initial* PHP-templated value, still irrelevant to the JS sink reading live URL data.

### Burp Suite exercise
Continue to demonstrate that URL fragment/query manipulation still reaches the DOM sink unfiltered:
```
http://localhost/dvwa/vulnerabilities/xss_d/?default=<svg/onload=alert(1)>
```
Confirms the fundamental fix location (server-side regex) never matches the real vulnerable code path (client-side `document.write`).

### Why it's still risky
This level demonstrates a critical, common real-world mistake: **fixing DOM XSS at the server layer instead of the client-side sink** — server-side filtering has zero effect on data the browser JavaScript re-reads independently from the URL/DOM.

---

## ⚪ IMPOSSIBLE

### Source logic
```php
// Server no longer echoes raw $default into JS at all.
// Client-side JS uses a SAFE DOM API and a strict allow-list of valid options:
<script>
    if (document.location.href.indexOf('default=') !== -1) {
        var lang = document.location.href.substring(document.location.href.indexOf('default=')+8);
        var allowed = ['English','French','Spanish','German'];
        if (allowed.indexOf(decodeURIComponent(lang)) === -1) {
            lang = 'English';
        }
        // Use safe DOM methods instead of document.write with concatenated HTML:
        var opt = document.createElement('option');
        opt.value = lang;
        opt.textContent = lang;   // textContent, NOT innerHTML — no markup interpretation
        document.getElementById('dropdown').appendChild(opt);
    }
</script>
```

### Why the attack fails
Two independent fixes close the sink: (1) a **strict allow-list** rejects any value not in a known-safe set, and (2) even if it didn't, using `textContent` (a safe DOM property) instead of `document.write()`/`innerHTML` means any string assigned is treated as plain text, never parsed as HTML/JS.

### Burp Suite/browser exercise
Attempt every payload from Low/Medium/High against the Impossible URL — the dropdown either silently defaults to "English" (rejected by allow-list) or, if any string does reach the DOM, appears as literal visible text with no script execution.

---

## Root Cause Analysis
DOM-based XSS is fundamentally different from reflected/stored XSS: the vulnerable **sink** is entirely client-side JavaScript (`document.write`, `innerHTML`, `eval`, etc.) reading from a client-side **source** (`location.href`, `location.hash`, `document.referrer`). Server-side sanitization of a request parameter is structurally incapable of fixing this, because the malicious flow never round-trips through the server.

## Defensive Takeaways
- Identify DOM XSS by tracing **client-side sources → sinks** in JavaScript, not just server request/response pairs — this requires reading JS source, not just Burp traffic.
- Avoid dangerous sinks: `document.write()`, `.innerHTML`, `eval()`, `setTimeout(string)`. Prefer `textContent`, `createElement`, or a framework with auto-escaping (React, Vue) that defaults to safe rendering.
- Apply strict allow-lists for any client-side value driving UI/behavior.
- Use CSP with `script-src` restrictions to blunt inline-script-based DOM XSS as defense-in-depth (see Chapter 13).

---
⬅ [Back: XSS Stored](11-xss-stored.md) | ➡ [Next: CSP Bypass](13-csp-bypass.md)
