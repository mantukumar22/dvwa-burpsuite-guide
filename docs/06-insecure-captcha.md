# Chapter 06 — Insecure CAPTCHA (DVWA Module: Insecure CAPTCHA)

## Objective
Bypass a CAPTCHA-protected password-change form by manipulating request parameters and flow logic in Burp, without solving the CAPTCHA image itself.

## Prerequisites
- Target: `http://localhost/dvwa/vulnerabilities/captcha/`
- Requires a Google reCAPTCHA key configured in DVWA config (or the module shows an error) — conceptually still testable via Burp on the underlying parameters.

---

## 🟢 LOW

### Source logic
```php
if( isset( $_POST[ 'Change' ] ) ) {
    // Server checks $_POST['g-recaptcha-response'] is non-empty, but doesn't verify with Google if step is skipped/reordered
    $pass_new = $_POST[ 'password_new' ];
    $pass_conf = $_POST[ 'password_conf' ];
    if ( $pass_new == $pass_conf ) {
        // password changed BEFORE some versions even check the captcha response validity properly
    }
}
```
The core low-level flaw: the CAPTCHA verification step and the password-change logic are not tightly bound — the server largely trusts that if a `Change` POST arrives, the CAPTCHA step happened client-side.

### Burp Suite steps
1. Capture the final POST request that submits the new password (after solving CAPTCHA once, normally, to see the exact parameter set).
2. Send to Repeater.
3. Replay the **exact same request** multiple times, or modify only `password_new`/`password_conf`, **without** re-solving the CAPTCHA.
4. Because the server doesn't tie a *fresh, single-use* CAPTCHA solve to *this specific* password change, the replayed/modified request still succeeds.

### Why it works
The CAPTCHA check (`recaptcha_check_answer`) is only invoked at Low if the step logic is present at all, and even then it's not causally bound to the specific state-change — an attacker who can directly POST the final-step parameters skips the human-verification step entirely.

---

## 🟡 MEDIUM

### Source logic
```php
// Server checks that 'g-recaptcha-response' equals literally "hidd3n_valu3" (a hardcoded bypass value left in for demo)
if( $_POST[ 'g-recaptcha-response' ] == 'hidd3n_valu3' ) {
    // treated as CAPTCHA solved
}
```
DVWA's Medium level intentionally demonstrates a **hardcoded/predictable bypass token**.

### Burp Suite bypass
1. Intercept the password-change POST.
2. Set the body parameter directly:
   ```
   g-recaptcha-response=hidd3n_valu3&password_new=hacked123&password_conf=hacked123&Change=Change
   ```
3. Send via Repeater — password changes without ever loading/solving a real CAPTCHA.

### Why the bypass works
A hardcoded "magic value" left in server logic (often for testing/demo purposes) becomes a permanent bypass once discovered — this mirrors real-world incidents where debug/test backdoors ship to production.

---

## 🔴 HIGH

### Source logic
```php
// Step 1: verify CAPTCHA via Google's API server-side
$resp = recaptcha_check_answer(..., $_POST['g-recaptcha-response']);
if ($resp->is_valid) {
    $_SESSION['captcha_passed'] = true;
}
// Step 2 (separate request): only allow password change if $_SESSION['captcha_passed'] is true
if( $_SESSION['captcha_passed'] === true && isset($_POST['Change']) ) {
    // change password, then reset captcha_passed = false
}
```

### Burp Suite exercise
1. This flow is stronger — it requires an actual server-verified CAPTCHA solve (via Google) tied to the session before Step 2 will succeed.
2. Test for **logic flaws**: does the server properly reset `captcha_passed` to `false` after use, or can Step 2 be replayed multiple times reusing one solved session flag? Use Repeater to resend the password-change POST twice in a row.
3. If the flag isn't reset, you can change the password multiple times off a single CAPTCHA solve — a race-condition/logic bug worth documenting even at High.

### Why it's stronger but not foolproof
Server-side verification against Google's API removes the "hardcoded token" flaw, but session-state handling bugs (failing to invalidate the "passed" flag after one use) can still create a **replay window**.

---

## ⚪ IMPOSSIBLE

### Source logic
```php
// CAPTCHA solved and verified server-side via Google reCAPTCHA API
// Flag is single-use: unset immediately after the password change completes
// CSRF token required
// Current password re-entry required
if( $resp->is_valid && checkToken(...) ) {
    // update password, verify current password first, then unset captcha session flag
}
```

### Why the attack fails
- Genuine server-side CAPTCHA verification (not a hardcoded string) requires solving an actual challenge Google validates.
- Single-use session flag prevents replay of the password-change step.
- CSRF token blocks forged cross-site submissions.
- Current-password confirmation adds re-authentication.

### Burp Suite exercise
Replay any captured request from Low/Medium/High — all fail due to missing/expired CSRF token, unset captcha flag, or wrong current password.

---

## Root Cause Analysis
Insecure CAPTCHA implementations fail because (a) verification isn't performed server-side against the actual CAPTCHA provider, (b) verification isn't causally/atomically tied to the specific sensitive action, or (c) session state around "verified" isn't properly invalidated after single use.

## Defensive Takeaways
- Always verify CAPTCHA responses server-side against the provider's API — never trust a client-supplied "solved" flag.
- Bind the verification to the specific action/session, single-use only.
- Never leave hardcoded bypass tokens in production code paths.
- Combine CAPTCHA with other controls (CSRF tokens, re-authentication) — it's not a substitute for them.

---
⬅ [Back: File Upload](05-file-upload.md) | ➡ [Next: SQL Injection](07-sql-injection.md)
