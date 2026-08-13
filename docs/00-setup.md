# Chapter 00 — Lab Setup: DVWA + Burp Suite

## Objective
Build an isolated, legal practice lab: DVWA running locally + Burp Suite configured as an intercepting proxy between your browser and DVWA.

---

## 1. Install DVWA

### Option A — Docker (fastest, recommended)

```bash
docker pull vulnerables/web-dvwa
docker run --rm -it -p 80:80 vulnerables/web-dvwa
```

Then browse to `http://localhost/setup.php`.

Alternative maintained image:
```bash
git clone https://github.com/digininja/DVWA.git
cd DVWA
docker compose up -d
```

### Option B — XAMPP / LAMP (manual)

```bash
sudo apt update
sudo apt install -y apache2 mysql-server php php-mysqli php-gd libapache2-mod-php
git clone https://github.com/digininja/DVWA.git
sudo mv DVWA /var/www/html/dvwa
sudo chown -R www-data:www-data /var/www/html/dvwa
sudo chmod -R 755 /var/www/html/dvwa
```

Copy config:
```bash
cd /var/www/html/dvwa/config
cp config.inc.php.dist config.inc.php
```

Edit `config.inc.php` and set DB credentials:
```php
$_DVWA[ 'db_server' ]   = '127.0.0.1';
$_DVWA[ 'db_database' ] = 'dvwa';
$_DVWA[ 'db_user' ]     = 'dvwa';
$_DVWA[ 'db_password' ] = 'p@ssw0rd';
```

Create the DB user:
```bash
sudo mysql -u root -p
CREATE DATABASE dvwa;
CREATE USER 'dvwa'@'localhost' IDENTIFIED BY 'p@ssw0rd';
GRANT ALL PRIVILEGES ON dvwa.* TO 'dvwa'@'localhost';
FLUSH PRIVILEGES;
EXIT;
```

Start services and initialize DB:
```bash
sudo service apache2 start
sudo service mysql start
```
Browse to `http://localhost/dvwa/setup.php` → click **Create / Reset Database**.

### Login
Default credentials: `admin` / `password`

---

## 2. Set the DVWA Security Level

Navigate to **DVWA Security** tab (left menu) after login → choose **Low / Medium / High / Impossible** → **Submit**.

> Every chapter in this guide expects you to switch this level between steps. The PHP source for each level is visible under **DVWA Security → View Source** button.

---

## 3. Install & Configure Burp Suite

### Install
Download Burp Suite Community Edition: https://portswigger.net/burp/communitydownload

```bash
chmod +x burpsuite_community_linux.sh
./burpsuite_community_linux.sh
```

### Configure browser proxy
1. Open Burp → **Proxy** tab → **Options** → confirm listener is `127.0.0.1:8080`.
2. In Firefox: `Settings → Network Settings → Manual proxy configuration`
   - HTTP Proxy: `127.0.0.1` Port: `8080`
   - Check "Also use this proxy for HTTPS"
   - (Recommended) Install **FoxyProxy** extension to toggle quickly.

### Install Burp's CA Certificate (needed for HTTPS targets; optional for local HTTP-only DVWA)
1. With proxy enabled, browse to `http://burp` (or `http://burpsuite`).
2. Click **CA Certificate** → download `cacert.der`.
3. Firefox: `Settings → Privacy & Security → Certificates → View Certificates → Import` → select the file → trust for websites.

### Test the intercept
1. Burp → **Proxy → Intercept** → toggle **Intercept is on**.
2. Visit `http://localhost/dvwa/login.php` in the proxied browser.
3. You should see the raw HTTP request appear in Burp.
4. Turn Intercept **off** for normal browsing; turn **on** only when you want to capture/modify a specific request.

---

## 4. Key Burp Suite Tabs You'll Use

| Tab | Purpose |
|-----|---------|
| **Proxy** | Intercept & modify live HTTP(S) requests |
| **Repeater** | Manually resend/edit a captured request repeatedly |
| **Intruder** | Automate payload fuzzing (brute force, injection sweeps) |
| **Decoder** | Encode/decode (URL, Base64, HTML, Hex) |
| **Comparer** | Diff two responses/requests |
| **Target → Site map** | Passive crawl map of the app |

Send a captured request to Repeater/Intruder with **right-click → Send to Repeater / Send to Intruder**, or `Ctrl+R` / `Ctrl+I`.

---

## 5. Sanity Checklist Before Each Chapter

- [ ] DVWA login works (`admin` / `password`)
- [ ] Correct **Security Level** selected for the exercise
- [ ] Burp proxy listener running on `127.0.0.1:8080`
- [ ] Browser proxy correctly points to Burp
- [ ] `PHPSESSID` and `security` cookies present in Burp's captured requests (DVWA tracks level via cookie)

---

Next: **[Chapter 01 — Brute Force →](01-brute-force.md)**
