# Passive CAPTCHA Hardened for Gravity Forms (Managed Hosting Ready)

**Version:** 3.1
**Author:** Rich Hamilton
**Requires at least:** 5.0 (Assumed based on modern WP functions used)
**Tested up to:** 6.8
**License:** GPLv2 or later
**License URI:** <https://www.gnu.org/licenses/gpl-2.0.html>

Advanced passive, non-interactive CAPTCHA protection designed specifically for Gravity Forms. Blocks bot submissions without user interaction using multiple layers of checks, including improved support for managed hosting environments like Pressable.

## Features

* **Passive Validation:** No visible challenge for users.
* **Client-Side Checks:** Analyzes timing, user interaction (mouse, keyboard, scroll), headless browser signatures, navigator properties, and WebGL fingerprinting.
* **Server-Side Checks:** Verifies WordPress nonces, session tokens (with longer lifespan for better cache compatibility), and IP/User-Agent consistency.
* **Robust IP Detection:** Attempts to identify the real visitor IP behind reverse proxies and CDNs (checks `HTTP_CF_CONNECTING_IP`, `HTTP_X_REAL_IP`, `HTTP_X_FORWARDED_FOR` before `REMOTE_ADDR`).
* **Conditional JA3 Check:** Validates TLS fingerprint via `HTTP_X_JA3_FINGERPRINT` header *only if* provided by the webserver (requires compatible server setup, skipped otherwise).
* **Rate Limiting:** Temporarily blocks IPs after configurable repeated validation failures using WordPress transients.
* **IP Whitelisting/Blacklisting:** Allows specific IPs to bypass checks or be blocked outright via plugin settings.
* **Webhook Notifications:** Sends alerts (with optional HMAC signature) to a specified URL upon validation failures or submissions from banned IPs.
* **Multisite Compatible:** Settings are managed network-wide.
* **Improved Logging:** Logs specific failure reasons to the PHP error log for easier debugging.
* **User-Friendly Errors:** Displays generic error messages to users upon failure.

## Installation

1. **Download:** Obtain the plugin zip file or directory (`passive-captcha-hardened`).
2. **Upload:** Via WordPress Admin (Plugins -> Add New -> Upload) or SFTP/FTP (`/wp-content/plugins/`).
3. **Activate:**
    * **Single Site:** Activate via Plugins -> Installed Plugins.
    * **Multisite:** Network Activate via Network Admin -> Plugins.

## Configuration

1. **Add Hidden Field to Gravity Forms:**
    * Edit the target Gravity Form.
    * Add a **Hidden** field (Standard Fields).
    * Set its **Field Label** to exactly: `CAPTCHA Token`.
    * Save the form.

2. **Configure Plugin Settings:**
    * Navigate to **Settings -> Passive CAPTCHA** (found under Network Admin -> Settings on multisite).
    * Adjust Rate Limit, Ban Duration, Webhook URL/Key, and IP Whitelist/Blacklist settings.
    * Save Changes.

## Usage

Once installed, activated, configured, and the hidden field is added, protection is automatic for the selected Gravity Form(s).

## Optional Advanced Setup

### JA3 TLS Fingerprinting

* Requires server-level configuration (e.g., NGINX+Lua) to capture the JA3 fingerprint and pass it via the `X-JA3-FINGERPRINT` HTTP header.
* The plugin will automatically use this header for validation *if it is present*. If not present (like on standard managed hosting), the check is skipped.

## For Developers: Running Tests

* Includes PHPUnit tests (`tests/` directory).
* Requires a WordPress test environment setup (manual or Docker). See `phpunit.xml` and `tests/bootstrap.php`. Docker setup files (`Dockerfile`, `docker-compose.yml`, `Makefile`) are included for containerized testing.
