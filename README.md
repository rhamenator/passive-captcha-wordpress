# Passive CAPTCHA Hardened (Generic Form Support - Multisite Ready)

**Version:** 4.0
**Author:** Rich Hamilton
**Requires at least:** 5.0 (Assumed based on modern WP functions used)
**Tested up to:** (Specify latest tested WP version)
**License:** GPLv2 or later
**License URI:** <https://www.gnu.org/licenses/gpl-2.0.html>

Passive, non-interactive CAPTCHA protection designed for generic WordPress form integration. Includes advanced bot detection, rate limiting, webhook escalation, multi-site support, and automated tests. Requires manual integration steps.

## Features

This plugin protects your form submissions using a multi-layered approach with no visible challenge to the user:

* **Timing Analysis:** Checks time spent on the page before submission.
* **JavaScript Execution:** Verifies the client can execute JavaScript to generate a token.
* **Interaction Detection:** Checks for basic user interactions like mouse movement or key presses.
* **Headless Browser Detection:** Identifies common headless browser signatures (`navigator.webdriver`, etc.).
* **Navigator Property Analysis:** Checks for inconsistencies in browser properties often found in bots.
* **WebGL Fingerprinting:** Generates a hash based on the browser's WebGL rendering capabilities.
* **Nonce Validation:** Prevents replay attacks using WordPress nonces tied to the user session.
* **Session Tying:** Uses temporary server-side transients to validate session lifetime.
* **IP Address + User Agent Binding:** Ensures the token is submitted from the same IP/UA combination that generated it.
* **JA3 TLS Fingerprinting Integration:** Validates the TLS handshake signature passed via a webserver header (requires server setup).
* **Rate Limiting & Auto-Ban:** Temporarily blocks IPs after repeated validation failures.
* **IP Whitelisting/Blacklisting:** Allows specific IPs to bypass checks or be blocked outright.
* **Webhook Escalation:** Sends notifications (with HMAC signature) to a specified URL upon validation failures.
* **Multisite Compatible:** Settings are managed network-wide.

## Installation

1. **Download:** Obtain the plugin zip file or directory (`passive-captcha-hardened`).
2. **Upload:**
    * Go to your WordPress Admin Dashboard -> Plugins -> Add New -> Upload Plugin. Choose the zip file.
    * OR, upload the `passive-captcha-hardened` directory to your `/wp-content/plugins/` directory via SFTP/FTP.
3. **Activate:**
    * **Single Site:** Go to Plugins -> Installed Plugins and click "Activate" for "Passive CAPTCHA Hardened...".
    * **Multisite Network:** Go to Network Admin -> Plugins and click "Network Activate" for "Passive CAPTCHA Hardened...".

## Configuration & Usage (Manual Integration Required)

This plugin requires manual steps to integrate it with your forms:

1. **Add Hidden Field to Your Form:**
    * In the HTML source of any form you want to protect, add the following hidden input field:

        ```html
        <input type="hidden" name="pch_captcha_token" value="">
        ```

    * The plugin's JavaScript will automatically find this field (by its `name` attribute) on page load and attempt to populate its value after running client-side checks.

2. **Call Verification Function in PHP:**
    * In your PHP code that handles the form submission (this could be in your theme's `functions.php`, another plugin, or a custom page template), you **must** call the `pch_verify_submission()` function *before* processing the form data.
    * Check the return value:
        * `true` indicates the CAPTCHA validation passed.
        * A `WP_Error` object indicates the validation failed. You can get the reason using `$error->get_error_message()`.
    * **Example PHP Form Handler:**

        ```php
        <?php
        // Example function to handle a POST request
        function my_custom_form_handler() {
            // Check if your specific form was submitted
            if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['my_submit_button_name'])) {

                // --- Passive CAPTCHA Verification ---
                if (function_exists('pch_verify_submission')) {
                    $captcha_result = pch_verify_submission();
                    if (is_wp_error($captcha_result)) {
                        // CAPTCHA Failed: Stop processing and show error
                        $error_message = $captcha_result->get_error_message();
                        // You might want to redirect back to the form with an error message
                        wp_die('CAPTCHA Verification Failed: ' . esc_html($error_message));
                        return; // Stop execution
                    }
                    // CAPTCHA Passed! Continue below.
                } else {
                    // Function doesn't exist - plugin likely inactive
                    wp_die('Required security component is inactive.');
                    return; // Stop execution
                }
                // --- End Passive CAPTCHA Verification ---


                // --- Your Form Processing Logic ---
                // If code execution reaches here, CAPTCHA passed.
                // Sanitize and process your other form fields (e.g., $_POST['email'], $_POST['message'])
                // ... (send email, save to database, etc.) ...

                // Redirect or display success message
                wp_redirect('/thank-you-page-url');
                exit;
            }
        }

        // Hook your handler appropriately (e.g., on 'init' or 'template_redirect')
        add_action('init', 'my_custom_form_handler');
        ?>
        ```

3. **Configure Plugin Settings:**
    * Go to your **Network Admin** dashboard (if multisite) or regular Admin dashboard (if single site).
    * Navigate to **Settings -> Passive CAPTCHA**. (Note: On Multisite, this appears under the Network Admin's Settings menu).
    * Adjust the following settings:
        * Rate Limit Threshold & Ban Duration
        * Webhook URL & HMAC Key (for failure notifications)
        * IP Whitelist & Blacklist
    * Click "Save Changes".

## Optional Advanced Setup

### JA3 TLS Fingerprinting

* This feature requires server-level configuration.
* You need to set up your webserver (e.g., NGINX with `ngx_http_lua_module` and `lua-resty-ja3`) to capture the client's JA3 fingerprint during the TLS handshake.
* The webserver must pass this fingerprint to PHP via an HTTP header. The plugin defaults to checking `$_SERVER['HTTP_X_JA3_FINGERPRINT']`. If this header is missing or invalid (and the IP isn't whitelisted), validation will fail.

## For Developers: Running Tests

This plugin includes automated PHPUnit tests to verify its server-side functionality.

### Manual Test Environment Setup

* Requires PHPUnit, a dedicated test database (MySQL/MariaDB), and a copy of the WordPress development files (`wordpress-tests-lib`).
* Follow standard WordPress plugin testing setup procedures.
* Once set up, navigate to the plugin directory (`passive-captcha-hardened`) in your terminal and run the `phpunit` command.

### Docker-Based Test Environment Setup

This method uses Docker and Docker Compose to run tests in an isolated environment. Assumes Docker and Docker Compose are installed. The necessary `Dockerfile`, `docker-compose.yml`, and `Makefile` should be included in the plugin's root directory.

1. **Build Containers:** `make build` (or `docker-compose build`)
2. **Start Services:** `make up` (or `docker-compose up -d wordpress db`)
3. **Install WP Test Library & Configure (Run Once):** `make install-tests`
4. **Run Tests (Clean Workflow):** `make test-reset` (This resets the DB, activates the plugin, and runs tests)
5. **Run Tests (Simple):** `make test` (or `docker-compose run --rm phpunit phpunit`)
6. **Clean Up:** `make down` (or `docker-compose down`)
