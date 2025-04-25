<?php
/**
 * Plugin Name: Passive CAPTCHA Hardened (Generic Form Support - Multisite Ready)
 * Description: Passive CAPTCHA with timing, nonce, JA3 fingerprinting, webhook escalation, multi-site support, and automated tests. Requires manual integration into form handling.
 * Version: 4.0
 * Author: Rich Hamilton
 * Author URI: https:\\www.github.com\rhamenato
 * Network: true
 */

if (!defined('ABSPATH')) {
    exit;
}

// Multi-site aware get_option wrapper
function pch_get_option($option, $default = '') {
    return is_multisite() ? get_site_option($option, $default) : get_option($option, $default);
}

// Multi-site aware update_option wrapper
function pch_update_option($option, $value) {
    return is_multisite() ? update_site_option($option, $value) : update_option($option, $value);
}

// Enqueue JS and session setup - applies to pages where the CAPTCHA might be used
function pch_enqueue_scripts() {
    // Consider adding a check here if you only want scripts loaded on specific pages/posts
    // if (is_page() || is_singular()) { // Example: Load only on pages/single posts
        $token_nonce = wp_create_nonce('pch_captcha_nonce');
        $session_token = bin2hex(random_bytes(16));
        // Store the session token transient with a limited lifespan (e.g., 10 minutes)
        set_transient('pch_' . $session_token, time(), 10 * MINUTE_IN_SECONDS);

        wp_enqueue_script('passive-captcha-hardened', plugin_dir_url(__FILE__) . 'js/passive-captcha.js', [], '4.0', true); // Added version
        // Pass necessary data to the script
        wp_localize_script('passive-captcha-hardened', 'pchData', [
            'nonce' => $token_nonce,
            'sessionToken' => $session_token,
            'ipHash' => sha1(($_SERVER['REMOTE_ADDR'] ?? '127.0.0.1') . ($_SERVER['HTTP_USER_AGENT'] ?? '')), // Use null coalescing
        ]);
    // }
}
add_action('wp_enqueue_scripts', 'pch_enqueue_scripts');

// --- Rate limiting helpers ---
function pch_check_rate_limit($ip) {
    $limit = (int) pch_get_option('pch_rate_limit_threshold', 5); // Ensure integer
    $ban_duration = (int) pch_get_option('pch_ban_duration', 3600); // Ensure integer
    $key = 'pch_fail_' . md5($ip);
    $fails = (int) get_transient($key);
    return ($limit > 0 && $fails >= $limit); // Check if limit is enabled (>0)
}

function pch_register_failure($ip) {
    $ban_duration = (int) pch_get_option('pch_ban_duration', 3600);
    if ($ban_duration <= 0) return; // Don't register if banning is disabled

    $key = 'pch_fail_' . md5($ip);
    $fails = (int) get_transient($key);
    // Increment failure count and update transient expiry
    set_transient($key, $fails + 1, $ban_duration);
}

// --- IP whitelist/blacklist helpers ---
function pch_is_ip_whitelisted($ip) {
    $list = pch_get_option('pch_ip_whitelist', '');
    if (empty($list)) return false;
    // Trim each IP and remove empty lines
    $ips = array_filter(array_map('trim', explode("\n", $list)));
    return in_array($ip, $ips);
}

function pch_is_ip_blacklisted($ip) {
    $list = pch_get_option('pch_ip_blacklist', '');
     if (empty($list)) return false;
    // Trim each IP and remove empty lines
    $ips = array_filter(array_map('trim', explode("\n", $list)));
    return in_array($ip, $ips);
}

// --- Webhook with HMAC signing ---
function pch_send_webhook($payload) {
    $url = pch_get_option('pch_webhook_url');
    $key = pch_get_option('pch_webhook_hmac_key');
    // Only send if URL and Key are configured
    if (empty($url) || empty($key)) {
        return;
    }

    // Ensure payload is an array before encoding
    if (!is_array($payload)) {
        $payload = ['error' => 'Invalid webhook payload type'];
    }

    $body = wp_json_encode($payload); // Use wp_json_encode for better WP compatibility
    if ($body === false) {
         // Handle JSON encoding error if necessary
         return;
    }

    $hmac = hash_hmac('sha256', $body, $key);

    wp_remote_post($url, [
        'timeout'   => 10, // Increased timeout slightly
        'headers'   => [
            'Content-Type' => 'application/json',
            'X-Signature'  => $hmac
        ],
        'body'      => $body,
        'sslverify' => true // Ensure SSL verification is explicitly enabled
    ]);
}

// --- Core Verification Function (Manual Call) ---

/**
 * Verifies the passive CAPTCHA submission.
 * Call this function from your custom form handler *before* processing the form data.
 * Reads data directly from $_POST and $_SERVER globals.
 *
 * @return bool|WP_Error Returns true on success, or a WP_Error object on failure.
 */
function pch_verify_submission() {
    // Retrieve IP and User Agent safely
    $ip = $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1'; // Default IP for safety? Consider implications.
    $ua = $_SERVER['HTTP_USER_AGENT'] ?? '';

    // Retrieve JA3 fingerprint header (ensure server config matches key)
    $ja3_header_key = 'HTTP_X_JA3_FINGERPRINT'; // Standard formatting for X-JA3-Fingerprint
    $ja3_fingerprint = $_SERVER[$ja3_header_key] ?? '';

    // --- IP Blacklist Check ---
    if (pch_is_ip_blacklisted($ip)) {
        // Optional: Send webhook for blacklist hit?
        // pch_send_webhook(['event' => 'ip_blacklisted', 'ip' => $ip, 'ua' => $ua, 'timestamp' => time()]);
        return new WP_Error('ip_blacklisted', __('Your IP is blacklisted.', 'passive-captcha-hardened'));
    }

    // --- IP Whitelist Check ---
    if (pch_is_ip_whitelisted($ip)) {
        return true; // Whitelisted, skip further checks, validation succeeds
    }

    // --- Conditional JA3 Fingerprint Check ---
    // Only perform the check if the JA3 fingerprint header is NOT empty.
    // If the header is empty (e.g., server not configured), skip this specific check.
    if (!empty($ja3_fingerprint)) {
        // The header exists, now check if it's potentially invalid (e.g., too short)
        $min_ja3_len = 10; // Minimum plausible length for a JA3 hash
        if (strlen($ja3_fingerprint) < $min_ja3_len) {
             pch_register_failure($ip); // Register failure if JA3 is present but invalid
             pch_send_webhook([
                 'event' => 'ja3_invalid_format', // More specific event
                 'ip' => $ip,
                 'user_agent' => $ua,
                 'ja3' => $ja3_fingerprint,
                 'timestamp' => time()
                 // Add 'form_identifier' if available/passed from calling context?
             ]);
             return new WP_Error('ja3_invalid_format', __('Security validation failed (JA3 Format).', 'passive-captcha-hardened'));
        }
        // If JA3 header exists and has minimum length, it passes this basic check.
    }
    // --- End Conditional JA3 Check ---


    // --- Rate Limit Check ---
    if (pch_check_rate_limit($ip)) {
        // Optional: Send specific webhook for rate limit hit attempt?
        // pch_send_webhook(['event' => 'rate_limit_hit', 'ip' => $ip, 'ua' => $ua, 'timestamp' => time()]);
        return new WP_Error('rate_limit_exceeded', __('Access temporarily blocked due to high activity.', 'passive-captcha-hardened'));
    }

    // --- Retrieve Submitted Values (Directly from $_POST) ---
    // Ensure these names match what the JS injects
    $submitted_value = $_POST['pch_captcha_token'] ?? null;
    $submitted_nonce = $_POST['pch_nonce'] ?? null;
    $submitted_session = $_POST['pch_session'] ?? null;
    $submitted_iphash = $_POST['pch_iphash'] ?? null;

    // --- Nonce Verification ---
    if (!wp_verify_nonce($submitted_nonce, 'pch_captcha_nonce')) {
        pch_register_failure($ip);
        // pch_send_webhook(['event' => 'nonce_invalid', 'ip' => $ip, 'ua' => $ua, 'timestamp' => time()]);
        return new WP_Error('nonce_invalid', __('Security check failed (Code: N). Please refresh and try again.', 'passive-captcha-hardened'));
    }

    // --- Session Token Verification ---
    $session_transient_key = 'pch_' . $submitted_session;
    if (empty($submitted_session) || !get_transient($session_transient_key)) {
        pch_register_failure($ip);
        // Delete transient just in case it somehow exists but get_transient returned false
        if ($submitted_session) delete_transient($session_transient_key);
        // pch_send_webhook(['event' => 'session_invalid', 'ip' => $ip, 'ua' => $ua, 'timestamp' => time()]);
        return new WP_Error('session_invalid', __('Your session has expired (Code: S). Please refresh and try again.', 'passive-captcha-hardened'));
    }

    // --- IP/User-Agent Hash Verification ---
    // Ensure calculation here matches the one in JS/wp_localize_script
    $expected_iphash = sha1($ip . $ua);
    if ($submitted_iphash !== $expected_iphash) {
        pch_register_failure($ip);
        delete_transient($session_transient_key); // Delete transient on failure
        // pch_send_webhook(['event' => 'ip_ua_mismatch', 'ip' => $ip, 'ua' => $ua, 'submitted_hash' => $submitted_iphash, 'expected_hash' => $expected_iphash, 'timestamp' => time()]);
        return new WP_Error('ip_ua_mismatch', __('Security check failed (Code: M). Please try again.', 'passive-captcha-hardened'));
    }

    // --- Interaction / JS Execution Check ---
    if (empty($submitted_value) || $submitted_value === 'no_interaction') {
        pch_register_failure($ip);
        delete_transient($session_transient_key); // Delete transient on failure
        // pch_send_webhook(['event' => 'no_interaction', 'ip' => $ip, 'ua' => $ua, 'token_value' => $submitted_value, 'timestamp' => time()]);
        return new WP_Error('no_interaction', __('Bot verification failed (Code: I). Please ensure JavaScript is enabled and refresh.', 'passive-captcha-hardened'));
    }

    // --- Token Decoding and Basic Format Check ---
    $decoded = base64_decode($submitted_value, true); // Use strict decoding
    if ($decoded === false || strpos($decoded, ':') === false) {
        pch_register_failure($ip);
        delete_transient($session_transient_key); // Delete transient on failure
        // pch_send_webhook(['event' => 'token_invalid_format', 'ip' => $ip, 'ua' => $ua, 'token_value' => $submitted_value, 'timestamp' => time()]);
        return new WP_Error('token_invalid_format', __('Invalid CAPTCHA token (Code: F). Please refresh and try again.', 'passive-captcha-hardened'));
    }

    // --- Token Content Verification (Timing & Fingerprint Hash) ---
    list($timeSpent, $navigatorHash) = explode(':', $decoded, 2); // Limit split
    // Minimum time (e.g., 3 seconds = 3000ms) and minimum hash length (e.g., 10 chars)
    $min_time = 3000;
    $min_hash_len = 10;
    if (!is_numeric($timeSpent) || $timeSpent < $min_time || strlen($navigatorHash) < $min_hash_len) {
        pch_register_failure($ip);
        delete_transient($session_transient_key); // Delete transient on failure
        // pch_send_webhook(['event' => 'timing_or_fingerprint_invalid', 'ip' => $ip, 'ua' => $ua, 'time' => $timeSpent, 'hash_len' => strlen($navigatorHash), 'timestamp' => time()]);
        return new WP_Error('timing_or_fingerprint_invalid', __('Security check failed (Code: T/H). Please try again.', 'passive-captcha-hardened'));
    }

    // --- ALL CHECKS PASSED ---
    delete_transient($session_transient_key); // Delete the used session transient *only* on full success
    return true; // Indicate successful validation
}

// --- Admin UI ---
function pch_add_admin_menu() {
     // Add to Network Settings page for multisite
     add_submenu_page(
        'settings.php',             // Parent slug (Network Admin -> Settings)
        __('Passive CAPTCHA Settings', 'passive-captcha-hardened'), // Page Title
        __('Passive CAPTCHA', 'passive-captcha-hardened'),          // Menu Title
        'manage_network_options',   // Capability Required (Network Admin)
        'pch-settings',             // Menu Slug
        'pch_settings_page'         // Callback Function
     );
}
// Hook into the network admin menu for multisite setup
add_action('network_admin_menu', 'pch_add_admin_menu');

// If not multisite, add to regular options menu (optional, depends if you want non-network admins to see it on single site)
// function pch_add_options_menu_single_site() {
//     if (!is_multisite()) {
//         add_options_page(
//             __('Passive CAPTCHA Settings', 'passive-captcha-hardened'),
//             __('Passive CAPTCHA', 'passive-captcha-hardened'),
//             'manage_options', // Standard capability for single site
//             'pch-settings',
//             'pch_settings_page'
//         );
//     }
// }
// add_action('admin_menu', 'pch_add_options_menu_single_site');


function pch_settings_page() {
    // Check if the user has the required capability
    if (!current_user_can(is_multisite() ? 'manage_network_options' : 'manage_options')) {
        wp_die(__('Sorry, you are not allowed to access this page.'));
    }

    // Process form submission
    if (isset($_POST['pch_settings_nonce']) && wp_verify_nonce($_POST['pch_settings_nonce'], 'pch_save_settings')) {
        // Use pch_update_option which handles multisite check internally
        pch_update_option('pch_rate_limit_threshold', intval($_POST['rate_limit']));
        pch_update_option('pch_ban_duration', intval($_POST['ban_duration']));
        pch_update_option('pch_webhook_url', sanitize_text_field(esc_url_raw($_POST['webhook_url']))); // Sanitize URL
        pch_update_option('pch_webhook_hmac_key', sanitize_text_field($_POST['hmac_key'])); // Key is text
        pch_update_option('pch_ip_whitelist', sanitize_textarea_field($_POST['ip_whitelist']));
        pch_update_option('pch_ip_blacklist', sanitize_textarea_field($_POST['ip_blacklist']));

        // Add a confirmation message
        echo '<div id="message" class="updated notice is-dismissible"><p>' . __('Settings saved.', 'passive-captcha-hardened') . '</p></div>';
    }

    // Retrieve current settings using multi-site aware function
    $rate_limit = pch_get_option('pch_rate_limit_threshold', 5);
    $ban_duration = pch_get_option('pch_ban_duration', 3600);
    $webhook_url = pch_get_option('pch_webhook_url', '');
    $hmac_key = pch_get_option('pch_webhook_hmac_key', '');
    $ip_whitelist = pch_get_option('pch_ip_whitelist', '');
    $ip_blacklist = pch_get_option('pch_ip_blacklist', '');

    ?>
    <div class="wrap">
        <h1><?php _e('Passive CAPTCHA Settings', 'passive-captcha-hardened'); ?></h1>

        <p><?php _e('This plugin provides passive bot protection for forms. It requires manual integration.', 'passive-captcha-hardened'); ?></p>
        <h2><?php _e('Integration Instructions', 'passive-captcha-hardened'); ?></h2>
        <ol>
             <li><?php printf(
                 __('Add the following hidden field inside any HTML form you want to protect: %s', 'passive-captcha-hardened'),
                 '<code>&lt;input type="hidden" name="pch_captcha_token" value=""&gt;</code>'
             ); ?></li>
             <li><?php printf(
                 __('In your PHP form processing code, call the %1$s function before handling the data. Check the return value (it returns %2$s on success, or a %3$s object on failure). Example: %4$s', 'passive-captcha-hardened'),
                 '<code>pch_verify_submission()</code>', '<code>true</code>', '<code>WP_Error</code>',
                 '<br><pre><code>if (function_exists(\'pch_verify_submission\')) {<br>    $captcha_result = pch_verify_submission();<br>    if (is_wp_error($captcha_result)) {<br>        // Handle CAPTCHA failure (e.g., display $captcha_result->get_error_message())<br>        wp_die("CAPTCHA check failed: " . esc_html($captcha_result->get_error_message()));<br>        return;<br>    }<br>} else {<br>    // Plugin might be inactive<br>    wp_die("Security check component inactive.");<br>    return;<br>}<br>// CAPTCHA passed, continue processing form...</code></pre>'
                 ); ?></li>
        </ol>

        <hr>

        <form method="post" action="">
            <?php // Add nonce field for security ?>
            <input type="hidden" name="pch_settings_nonce" value="<?php echo wp_create_nonce('pch_save_settings'); ?>">

            <h2><?php _e('Behavior Settings', 'passive-captcha-hardened'); ?></h2>
            <table class="form-table" role="presentation">
                <tbody>
                    <tr>
                        <th scope="row"><label for="rate_limit"><?php _e('Rate Limit Threshold', 'passive-captcha-hardened'); ?></label></th>
                        <td><input name="rate_limit" type="number" id="rate_limit" value="<?php echo esc_attr($rate_limit); ?>" class="regular-text">
                        <p class="description"><?php _e('Number of failed attempts from an IP before temporary banning (0 to disable).', 'passive-captcha-hardened'); ?></p></td>
                    </tr>
                    <tr>
                        <th scope="row"><label for="ban_duration"><?php _e('Ban Duration (seconds)', 'passive-captcha-hardened'); ?></label></th>
                        <td><input name="ban_duration" type="number" id="ban_duration" value="<?php echo esc_attr($ban_duration); ?>" class="regular-text">
                        <p class="description"><?php _e('How long an IP remains banned after hitting the threshold (e.g., 3600 = 1 hour).', 'passive-captcha-hardened'); ?></p></td>
                    </tr>
                </tbody>
            </table>

             <h2><?php _e('Webhook Settings', 'passive-captcha-hardened'); ?></h2>
             <table class="form-table" role="presentation">
                 <tbody>
                     <tr>
                         <th scope="row"><label for="webhook_url"><?php _e('Webhook URL', 'passive-captcha-hardened'); ?></label></th>
                         <td><input name="webhook_url" type="url" id="webhook_url" value="<?php echo esc_attr($webhook_url); ?>" class="large-text">
                         <p class="description"><?php _e('URL to send failure notifications (POST requests with JSON payload). Leave blank to disable.', 'passive-captcha-hardened'); ?></p></td>
                     </tr>
                     <tr>
                         <th scope="row"><label for="hmac_key"><?php _e('Webhook HMAC Key', 'passive-captcha-hardened'); ?></label></th>
                         <td><input name="hmac_key" type="text" id="hmac_key" value="<?php echo esc_attr($hmac_key); ?>" class="regular-text">
                         <p class="description"><?php _e('A secret key to sign webhook payloads (using SHA256 HMAC). Required if Webhook URL is set.', 'passive-captcha-hardened'); ?></p></td>
                     </tr>
                 </tbody>
            </table>

             <h2><?php _e('IP Address Management', 'passive-captcha-hardened'); ?></h2>
             <table class="form-table" role="presentation">
                 <tbody>
                      <tr>
                         <th scope="row"><label for="ip_whitelist"><?php _e('IP Whitelist', 'passive-captcha-hardened'); ?></label></th>
                         <td><textarea name="ip_whitelist" id="ip_whitelist" rows="5" cols="50" class="large-text"><?php echo esc_textarea($ip_whitelist); ?></textarea>
                         <p class="description"><?php _e('One IP address per line. Submissions from these IPs will bypass all checks.', 'passive-captcha-hardened'); ?></p></td>
                     </tr>
                     <tr>
                         <th scope="row"><label for="ip_blacklist"><?php _e('IP Blacklist', 'passive-captcha-hardened'); ?></label></th>
                         <td><textarea name="ip_blacklist" id="ip_blacklist" rows="5" cols="50" class="large-text"><?php echo esc_textarea($ip_blacklist); ?></textarea>
                         <p class="description"><?php _e('One IP address per line. Submissions from these IPs will always be blocked.', 'passive-captcha-hardened'); ?></p></td>
                     </tr>
                 </tbody>
            </table>

            <?php submit_button(); // Standard WordPress submit button ?>
        </form>
    </div>
    <?php
}

// Add internationalization support
function pch_load_textdomain() {
    load_plugin_textdomain('passive-captcha-hardened', false, dirname(plugin_basename(__FILE__)) . '/languages/');
}
add_action('plugins_loaded', 'pch_load_textdomain');

?>