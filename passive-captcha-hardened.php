<?php
/**
 * Plugin Name: Passive CAPTCHA Hardened (Generic Form Support - Managed Hosting Ready)
 * Description: Configurable passive CAPTCHA for any WordPress form with timing, nonce, session, IP/UA checks, rate limiting, webhooks, IP lists, conditional JA3, improved IP detection, admin log viewer, and ban clearing. Requires manual integration.
 * Version: 4.4
 * Author: Rich Hamilton
 * Author URI: https://github.com/rhamenator
 * Network: true
 */

if (!defined('ABSPATH')) {
    exit; // Exit if accessed directly.
}

// --- Core Helper Functions ---
// pch_get_option, pch_update_option, pch_log_event, pch_get_visitor_ip - remain the same
function pch_get_option($option, $default = '') { return is_multisite() ? get_site_option($option, $default) : get_option($option, $default); }
function pch_update_option($option, $value) { return is_multisite() ? update_site_option($option, $value) : update_option($option, $value); }
function pch_log_event($message) { error_log("[Passive CAPTCHA] " . $message); $log_option_key = 'pch_recent_logs'; $max_log_entries = 50; $logs = is_multisite() ? get_site_option($log_option_key, []) : get_option($log_option_key, []); if (!is_array($logs)) { $logs = []; } $timestamp = current_time('mysql'); array_unshift($logs, "[$timestamp] " . $message); if (count($logs) > $max_log_entries) { $logs = array_slice($logs, 0, $max_log_entries); } if (is_multisite()) { update_site_option($log_option_key, $logs); } else { update_option($log_option_key, $logs, false); } }
function pch_get_visitor_ip() { $custom_header_key_raw = pch_get_option('pch_custom_ip_header', ''); $custom_header_key = preg_replace('/[^A-Z0-9_\-]/', '', strtoupper($custom_header_key_raw)); $ip_headers = []; if (!empty($custom_header_key)) { $ip_headers[] = $custom_header_key; } $ip_headers = array_merge($ip_headers, [ 'HTTP_CF_CONNECTING_IP', 'HTTP_X_REAL_IP', 'HTTP_CLIENT_IP', 'HTTP_X_FORWARDED_FOR', 'REMOTE_ADDR' ]); $ip_headers = array_unique($ip_headers); foreach ($ip_headers as $header) { if (!empty($_SERVER[$header])) { if ($header === 'HTTP_X_FORWARDED_FOR') { $ip_list = explode(',', $_SERVER[$header]); foreach ($ip_list as $ip_candidate) { $ip = trim($ip_candidate); if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) { return $ip; } if (filter_var(trim($ip_list[0]), FILTER_VALIDATE_IP)) { return trim($ip_list[0]); } } continue; } else { $ip = trim($_SERVER[$header]); } if (filter_var($ip, FILTER_VALIDATE_IP)) { return $ip; } } } return $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1'; }

// --- Script Enqueueing ---
// pch_enqueue_scripts - remains the same
function pch_enqueue_scripts() { /* ... same as previous generic version ... */ if (is_page() || is_singular()) { $token_nonce = wp_create_nonce('pch_captcha_nonce'); $session_token = bin2hex(random_bytes(16)); $visitor_ip = pch_get_visitor_ip(); $user_agent = $_SERVER['HTTP_USER_AGENT'] ?? ''; $session_lifetime_seconds = (int) pch_get_option('pch_session_lifetime', 12 * HOUR_IN_SECONDS); if ($session_lifetime_seconds <= 0) { $session_lifetime_seconds = 12 * HOUR_IN_SECONDS; } set_transient('pch_' . $session_token, time(), $session_lifetime_seconds); wp_enqueue_script('passive-captcha-hardened', plugin_dir_url(__FILE__) . 'js/passive-captcha.js', [], '4.4', true); $enable_webgl = (bool) pch_get_option('pch_enable_webgl', true); $enable_math = (bool) pch_get_option('pch_enable_math', true); wp_localize_script('passive-captcha-hardened', 'pchData', [ 'nonce' => $token_nonce, 'sessionToken' => $session_token, 'ipHash' => sha1($visitor_ip . $user_agent), 'enableWebGL' => $enable_webgl, 'enableMath' => $enable_math, ]); } }
add_action('wp_enqueue_scripts', 'pch_enqueue_scripts');

// --- Rate limiting helpers ---
// pch_check_rate_limit, pch_register_failure - remain the same
function pch_check_rate_limit($ip) { $limit = (int) pch_get_option('pch_rate_limit_threshold', 5); $ban_duration = (int) pch_get_option('pch_ban_duration', 3600); if ($limit <= 0) return false; $key = 'pch_fail_' . md5($ip); $fails = (int) get_transient($key); return $fails >= $limit; }
function pch_register_failure($ip) { $ban_duration = (int) pch_get_option('pch_ban_duration', 3600); if ($ban_duration <= 0) return; $key = 'pch_fail_' . md5($ip); $fails = (int) get_transient($key); set_transient($key, $fails + 1, $ban_duration); }

// --- IP whitelist/blacklist helpers ---
// pch_is_ip_whitelisted, pch_is_ip_blacklisted - remain the same
function pch_is_ip_whitelisted($ip) { $list = pch_get_option('pch_ip_whitelist', ''); if (empty($list)) return false; $ips = array_filter(array_map('trim', explode("\n", $list))); return in_array($ip, $ips); }
function pch_is_ip_blacklisted($ip) { $list = pch_get_option('pch_ip_blacklist', ''); if (empty($list)) return false; $ips = array_filter(array_map('trim', explode("\n", $list))); return in_array($ip, $ips); }

// --- Webhook with HMAC signing ---
// pch_send_webhook - remains the same
function pch_send_webhook($payload) { $url = pch_get_option('pch_webhook_url'); $key = pch_get_option('pch_webhook_hmac_key'); if (empty($url) || empty($key)) { return; } if (!is_array($payload)) { $payload = ['error' => 'Invalid webhook payload type']; } $body = wp_json_encode($payload); if ($body === false) { return; } $hmac = hash_hmac('sha256', $body, $key); wp_remote_post($url, [ 'timeout' => 10, 'headers' => [ 'Content-Type' => 'application/json', 'X-Signature' => $hmac ], 'body' => $body, 'sslverify' => true ]); }

// --- Core Verification Function (Manual Call) ---
// pch_verify_submission - remains the same (uses pch_log_event now)
function pch_verify_submission() {
    $ip = pch_get_visitor_ip(); $ua = $_SERVER['HTTP_USER_AGENT'] ?? '';
    $user_error_message = __('Security check failed. Please refresh the page and try again.', 'passive-captcha-hardened');
    $ja3_header_key = 'HTTP_X_JA3_FINGERPRINT'; $ja3_fingerprint = $_SERVER[$ja3_header_key] ?? '';
    if (pch_is_ip_blacklisted($ip)) { pch_log_event("Generic Failure: IP Blacklisted. IP: {$ip}, UA: {$ua}"); return new WP_Error('ip_blacklisted', $user_error_message); }
    if (pch_is_ip_whitelisted($ip)) { return true; }
    if (!empty($ja3_fingerprint)) { $min_ja3_len = 10; if (strlen($ja3_fingerprint) < $min_ja3_len) { pch_register_failure($ip); pch_log_event("Generic Failure: JA3 Invalid Format. IP: {$ip}, UA: {$ua}, JA3: {$ja3_fingerprint}"); pch_send_webhook(['event' => 'ja3_invalid_format', 'ip' => $ip, 'user_agent' => $ua, 'ja3' => $ja3_fingerprint, 'timestamp' => time()]); return new WP_Error('ja3_invalid_format', $user_error_message); } }
    if (pch_check_rate_limit($ip)) { pch_log_event("Generic Failure: Rate Limit Exceeded. IP: {$ip}, UA: {$ua}"); return new WP_Error('rate_limit_exceeded', __('Access temporarily blocked due to high activity.', 'passive-captcha-hardened')); }
    $submitted_value = $_POST['pch_captcha_token'] ?? null; $submitted_nonce = $_POST['pch_nonce'] ?? null; $submitted_session = $_POST['pch_session'] ?? null; $submitted_iphash = $_POST['pch_iphash'] ?? null;
    if (!wp_verify_nonce($submitted_nonce, 'pch_captcha_nonce')) { pch_register_failure($ip); pch_log_event("Generic Failure: Nonce Invalid. IP: {$ip}, UA: {$ua}"); return new WP_Error('nonce_invalid', $user_error_message); }
    $session_transient_key = 'pch_' . $submitted_session; if (empty($submitted_session) || !get_transient($session_transient_key)) { pch_register_failure($ip); if ($submitted_session) delete_transient($session_transient_key); pch_log_event("Generic Failure: Session Invalid/Expired. IP: {$ip}, UA: {$ua}, Session: {$submitted_session}"); return new WP_Error('session_invalid', $user_error_message); }
    $expected_iphash = sha1($ip . $ua); if ($submitted_iphash !== $expected_iphash) { pch_register_failure($ip); delete_transient($session_transient_key); pch_log_event("Generic Failure: IP/UA Mismatch. IP: {$ip}, UA: {$ua}, Submitted: {$submitted_iphash}, Expected: {$expected_iphash}"); return new WP_Error('ip_ua_mismatch', $user_error_message); }
    if (empty($submitted_value) || $submitted_value === 'no_interaction') { pch_register_failure($ip); delete_transient($session_transient_key); pch_log_event("Generic Failure: No Interaction/JS Fail. IP: {$ip}, UA: {$ua}, Token: {$submitted_value}"); return new WP_Error('no_interaction', $user_error_message); }
    $decoded = base64_decode($submitted_value, true); if ($decoded === false || strpos($decoded, ':') === false) { pch_register_failure($ip); delete_transient($session_transient_key); pch_log_event("Generic Failure: Invalid Token Format. IP: {$ip}, UA: {$ua}, Token: {$submitted_value}"); return new WP_Error('token_invalid_format', $user_error_message); }
    list($timeSpent, $navigatorHash) = explode(':', $decoded, 2); $min_time = (int) pch_get_option('pch_min_time_threshold', 3000); $min_hash_len = (int) pch_get_option('pch_min_hash_length', 10); if ($min_time <= 0) { $min_time = 3000; } if ($min_hash_len <= 0) { $min_hash_len = 10; }
    if (!is_numeric($timeSpent) || $timeSpent < $min_time || strlen($navigatorHash) < $min_hash_len) { pch_register_failure($ip); delete_transient($session_transient_key); pch_log_event("Generic Failure: Timing/Fingerprint Invalid. IP: {$ip}, UA: {$ua}, Time: {$timeSpent} (Min: {$min_time}), HashLen: " . strlen($navigatorHash) . " (Min: {$min_hash_len})"); return new WP_Error('timing_or_fingerprint_invalid', $user_error_message); }
    delete_transient($session_transient_key); return true;
}

// --- Admin UI ---
// pch_add_admin_menu_links, pch_add_action_links - remain the same
function pch_add_admin_menu_links() { if (is_multisite()) { add_submenu_page('settings.php', __('Passive CAPTCHA Settings', 'passive-captcha-hardened'), __('Passive CAPTCHA', 'passive-captcha-hardened'), 'manage_network_options', 'pch-settings', 'pch_settings_page'); } else { add_options_page(__('Passive CAPTCHA Settings', 'passive-captcha-hardened'), __('Passive CAPTCHA', 'passive-captcha-hardened'), 'manage_options', 'pch-settings', 'pch_settings_page'); } }
add_action(is_multisite() ? 'network_admin_menu' : 'admin_menu', 'pch_add_admin_menu_links');
function pch_add_action_links ( $links ) { $capability = is_multisite() ? 'manage_network_options' : 'manage_options'; if (current_user_can($capability)) { $settings_url = is_multisite() ? network_admin_url('settings.php?page=pch-settings') : admin_url('options-general.php?page=pch-settings'); $settings_link = '<a href="' . esc_url($settings_url) . '">' . __('Settings', 'passive-captcha-hardened') . '</a>'; array_unshift( $links, $settings_link ); } return $links; }
add_filter( 'plugin_action_links_' . plugin_basename( __FILE__ ), 'pch_add_action_links' );

/**
 * Renders the settings page HTML with new options and log viewer/clear buttons.
 */
function pch_settings_page() {
    global $wpdb; // Needed for direct DB query
    $capability = is_multisite() ? 'manage_network_options' : 'manage_options';
    if (!current_user_can($capability)) { wp_die(__('Sorry, you are not allowed to access this page.')); }

    $message = ''; // Feedback messages

    // Handle Clear Log action
    if (isset($_POST['pch_clear_log']) && isset($_POST['pch_clear_log_nonce']) && wp_verify_nonce($_POST['pch_clear_log_nonce'], 'pch_clear_log_action')) {
        if (current_user_can($capability)) {
            pch_update_option('pch_recent_logs', []);
            $message = __('Recent log entries cleared.', 'passive-captcha-hardened');
            pch_log_event("Admin Action: Recent logs cleared by user ID " . get_current_user_id());
        } else { $message = __('Error: Insufficient permissions to clear logs.', 'passive-captcha-hardened'); }
        wp_safe_redirect(add_query_arg('pch_message', urlencode($message), wp_get_referer())); exit;
    }

    // Handle Clear Bans action
    if (isset($_POST['pch_clear_bans']) && isset($_POST['pch_clear_bans_nonce']) && wp_verify_nonce($_POST['pch_clear_bans_nonce'], 'pch_clear_bans_action')) {
         if (current_user_can($capability)) {
            $transient_prefix = '_transient_pch_fail_';
            $sql = $wpdb->prepare("SELECT option_name FROM {$wpdb->options} WHERE option_name LIKE %s", $transient_prefix . '%');
            $transient_keys = $wpdb->get_col($sql);
            $deleted_count = 0;
            if (!empty($transient_keys)) {
                foreach ($transient_keys as $key) {
                    if (strpos($key, $transient_prefix) === 0) {
                        $transient_name = substr($key, strlen('_transient_'));
                        if (delete_transient($transient_name)) { $deleted_count++; }
                    }
                }
            }
            $message = sprintf(__('Cleared %d rate limit ban entries.', 'passive-captcha-hardened'), $deleted_count);
            pch_log_event("Admin Action: All rate limit bans cleared by user ID " . get_current_user_id() . ". Cleared count: " . $deleted_count);
        } else { $message = __('Error: Insufficient permissions to clear bans.', 'passive-captcha-hardened'); }
        wp_safe_redirect(add_query_arg('pch_message', urlencode($message), wp_get_referer())); exit;
    }

    // Process main settings form submission
    if (isset($_POST['pch_settings_nonce']) && wp_verify_nonce($_POST['pch_settings_nonce'], 'pch_save_settings')) {
        // Save all settings...
        pch_update_option('pch_rate_limit_threshold', intval($_POST['rate_limit']));
        pch_update_option('pch_ban_duration', intval($_POST['ban_duration']));
        pch_update_option('pch_session_lifetime', intval($_POST['session_lifetime']));
        pch_update_option('pch_min_time_threshold', intval($_POST['min_time_threshold']));
        pch_update_option('pch_min_hash_length', intval($_POST['min_hash_length']));
        pch_update_option('pch_enable_webgl', isset($_POST['enable_webgl']) ? 1 : 0);
        pch_update_option('pch_enable_math', isset($_POST['enable_math']) ? 1 : 0);
        pch_update_option('pch_webhook_url', sanitize_text_field(esc_url_raw($_POST['webhook_url'])));
        pch_update_option('pch_webhook_hmac_key', sanitize_text_field($_POST['hmac_key']));
        pch_update_option('pch_custom_ip_header', sanitize_text_field(strtoupper(str_replace('-', '_', $_POST['custom_ip_header']))));
        pch_update_option('pch_ip_whitelist', sanitize_textarea_field($_POST['ip_whitelist']));
        pch_update_option('pch_ip_blacklist', sanitize_textarea_field($_POST['ip_blacklist']));

        $message = __('Settings saved.', 'passive-captcha-hardened');
        wp_safe_redirect(add_query_arg('pch_message', urlencode($message), wp_get_referer())); exit;
    }

     // Display messages from redirects
    if (isset($_GET['pch_message'])) {
         echo '<div id="message" class="updated notice is-dismissible"><p>' . esc_html(urldecode($_GET['pch_message'])) . '</p></div>';
    }

    // Retrieve current settings and logs
    $rate_limit = pch_get_option('pch_rate_limit_threshold', 5);
    $ban_duration = pch_get_option('pch_ban_duration', 3600);
    $session_lifetime = pch_get_option('pch_session_lifetime', 12 * HOUR_IN_SECONDS);
    $min_time_threshold = pch_get_option('pch_min_time_threshold', 3000);
    $min_hash_length = pch_get_option('pch_min_hash_length', 10);
    $enable_webgl = (bool) pch_get_option('pch_enable_webgl', true);
    $enable_math = (bool) pch_get_option('pch_enable_math', true);
    $webhook_url = pch_get_option('pch_webhook_url', '');
    $hmac_key = pch_get_option('pch_webhook_hmac_key', '');
    $custom_ip_header = pch_get_option('pch_custom_ip_header', '');
    $ip_whitelist = pch_get_option('pch_ip_whitelist', '');
    $ip_blacklist = pch_get_option('pch_ip_blacklist', '');
    $recent_logs = pch_get_option('pch_recent_logs', []);
    if (!is_array($recent_logs)) { $recent_logs = []; }

    ?>
    <div class="wrap">
        <h1><?php _e('Passive CAPTCHA Settings (Generic)', 'passive-captcha-hardened'); ?></h1>

        <p><?php _e('Configure passive bot protection. Requires manual integration into your forms.', 'passive-captcha-hardened'); ?></p>
        <details>
            <summary><strong><?php _e('Click here for Integration Instructions', 'passive-captcha-hardened'); ?></strong></summary>
             <h2><?php _e('Integration Instructions', 'passive-captcha-hardened'); ?></h2>
            <ol>
                 <li><?php printf(__('Add hidden field: %s', 'passive-captcha-hardened'), '<code>&lt;input type="hidden" name="pch_captcha_token" value=""&gt;</code>'); ?></li>
                 <li><?php printf(__('Call %1$s in your PHP form handler before processing. Returns %2$s or %3$s.', 'passive-captcha-hardened'), '<code>pch_verify_submission()</code>', '<code>true</code>', '<code>WP_Error</code>'); ?></li>
                 <li><?php _e('Example PHP check:', 'passive-captcha-hardened'); ?>
                     <pre><code>if (function_exists('pch_verify_submission')) {<br>    $captcha_result = pch_verify_submission();<br>    if (is_wp_error($captcha_result)) {<br>        wp_die("CAPTCHA Failed: " . esc_html($captcha_result->get_error_message()));<br>        return;<br>    }<br>} else { /* Plugin inactive */ wp_die("Security check missing."); return; }<br>// Continue processing...</code></pre>
                 </li>
            </ol>
        </details>
        <hr>

        <form method="post" action="" id="pch-main-settings-form">
            <input type="hidden" name="pch_settings_nonce" value="<?php echo wp_create_nonce('pch_save_settings'); ?>">

            <h2><?php _e('Behavior Settings', 'passive-captcha-hardened'); ?></h2>
            <table class="form-table" role="presentation"><tbody>
                <tr><th scope="row"><label for="rate_limit"><?php _e('Rate Limit Threshold', 'passive-captcha-hardened'); ?></label></th><td><input name="rate_limit" type="number" step="1" min="0" id="rate_limit" value="<?php echo esc_attr($rate_limit); ?>" class="small-text"><p class="description"><?php _e('Failed attempts from an IP before banning (0=disable).', 'passive-captcha-hardened'); ?></p></td></tr>
                <tr><th scope="row"><label for="ban_duration"><?php _e('Ban Duration (seconds)', 'passive-captcha-hardened'); ?></label></th><td><input name="ban_duration" type="number" step="1" min="0" id="ban_duration" value="<?php echo esc_attr($ban_duration); ?>" class="regular-text"><p class="description"><?php _e('How long banned IPs are blocked (e.g., 3600 = 1 hour).', 'passive-captcha-hardened'); ?></p></td></tr>
                <tr><th scope="row"><label for="session_lifetime"><?php _e('Session Token Lifetime (seconds)', 'passive-captcha-hardened'); ?></label></th><td><input name="session_lifetime" type="number" step="1" min="60" id="session_lifetime" value="<?php echo esc_attr($session_lifetime); ?>" class="regular-text"><p class="description"><?php _e('How long the server remembers a user session token (Default: 43200 = 12 hours). Should be >= nonce lifetime.', 'passive-captcha-hardened'); ?></p></td></tr>
            </tbody></table>

            <h2><?php _e('Validation Thresholds', 'passive-captcha-hardened'); ?></h2>
            <table class="form-table" role="presentation"><tbody>
                 <tr><th scope="row"><label for="min_time_threshold"><?php _e('Minimum Time Threshold (ms)', 'passive-captcha-hardened'); ?></label></th><td><input name="min_time_threshold" type="number" step="100" min="0" id="min_time_threshold" value="<?php echo esc_attr($min_time_threshold); ?>" class="small-text"><p class="description"><?php _e('Minimum time (milliseconds) user must spend on page (Default: 3000).', 'passive-captcha-hardened'); ?></p></td></tr>
                 <tr><th scope="row"><label for="min_hash_length"><?php _e('Minimum Fingerprint Hash Length', 'passive-captcha-hardened'); ?></label></th><td><input name="min_hash_length" type="number" step="1" min="0" id="min_hash_length" value="<?php echo esc_attr($min_hash_length); ?>" class="small-text"><p class="description"><?php _e('Minimum expected length of the client-side fingerprint hash (Default: 10).', 'passive-captcha-hardened'); ?></p></td></tr>
            </tbody></table>

             <h2><?php _e('Client-Side Checks', 'passive-captcha-hardened'); ?></h2>
             <table class="form-table" role="presentation"><tbody>
                 <tr><th scope="row"><?php _e('Enable Checks', 'passive-captcha-hardened'); ?></th><td><fieldset><legend class="screen-reader-text"><span><?php _e('Enable Checks', 'passive-captcha-hardened'); ?></span></legend><label for="enable_webgl"><input name="enable_webgl" type="checkbox" id="enable_webgl" value="1" <?php checked($enable_webgl, true); ?>> <?php _e('Include WebGL Fingerprint in client hash', 'passive-captcha-hardened'); ?></label><br><label for="enable_math"><input name="enable_math" type="checkbox" id="enable_math" value="1" <?php checked($enable_math, true); ?>> <?php _e('Include Invisible Math Challenge in client hash', 'passive-captcha-hardened'); ?></label><p class="description"><?php _e('Disabling these reduces bot detection capability but may address privacy concerns.', 'passive-captcha-hardened'); ?></p></fieldset></td></tr>
            </tbody></table>

             <h2><?php _e('Webhook Settings', 'passive-captcha-hardened'); ?></h2>
             <table class="form-table" role="presentation"><tbody>
                 <tr><th scope="row"><label for="webhook_url"><?php _e('Webhook URL', 'passive-captcha-hardened'); ?></label></th><td><input name="webhook_url" type="url" id="webhook_url" value="<?php echo esc_attr($webhook_url); ?>" class="large-text" placeholder="https://your-webhook-receiver.com/endpoint"><p class="description"><?php _e('URL to send failure notifications (POST JSON). Leave blank to disable.', 'passive-captcha-hardened'); ?></p></td></tr>
                 <tr><th scope="row"><label for="hmac_key"><?php _e('Webhook HMAC Key', 'passive-captcha-hardened'); ?></label></th><td><input name="hmac_key" type="text" id="hmac_key" value="<?php echo esc_attr($hmac_key); ?>" class="regular-text"><p class="description"><?php _e('Secret key to sign webhook payloads (SHA256 HMAC). Required if URL is set.', 'passive-captcha-hardened'); ?></p></td></tr>
             </tbody></table>

             <h2><?php _e('IP Address Management', 'passive-captcha-hardened'); ?></h2>
             <table class="form-table" role="presentation"><tbody>
                 <tr><th scope="row"><label for="custom_ip_header"><?php _e('Custom IP Header (Advanced)', 'passive-captcha-hardened'); ?></label></th><td><input name="custom_ip_header" type="text" id="custom_ip_header" value="<?php echo esc_attr($custom_ip_header); ?>" class="regular-text" placeholder="HTTP_X_REAL_IP"><p class="description"><?php _e('Optional: Specify a server variable (e.g., HTTP_CF_CONNECTING_IP) to check first for the visitor IP. Use format seen by PHP in $_SERVER.', 'passive-captcha-hardened'); ?></p></td></tr>
                 <tr><th scope="row"><label for="ip_whitelist"><?php _e('IP Whitelist', 'passive-captcha-hardened'); ?></label></th><td><textarea name="ip_whitelist" id="ip_whitelist" rows="5" cols="50" class="large-text" placeholder="1.2.3.4&#10;5.6.7.8"><?php echo esc_textarea($ip_whitelist); ?></textarea><p class="description"><?php _e('One IP per line. Bypasses all checks.', 'passive-captcha-hardened'); ?></p></td></tr>
                 <tr><th scope="row"><label for="ip_blacklist"><?php _e('IP Blacklist', 'passive-captcha-hardened'); ?></label></th><td><textarea name="ip_blacklist" id="ip_blacklist" rows="5" cols="50" class="large-text" placeholder="9.8.7.6&#10;5.5.5.5"><?php echo esc_textarea($ip_blacklist); ?></textarea><p class="description"><?php _e('One IP per line. Always blocked.', 'passive-captcha-hardened'); ?></p></td></tr>
             </tbody></table>

            <?php submit_button(__('Save Settings', 'passive-captcha-hardened')); ?>
        </form> <hr style="margin-top: 30px;">
        <h2><?php _e('Rate Limit Management', 'passive-captcha-hardened'); ?></h2>
        <p><?php _e('Use this button to immediately clear all current rate limit bans (failure counts). Banned IPs will be able to submit again immediately.', 'passive-captcha-hardened'); ?></p>
        <form method="post" action="" style="margin-top: 0;">
            <?php // Add nonce for the clear bans action ?>
            <input type="hidden" name="pch_clear_bans_nonce" value="<?php echo wp_create_nonce('pch_clear_bans_action'); ?>">
            <?php submit_button(__('Clear All Rate Limit Bans', 'passive-captcha-hardened'), 'delete', 'pch_clear_bans', false, ['onclick' => "return confirm('" . esc_js(__('Are you sure you want to clear all current rate limit bans?', 'passive-captcha-hardened')) . "');"]); ?>
        </form>
        <hr style="margin-top: 30px;">
        <h2><?php _e('Recent Log Entries', 'passive-captcha-hardened'); ?></h2>
        <p><?php _e('Shows the last 50 logged events from this plugin (failures, alerts). Check server PHP error logs for more details.', 'passive-captcha-hardened'); ?></p>
        <div id="pch-log-display" style="margin-bottom: 15px;">
            <textarea readonly="readonly" style="width: 100%; height: 250px; background-color: #f0f0f0; font-family: monospace; font-size: 12px; white-space: pre; overflow: auto; border: 1px solid #ccc; padding: 5px; box-sizing: border-box;"><?php
                if (!empty($recent_logs)) {
                    echo esc_textarea(implode("\n", $recent_logs));
                } else {
                    echo esc_textarea(__('No recent log entries found.', 'passive-captcha-hardened'));
                }
            ?></textarea>
        </div>
        <form method="post" action="" style="margin-top: 0;">
            <?php // Add nonce for the clear log action ?>
            <input type="hidden" name="pch_clear_log_nonce" value="<?php echo wp_create_nonce('pch_clear_log_action'); ?>">
            <?php submit_button(__('Clear Recent Log Entries', 'passive-captcha-hardened'), 'delete', 'pch_clear_log', false); // Use 'delete' class for styling ?>
        </form>
        </div><?php
}


// --- Internationalization ---
function pch_load_textdomain() { load_plugin_textdomain('passive-captcha-hardened', false, dirname(plugin_basename(__FILE__)) . '/languages/'); }
add_action('plugins_loaded', 'pch_load_textdomain');

?>
