<?php
// tests/tests-passive-captcha.php - Generic Version - Configurable

use Yoast\PHPUnitPolyfills\TestCases\TestCase; // Or ensure WP_UnitTestCase is available

class PassiveCaptchaTest extends WP_UnitTestCase { // Or extends TestCase

    private $mock_ip = '192.0.2.5';
    private $mock_ua = 'Mozilla/5.0 Test Agent';
    private $mock_ja3 = 'mock-ja3-fingerprint-string';
    private $captcha_token_field = 'pch_captcha_token';
    private $nonce_field = 'pch_nonce';
    private $session_field = 'pch_session';
    private $iphash_field = 'pch_iphash';

    // Store original SERVER state
    private $original_server;

    public function setUp(): void {
        parent::setUp();
        // Store original $_SERVER
        $this->original_server = $_SERVER;

        // Reset options relevant to tests before each run
        $options_to_reset = [
            'pch_rate_limit_threshold', 'pch_ban_duration', 'pch_ip_whitelist',
            'pch_ip_blacklist', 'pch_webhook_url', 'pch_webhook_hmac_key',
            'pch_min_time_threshold', 'pch_min_hash_length', 'pch_session_lifetime',
            'pch_custom_ip_header', 'pch_enable_webgl', 'pch_enable_math'
        ];
        foreach ($options_to_reset as $option) {
            if (function_exists('delete_site_option')) {
                delete_site_option($option);
            } else {
                delete_option($option);
            }
        }

        // Clear potentially lingering failure transient for mock IP
        delete_transient('pch_fail_' . md5($this->mock_ip));

        // Mock server variables - essential for the function
        $_SERVER['REMOTE_ADDR'] = $this->mock_ip;
        $_SERVER['HTTP_USER_AGENT'] = $this->mock_ua;
        $_SERVER['HTTP_X_JA3_FINGERPRINT'] = $this->mock_ja3;

        // Clear POST data at the start of each test
        $_POST = [];
    }

    public function tearDown(): void {
        // Restore original $_SERVER
        $_SERVER = $this->original_server;
        // Clean up POST data
        $_POST = [];
        parent::tearDown();
    }

    // --- Helper Tests (Rate Limit, IP Lists, Webhook) ---
    // (These remain the same as before)
    public function testRateLimitDefaults() { $this->assertEquals(5, pch_get_option('pch_rate_limit_threshold', 5)); $this->assertEquals(3600, pch_get_option('pch_ban_duration', 3600)); }
    public function testRateLimitIncrements() { $ip = '192.0.2.1'; delete_transient('pch_fail_' . md5($ip)); $this->assertFalse(pch_check_rate_limit($ip)); pch_update_option('pch_rate_limit_threshold', 3); pch_update_option('pch_ban_duration', 60); pch_register_failure($ip); $this->assertFalse(pch_check_rate_limit($ip)); pch_register_failure($ip); $this->assertFalse(pch_check_rate_limit($ip)); pch_register_failure($ip); $this->assertTrue(pch_check_rate_limit($ip)); delete_transient('pch_fail_' . md5($ip)); }
    public function testIpWhitelistBlacklistFunctions() { $whitelisted_ip = '192.0.2.100'; $blacklisted_ip = '203.0.113.1'; $other_ip = '8.8.8.8'; pch_update_option('pch_ip_whitelist', $whitelisted_ip . "\n198.51.100.1"); pch_update_option('pch_ip_blacklist', $blacklisted_ip . "\n198.51.100.99"); $this->assertTrue(pch_is_ip_whitelisted($whitelisted_ip)); $this->assertFalse(pch_is_ip_whitelisted($other_ip)); $this->assertTrue(pch_is_ip_blacklisted($blacklisted_ip)); $this->assertFalse(pch_is_ip_blacklisted($other_ip)); }
    public function testWebhookSignatureGeneration() { pch_update_option('pch_webhook_hmac_key', 'testsecret'); $payload = ['event' => 'test', 'ip' => '127.0.0.1']; $body = wp_json_encode($payload); $expected_hmac = hash_hmac('sha256', $body, 'testsecret'); $this->assertEquals($expected_hmac, hash_hmac('sha256', $body, pch_get_option('pch_webhook_hmac_key'))); }

    // --- Test for pch_get_visitor_ip() ---
    public function testGetVisitorIpPrioritization() {
        // Test Case 1: Standard X-Forwarded-For
        $_SERVER['HTTP_X_FORWARDED_FOR'] = '1.1.1.1, 192.168.1.1';
        $_SERVER['REMOTE_ADDR'] = '10.0.0.1'; // Proxy IP
        $this->assertEquals('1.1.1.1', pch_get_visitor_ip(), 'Should get first public IP from XFF');

        // Test Case 2: Cloudflare Header
        $_SERVER['HTTP_CF_CONNECTING_IP'] = '2.2.2.2';
        $this->assertEquals('2.2.2.2', pch_get_visitor_ip(), 'Should prioritize CF header');
        unset($_SERVER['HTTP_CF_CONNECTING_IP']); // Clean up for next test

        // Test Case 3: X-Real-IP Header
        $_SERVER['HTTP_X_REAL_IP'] = '3.3.3.3';
        $this->assertEquals('3.3.3.3', pch_get_visitor_ip(), 'Should prioritize X-Real-IP');
        unset($_SERVER['HTTP_X_REAL_IP']);

        // Test Case 4: Custom Header Set in Options
        $custom_header = 'HTTP_X_MY_CUSTOM_IP';
        pch_update_option('pch_custom_ip_header', $custom_header);
        $_SERVER[$custom_header] = '4.4.4.4';
        $this->assertEquals('4.4.4.4', pch_get_visitor_ip(), 'Should prioritize Custom header from options');
        unset($_SERVER[$custom_header]);
        pch_update_option('pch_custom_ip_header', ''); // Reset option

        // Test Case 5: Fallback to REMOTE_ADDR
        unset($_SERVER['HTTP_X_FORWARDED_FOR']);
        $this->assertEquals('10.0.0.1', pch_get_visitor_ip(), 'Should fall back to REMOTE_ADDR');

        // Test Case 6: Invalid IP in XFF
         $_SERVER['HTTP_X_FORWARDED_FOR'] = 'invalid-ip, 1.1.1.1';
         $this->assertEquals('1.1.1.1', pch_get_visitor_ip(), 'Should skip invalid IP in XFF');
         unset($_SERVER['HTTP_X_FORWARDED_FOR']);

         // Test Case 7: Only private IP in XFF
         $_SERVER['HTTP_X_FORWARDED_FOR'] = '192.168.1.100, 10.0.0.5';
         $this->assertEquals('192.168.1.100', pch_get_visitor_ip(), 'Should take first valid IP even if private'); // Current logic takes first valid
         unset($_SERVER['HTTP_X_FORWARDED_FOR']);

    }

    // --- VALIDATION TEST CASES for pch_verify_submission() ---
    // (Most remain structurally similar, but update checks involving new settings)

    public function testVerificationSucceedsWithValidData() {
        // 1. Arrange
        $nonce = wp_create_nonce('pch_captcha_nonce');
        $session_token = 'valid_session_' . uniqid();
        set_transient('pch_' . $session_token, time(), 12 * HOUR_IN_SECONDS); // Use default long lifetime
        $ip_hash = sha1($this->mock_ip . $this->mock_ua);
        $time_spent = 5000; // > default 3000ms
        $nav_hash = 'valid_navigator_data_long_enough'; // > default 10 chars
        $token_value = base64_encode($time_spent . ':' . $nav_hash);

        $_POST[$this->captcha_token_field] = $token_value;
        $_POST[$this->nonce_field] = $nonce;
        $_POST[$this->session_field] = $session_token;
        $_POST[$this->iphash_field] = $ip_hash;

        // 2. Act
        $result = pch_verify_submission();

        // 3. Assert
        $this->assertTrue($result, 'Verification should return true for valid data with defaults');
        $this->assertFalse(get_transient('pch_' . $session_token), 'Session transient should be deleted on success');
    }

    // (Tests for Blacklist, Whitelist, Rate Limit, Nonce, Session, IP/UA Mismatch, No Interaction, Empty Token, Invalid Token Format remain largely the same)
    // ... include those tests here, ensuring they use the correct $_POST keys ...
    public function testVerificationFailsOnBlacklistedIp() { pch_update_option('pch_ip_blacklist', $this->mock_ip); $result = pch_verify_submission(); $this->assertInstanceOf(WP_Error::class, $result); $this->assertEquals('ip_blacklisted', $result->get_error_code()); }
    public function testVerificationSucceedsOnWhitelistedIp() { pch_update_option('pch_ip_whitelist', $this->mock_ip); $_POST[$this->nonce_field] = 'invalid'; $result = pch_verify_submission(); $this->assertTrue($result); }
    public function testVerificationFailsOnRateLimitExceeded() { pch_update_option('pch_rate_limit_threshold', 1); pch_register_failure($this->mock_ip); $nonce = wp_create_nonce('pch_captcha_nonce'); $session_token = 's'; set_transient('pch_'.$session_token, time(), 60); $_POST[$this->nonce_field] = $nonce; $_POST[$this->session_field] = $session_token; $result = pch_verify_submission(); $this->assertInstanceOf(WP_Error::class, $result); $this->assertEquals('rate_limit_exceeded', $result->get_error_code()); }
    public function testVerificationFailsOnInvalidNonce() { $session_token = 's'; set_transient('pch_'.$session_token, time(), 60); $_POST[$this->nonce_field] = 'invalid'; $_POST[$this->session_field] = $session_token; $result = pch_verify_submission(); $this->assertInstanceOf(WP_Error::class, $result); $this->assertEquals('nonce_invalid', $result->get_error_code()); }
    public function testVerificationFailsOnExpiredSession() { $nonce = wp_create_nonce('pch_captcha_nonce'); $_POST[$this->nonce_field] = $nonce; $_POST[$this->session_field] = 'expired'; $result = pch_verify_submission(); $this->assertInstanceOf(WP_Error::class, $result); $this->assertEquals('session_invalid', $result->get_error_code()); }
    public function testVerificationFailsOnIpUaMismatch() { $nonce = wp_create_nonce('pch_captcha_nonce'); $session_token = 's'; set_transient('pch_'.$session_token, time(), 60); $_POST[$this->nonce_field] = $nonce; $_POST[$this->session_field] = $session_token; $_POST[$this->iphash_field] = 'badhash'; $result = pch_verify_submission(); $this->assertInstanceOf(WP_Error::class, $result); $this->assertEquals('ip_ua_mismatch', $result->get_error_code()); $this->assertFalse(get_transient('pch_'.$session_token)); }
    public function testVerificationFailsOnNoInteractionValue() { $nonce = wp_create_nonce('pch_captcha_nonce'); $session_token = 's'; set_transient('pch_'.$session_token, time(), 60); $ip_hash = sha1($this->mock_ip . $this->mock_ua); $_POST[$this->captcha_token_field] = 'no_interaction'; $_POST[$this->nonce_field] = $nonce; $_POST[$this->session_field] = $session_token; $_POST[$this->iphash_field] = $ip_hash; $result = pch_verify_submission(); $this->assertInstanceOf(WP_Error::class, $result); $this->assertEquals('no_interaction', $result->get_error_code()); $this->assertFalse(get_transient('pch_'.$session_token)); }
    public function testVerificationFailsOnEmptyTokenValue() { $nonce = wp_create_nonce('pch_captcha_nonce'); $session_token = 's'; set_transient('pch_'.$session_token, time(), 60); $ip_hash = sha1($this->mock_ip . $this->mock_ua); $_POST[$this->captcha_token_field] = ''; $_POST[$this->nonce_field] = $nonce; $_POST[$this->session_field] = $session_token; $_POST[$this->iphash_field] = $ip_hash; $result = pch_verify_submission(); $this->assertInstanceOf(WP_Error::class, $result); $this->assertEquals('no_interaction', $result->get_error_code()); $this->assertFalse(get_transient('pch_'.$session_token)); }
    public function testVerificationFailsOnInvalidTokenFormat() { $nonce = wp_create_nonce('pch_captcha_nonce'); $session_token = 's'; set_transient('pch_'.$session_token, time(), 60); $ip_hash = sha1($this->mock_ip . $this->mock_ua); $_POST[$this->captcha_token_field] = '!!!'; $_POST[$this->nonce_field] = $nonce; $_POST[$this->session_field] = $session_token; $_POST[$this->iphash_field] = $ip_hash; $result = pch_verify_submission(); $this->assertInstanceOf(WP_Error::class, $result); $this->assertEquals('token_invalid_format', $result->get_error_code()); $this->assertFalse(get_transient('pch_'.$session_token)); }


    // --- Updated Tests for Configurable Thresholds ---

    public function testVerificationFailsOnTimingFailureWithCustomThreshold() {
        // 1. Arrange
        pch_update_option('pch_min_time_threshold', 5000); // Set custom threshold

        $nonce = wp_create_nonce('pch_captcha_nonce');
        $session_token = 'valid_session_' . uniqid();
        set_transient('pch_' . $session_token, time(), 600);
        $ip_hash = sha1($this->mock_ip . $this->mock_ua);
        $time_spent = 4000; // FAILS custom threshold, but passes default
        $nav_hash = 'valid_navigator_hash_long_enough';
        $token_value = base64_encode($time_spent . ':' . $nav_hash);

        $_POST[$this->captcha_token_field] = $token_value;
        $_POST[$this->nonce_field] = $nonce;
        $_POST[$this->session_field] = $session_token;
        $_POST[$this->iphash_field] = $ip_hash;

        // 2. Act
        $result = pch_verify_submission();

        // 3. Assert
        $this->assertInstanceOf(WP_Error::class, $result, 'Result should be WP_Error on timing failure');
        $this->assertEquals('timing_or_fingerprint_invalid', $result->get_error_code());
        $this->assertFalse(get_transient('pch_' . $session_token));
    }

     public function testVerificationFailsOnFingerprintHashFailureWithCustomThreshold() {
        // 1. Arrange
        pch_update_option('pch_min_hash_length', 20); // Set custom threshold

        $nonce = wp_create_nonce('pch_captcha_nonce');
        $session_token = 'valid_session_' . uniqid();
        set_transient('pch_' . $session_token, time(), 600);
        $ip_hash = sha1($this->mock_ip . $this->mock_ua);
        $time_spent = 5000; // Valid time
        $nav_hash = 'short_hash_15'; // FAILS custom threshold (len 13), passes default
        $token_value = base64_encode($time_spent . ':' . $nav_hash);

        $_POST[$this->captcha_token_field] = $token_value;
        $_POST[$this->nonce_field] = $nonce;
        $_POST[$this->session_field] = $session_token;
        $_POST[$this->iphash_field] = $ip_hash;

        // 2. Act
        $result = pch_verify_submission();

        // 3. Assert
        $this->assertInstanceOf(WP_Error::class, $result, 'Result should be WP_Error on short navigator hash');
        $this->assertEquals('timing_or_fingerprint_invalid', $result->get_error_code());
        $this->assertFalse(get_transient('pch_' . $session_token));
    }

    // Note: Testing the effect of pch_enable_webgl/pch_enable_math requires checking
    // the generated JS hash, which isn't directly testable in PHPUnit without
    // more complex JS simulation or inspecting the localized data.
    // We trust wp_localize_script passes the flags correctly.

} // End class PassiveCaptchaTest

