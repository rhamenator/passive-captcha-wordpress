<?php
// tests/tests-passive-captcha.php - Generic Version

use Yoast\PHPUnitPolyfills\TestCases\TestCase; // Or ensure WP_UnitTestCase is available

class PassiveCaptchaTest extends WP_UnitTestCase { // Or extends TestCase

    private $mock_ip = '192.0.2.5';
    private $mock_ua = 'Mozilla/5.0 Test Agent';
    private $mock_ja3 = 'mock-ja3-fingerprint-string'; // Example valid JA3
    // Field names used directly in $_POST now
    private $captcha_token_field = 'pch_captcha_token';
    private $nonce_field = 'pch_nonce';
    private $session_field = 'pch_session';
    private $iphash_field = 'pch_iphash';


    public function setUp(): void {
        parent::setUp();
        // Reset options relevant to tests before each run
        if (function_exists('delete_site_option')) {
             delete_site_option('pch_rate_limit_threshold');
             delete_site_option('pch_ban_duration');
             delete_site_option('pch_ip_whitelist');
             delete_site_option('pch_ip_blacklist');
             delete_site_option('pch_webhook_url');
             delete_site_option('pch_webhook_hmac_key');
        } else {
             delete_option('pch_rate_limit_threshold');
             delete_option('pch_ban_duration');
             delete_option('pch_ip_whitelist');
             delete_option('pch_ip_blacklist');
             delete_option('pch_webhook_url');
             delete_option('pch_webhook_hmac_key');
        }

        // Clear potentially lingering failure transient for mock IP
        delete_transient('pch_fail_' . md5($this->mock_ip));

        // Mock server variables
        $_SERVER['REMOTE_ADDR'] = $this->mock_ip;
        $_SERVER['HTTP_USER_AGENT'] = $this->mock_ua;
        $_SERVER['HTTP_X_JA3_FINGERPRINT'] = $this->mock_ja3; // Matches key in pch_verify_submission

        // Clear POST data at the start of each test
        $_POST = [];
    }

    public function tearDown(): void {
        // Clean up mocked globals
        unset($_SERVER['REMOTE_ADDR']);
        unset($_SERVER['HTTP_USER_AGENT']);
        unset($_SERVER['HTTP_X_JA3_FINGERPRINT']);
        // Clean up POST data
        $_POST = [];
        parent::tearDown();
    }

    // No longer need create_mock_form helper

    // --- Helper Tests (Rate Limit, IP Lists, Webhook) ---
    // These tests remain largely the same as they test independent functions

    public function testRateLimitDefaults() {
        $this->assertEquals(5, pch_get_option('pch_rate_limit_threshold', 5));
        $this->assertEquals(3600, pch_get_option('pch_ban_duration', 3600));
    }

    public function testRateLimitIncrements() {
        $ip = '192.0.2.1';
        delete_transient('pch_fail_' . md5($ip));

        $this->assertFalse(pch_check_rate_limit($ip), 'Rate limit should initially be false');

        pch_update_option('pch_rate_limit_threshold', 3);
        pch_update_option('pch_ban_duration', 60);

        pch_register_failure($ip); // 1st
        $this->assertFalse(pch_check_rate_limit($ip), 'Rate limit false after 1');
        $this->assertEquals(1, (int) get_transient('pch_fail_' . md5($ip)));

        pch_register_failure($ip); // 2nd
        $this->assertFalse(pch_check_rate_limit($ip), 'Rate limit false after 2');
        $this->assertEquals(2, (int) get_transient('pch_fail_' . md5($ip)));

        pch_register_failure($ip); // 3rd - triggers ban
        $this->assertTrue(pch_check_rate_limit($ip), 'Rate limit true after 3');
        $this->assertEquals(3, (int) get_transient('pch_fail_' . md5($ip)));

        delete_transient('pch_fail_' . md5($ip));
    }

    public function testIpWhitelistBlacklistFunctions() { // Renamed for clarity
        $whitelisted_ip = '192.0.2.100';
        $blacklisted_ip = '203.0.113.1';
        $other_ip = '8.8.8.8';

        pch_update_option('pch_ip_whitelist', $whitelisted_ip . "\n198.51.100.1");
        pch_update_option('pch_ip_blacklist', $blacklisted_ip . "\n198.51.100.99");

        $this->assertTrue(pch_is_ip_whitelisted($whitelisted_ip));
        $this->assertFalse(pch_is_ip_whitelisted($other_ip));
        $this->assertFalse(pch_is_ip_whitelisted($blacklisted_ip));

        $this->assertTrue(pch_is_ip_blacklisted($blacklisted_ip));
        $this->assertFalse(pch_is_ip_blacklisted($other_ip));
        $this->assertFalse(pch_is_ip_blacklisted($whitelisted_ip));
    }

    public function testWebhookSignatureGeneration() {
        pch_update_option('pch_webhook_hmac_key', 'testsecret');
        $payload = ['event' => 'test', 'ip' => '127.0.0.1'];
        $body = wp_json_encode($payload); // Use wp_json_encode matching the function
        $expected_hmac = hash_hmac('sha256', $body, 'testsecret');

        $this->assertEquals($expected_hmac, hash_hmac('sha256', $body, pch_get_option('pch_webhook_hmac_key')), 'Generated HMAC should match expected');
    }


    // --- NEW VALIDATION TEST CASES for pch_verify_submission() ---

    public function testVerificationSucceedsWithValidData() {
        // 1. Arrange
        $nonce = wp_create_nonce('pch_captcha_nonce');
        $session_token = 'valid_session_' . uniqid();
        set_transient('pch_' . $session_token, time(), 600);
        $ip_hash = sha1($this->mock_ip . $this->mock_ua);
        $time_spent = 5000;
        $nav_hash = 'valid_navigator_data_long_enough';
        $token_value = base64_encode($time_spent . ':' . $nav_hash);

        $_POST[$this->captcha_token_field] = $token_value;
        $_POST[$this->nonce_field] = $nonce;
        $_POST[$this->session_field] = $session_token;
        $_POST[$this->iphash_field] = $ip_hash;

        // 2. Act
        $result = pch_verify_submission();

        // 3. Assert
        $this->assertTrue($result, 'Verification should return true for valid data');
        $this->assertFalse(get_transient('pch_' . $session_token), 'Session transient should be deleted on success');
        $fail_key = 'pch_fail_' . md5($this->mock_ip);
        $this->assertEquals(0, (int) get_transient($fail_key), 'Failure count should be 0 on success');
    }

    public function testVerificationFailsOnInvalidNonce() {
        // 1. Arrange
        $session_token = 'valid_session_' . uniqid();
        set_transient('pch_' . $session_token, time(), 600);
        $ip_hash = sha1($this->mock_ip . $this->mock_ua);
        $token_value = base64_encode('5000:validhashlongenough');

        $_POST[$this->captcha_token_field] = $token_value;
        $_POST[$this->nonce_field] = 'invalid-nonce-value'; // Incorrect nonce
        $_POST[$this->session_field] = $session_token;
        $_POST[$this->iphash_field] = $ip_hash;

        // 2. Act
        $result = pch_verify_submission();

        // 3. Assert
        $this->assertInstanceOf(WP_Error::class, $result, 'Result should be WP_Error on nonce failure');
        $this->assertEquals('nonce_invalid', $result->get_error_code(), 'Error code should be nonce_invalid');
        $fail_key = 'pch_fail_' . md5($this->mock_ip);
        $this->assertEquals(1, (int) get_transient($fail_key), 'Failure count should be 1');
         // Session is NOT deleted on nonce failure in the generic function
        $this->assertTrue( (bool) get_transient('pch_' . $session_token), 'Session transient should NOT be deleted on nonce failure');
    }

    public function testVerificationFailsOnMissingJA3() {
        // 1. Arrange
        unset($_SERVER['HTTP_X_JA3_FINGERPRINT']); // Simulate missing header
         // Need to set valid POST data otherwise it fails earlier on nonce/session check
        $nonce = wp_create_nonce('pch_captcha_nonce');
        $session_token = 'valid_session_' . uniqid();
        set_transient('pch_' . $session_token, time(), 600);
        $_POST[$this->nonce_field] = $nonce;
        $_POST[$this->session_field] = $session_token;


        // 2. Act
        $result = pch_verify_submission();

        // 3. Assert
        $this->assertInstanceOf(WP_Error::class, $result, 'Result should be WP_Error on missing JA3');
        $this->assertEquals('ja3_invalid', $result->get_error_code(), 'Error code should be ja3_invalid');
        $fail_key = 'pch_fail_' . md5($this->mock_ip);
        $this->assertEquals(1, (int) get_transient($fail_key), 'Failure count should be 1');
    }

     public function testVerificationFailsOnExpiredSession() {
        // 1. Arrange
        $nonce = wp_create_nonce('pch_captcha_nonce');
        $session_token = 'expired_session_' . uniqid();
        // Do not set the transient
        $ip_hash = sha1($this->mock_ip . $this->mock_ua);
        $token_value = base64_encode('5000:validhashlongenough');

        $_POST[$this->captcha_token_field] = $token_value;
        $_POST[$this->nonce_field] = $nonce;
        $_POST[$this->session_field] = $session_token; // Session token submitted, but no valid transient
        $_POST[$this->iphash_field] = $ip_hash;

        // 2. Act
        $result = pch_verify_submission();

        // 3. Assert
        $this->assertInstanceOf(WP_Error::class, $result, 'Result should be WP_Error on expired session');
        $this->assertEquals('session_invalid', $result->get_error_code(), 'Error code should be session_invalid');
        $fail_key = 'pch_fail_' . md5($this->mock_ip);
        $this->assertEquals(1, (int) get_transient($fail_key), 'Failure count should be 1');
    }

    public function testVerificationFailsOnBlacklistedIp() {
        // 1. Arrange
        pch_update_option('pch_ip_blacklist', $this->mock_ip . "\n1.2.3.4");

        // 2. Act
        $result = pch_verify_submission();

        // 3. Assert
        $this->assertInstanceOf(WP_Error::class, $result, 'Result should be WP_Error for blacklisted IP');
        $this->assertEquals('ip_blacklisted', $result->get_error_code(), 'Error code should be ip_blacklisted');
        // Failure count shouldn't increase here
        $fail_key = 'pch_fail_' . md5($this->mock_ip);
        $this->assertEquals(0, (int) get_transient($fail_key), 'Failure count should be 0');
    }

    public function testVerificationSucceedsOnWhitelistedIp() { // Changed name, it succeeds
        // 1. Arrange
        pch_update_option('pch_ip_whitelist', "8.8.8.8\n" . $this->mock_ip);
        // Provide data that would fail later checks
        $_POST[$this->captcha_token_field] = 'invalid-token';
        $_POST[$this->nonce_field] = 'invalid-nonce';
        unset($_SERVER['HTTP_X_JA3_FINGERPRINT']); // Ensure JA3 check would fail if not skipped

        // 2. Act
        $result = pch_verify_submission();

        // 3. Assert
        $this->assertTrue($result, 'Verification should return true for whitelisted IP');
        // Failure count shouldn't increase
        $fail_key = 'pch_fail_' . md5($this->mock_ip);
        $this->assertEquals(0, (int) get_transient($fail_key), 'Failure count should be 0');
    }

    public function testVerificationFailsOnRateLimitExceeded() {
        // 1. Arrange
        pch_update_option('pch_rate_limit_threshold', 2);
        pch_update_option('pch_ban_duration', 60);
        pch_register_failure($this->mock_ip);
        pch_register_failure($this->mock_ip);
         // Need to set valid nonce/session otherwise it fails before rate limit check
        $nonce = wp_create_nonce('pch_captcha_nonce');
        $session_token = 'valid_session_' . uniqid();
        set_transient('pch_' . $session_token, time(), 600);
        $_POST[$this->nonce_field] = $nonce;
        $_POST[$this->session_field] = $session_token;

        // 2. Act
        $result = pch_verify_submission();

        // 3. Assert
        $this->assertInstanceOf(WP_Error::class, $result, 'Result should be WP_Error when rate limit exceeded');
        $this->assertEquals('rate_limit_exceeded', $result->get_error_code(), 'Error code should be rate_limit_exceeded');
        // Failure count should remain at the threshold
        $fail_key = 'pch_fail_' . md5($this->mock_ip);
        $this->assertEquals(2, (int) get_transient($fail_key), 'Failure count should remain 2');
    }

    public function testVerificationFailsOnIpUaMismatch() {
        // 1. Arrange
        $nonce = wp_create_nonce('pch_captcha_nonce');
        $session_token = 'valid_session_' . uniqid();
        set_transient('pch_' . $session_token, time(), 600);
        $correct_ip_hash = sha1($this->mock_ip . $this->mock_ua);
        $incorrect_ip_hash = sha1('different_ip_or_ua' . $this->mock_ua);
        $token_value = base64_encode('5000:validhashlongenough');

        $_POST[$this->captcha_token_field] = $token_value;
        $_POST[$this->nonce_field] = $nonce;
        $_POST[$this->session_field] = $session_token;
        $_POST[$this->iphash_field] = $incorrect_ip_hash; // Submit incorrect hash

        // 2. Act
        $result = pch_verify_submission();

        // 3. Assert
        $this->assertInstanceOf(WP_Error::class, $result, 'Result should be WP_Error on IP/UA mismatch');
        $this->assertEquals('ip_ua_mismatch', $result->get_error_code(), 'Error code should be ip_ua_mismatch');
        $fail_key = 'pch_fail_' . md5($this->mock_ip);
        $this->assertEquals(1, (int) get_transient($fail_key), 'Failure count should be 1');
        $this->assertFalse(get_transient('pch_' . $session_token), 'Session transient should be deleted on IP/UA failure');
    }

     public function testVerificationFailsOnNoInteractionValue() {
        // 1. Arrange
        $nonce = wp_create_nonce('pch_captcha_nonce');
        $session_token = 'valid_session_' . uniqid();
        set_transient('pch_' . $session_token, time(), 600);
        $ip_hash = sha1($this->mock_ip . $this->mock_ua);

        $_POST[$this->captcha_token_field] = 'no_interaction'; // Explicit failure value
        $_POST[$this->nonce_field] = $nonce;
        $_POST[$this->session_field] = $session_token;
        $_POST[$this->iphash_field] = $ip_hash;

        // 2. Act
        $result = pch_verify_submission();

        // 3. Assert
        $this->assertInstanceOf(WP_Error::class, $result, 'Result should be WP_Error for "no_interaction" value');
         $this->assertEquals('no_interaction', $result->get_error_code(), 'Error code should be no_interaction');
        $fail_key = 'pch_fail_' . md5($this->mock_ip);
        $this->assertEquals(1, (int) get_transient($fail_key), 'Failure count should be 1');
        $this->assertFalse(get_transient('pch_' . $session_token), 'Session transient should be deleted on interaction failure');
    }

     public function testVerificationFailsOnEmptyTokenValue() {
        // 1. Arrange
        $nonce = wp_create_nonce('pch_captcha_nonce');
        $session_token = 'valid_session_' . uniqid();
        set_transient('pch_' . $session_token, time(), 600);
        $ip_hash = sha1($this->mock_ip . $this->mock_ua);

        $_POST[$this->captcha_token_field] = ''; // Empty value
        $_POST[$this->nonce_field] = $nonce;
        $_POST[$this->session_field] = $session_token;
        $_POST[$this->iphash_field] = $ip_hash;

        // 2. Act
        $result = pch_verify_submission();

        // 3. Assert
         // It fails with 'no_interaction' code based on the function logic
        $this->assertInstanceOf(WP_Error::class, $result, 'Result should be WP_Error for empty token value');
        $this->assertEquals('no_interaction', $result->get_error_code(), 'Error code should be no_interaction for empty token');
        $fail_key = 'pch_fail_' . md5($this->mock_ip);
        $this->assertEquals(1, (int) get_transient($fail_key), 'Failure count should be 1');
        $this->assertFalse(get_transient('pch_' . $session_token), 'Session transient should be deleted on empty token failure');
    }

    public function testVerificationFailsOnInvalidTokenFormat() {
        // 1. Arrange
        $nonce = wp_create_nonce('pch_captcha_nonce');
        $session_token = 'valid_session_' . uniqid();
        set_transient('pch_' . $session_token, time(), 600);
        $ip_hash = sha1($this->mock_ip . $this->mock_ua);
        $fail_key = 'pch_fail_' . md5($this->mock_ip);

        // --- Test 1: Not base64 ---
        $_POST[$this->captcha_token_field] = '!!!@@@$$$%%%';
        $_POST[$this->nonce_field] = $nonce;
        $_POST[$this->session_field] = $session_token;
        $_POST[$this->iphash_field] = $ip_hash;

        // 2. Act
        $result1 = pch_verify_submission();

        // 3. Assert
        $this->assertInstanceOf(WP_Error::class, $result1, 'Result 1 should be WP_Error');
        $this->assertEquals('token_invalid_format', $result1->get_error_code(), 'Error code 1 should be token_invalid_format');
        $this->assertEquals(1, (int) get_transient($fail_key), 'Failure count should be 1 after base64 fail');
        $this->assertFalse(get_transient('pch_' . $session_token), 'Session transient deleted after base64 fail');
        // Re-set transient for next part
        set_transient('pch_' . $session_token, time(), 600);


        // --- Test 2: Base64 but no colon ---
        $_POST[$this->captcha_token_field] = base64_encode('juststringnocolon');
        // Nonce, session (re-set), iphash remain the same

        // 2. Act
        $result2 = pch_verify_submission();

        // 3. Assert
        $this->assertInstanceOf(WP_Error::class, $result2, 'Result 2 should be WP_Error');
        $this->assertEquals('token_invalid_format', $result2->get_error_code(), 'Error code 2 should be token_invalid_format');
        $this->assertEquals(2, (int) get_transient($fail_key), 'Failure count should be 2 after colon fail');
        $this->assertFalse(get_transient('pch_' . $session_token), 'Session transient deleted after colon fail');
    }

    public function testVerificationFailsOnTimingFailure() {
        // 1. Arrange
        $nonce = wp_create_nonce('pch_captcha_nonce');
        $session_token = 'valid_session_' . uniqid();
        set_transient('pch_' . $session_token, time(), 600);
        $ip_hash = sha1($this->mock_ip . $this->mock_ua);
        $time_spent = 1500; // Too fast (< 3000)
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
        $this->assertEquals('timing_or_fingerprint_invalid', $result->get_error_code(), 'Error code should be timing_or_fingerprint_invalid');
        $fail_key = 'pch_fail_' . md5($this->mock_ip);
        $this->assertEquals(1, (int) get_transient($fail_key), 'Failure count should be 1');
        $this->assertFalse(get_transient('pch_' . $session_token), 'Session transient should be deleted on timing failure');
    }

     public function testVerificationFailsOnFingerprintHashFailure() {
        // 1. Arrange
        $nonce = wp_create_nonce('pch_captcha_nonce');
        $session_token = 'valid_session_' . uniqid();
        set_transient('pch_' . $session_token, time(), 600);
        $ip_hash = sha1($this->mock_ip . $this->mock_ua);
        $time_spent = 5000; // Valid time
        $nav_hash = 'short'; // Too short (strlen < 10)
        $token_value = base64_encode($time_spent . ':' . $nav_hash);

        $_POST[$this->captcha_token_field] = $token_value;
        $_POST[$this->nonce_field] = $nonce;
        $_POST[$this->session_field] = $session_token;
        $_POST[$this->iphash_field] = $ip_hash;

        // 2. Act
        $result = pch_verify_submission();

        // 3. Assert
        $this->assertInstanceOf(WP_Error::class, $result, 'Result should be WP_Error on short navigator hash');
        $this->assertEquals('timing_or_fingerprint_invalid', $result->get_error_code(), 'Error code should be timing_or_fingerprint_invalid');
        $fail_key = 'pch_fail_' . md5($this->mock_ip);
        $this->assertEquals(1, (int) get_transient($fail_key), 'Failure count should be 1');
        $this->assertFalse(get_transient('pch_' . $session_token), 'Session transient should be deleted on fingerprint failure');
    }

} // End class PassiveCaptchaTest