<?php
/**
 * PHPUnit bootstrap file for Passive CAPTCHA Hardened plugin.
 */

$_tests_dir = getenv('WP_TESTS_DIR') ?: '/tmp/wordpress/tests/phpunit'; // Define test lib path

// Load the WordPress test functions.
require_once $_tests_dir . '/includes/functions.php';

/**
 * Manually load the plugin being tested.
 */
function _load_passive_captcha_plugin() {
    // Loads the main plugin file
    require dirname(__DIR__) . '/passive-captcha-hardened.php';
}
// Hook to load the plugin during WP test setup
tests_add_filter('muplugins_loaded', '_load_passive_captcha_plugin');

// Start up the WP testing environment.
require $_tests_dir . '/includes/bootstrap.php';

// Ensure plugin activation.
require_once ABSPATH . 'wp-admin/includes/plugin.php';

// Use the correct plugin slug
$plugin_slug = 'passive-captcha-hardened/passive-captcha-hardened.php';

if (!is_plugin_active($plugin_slug)) {
    activate_plugin($plugin_slug);
    if (!is_plugin_active($plugin_slug)) {
        // Error if activation fails
        echo "Error: Failed to activate plugin {$plugin_slug}\n";
        exit(1);
    }
}
?>