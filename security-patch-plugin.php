<?php
/**
 * Plugin Name: Security Patch By Click Track Marketing
 * Description: Custom login URL changer and security patch manager for WordPress.
 * Version: 1.4.0
 * Author: Click Track Marketing
 * Author URI: https://www.clicktrackmarketing.com/
 */

if (!defined('ABSPATH')) {
    exit;
}

if (!defined('SPEEDX_SECURITY_PATCH_MAIN_FILE')) {
    define('SPEEDX_SECURITY_PATCH_MAIN_FILE', __FILE__);
}

require_once __DIR__ . '/speedx-security-patch.php';
