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

if (!class_exists('SpeedX_Security_Patch')) {
    class SpeedX_Security_Patch {
        private $option_name = 'speedx_security_patch_settings';
        private $htaccess_marker = 'SpeedX Security Patch - wp-config Protection';
        private $lockout_minutes = 30;
        private $file_monitor_hash_option = 'speedx_security_patch_file_monitor_hash';
        private $file_monitor_snapshot_option = 'speedx_security_patch_file_monitor_snapshot';
        private $file_monitor_log_option = 'speedx_security_patch_file_monitor_log';
        private $file_monitor_notice_transient = 'speedx_security_patch_file_monitor_notice';
        private $readonly_permissions_option = 'speedx_security_patch_non_wp_content_permissions';

        public function __construct() {
            $plugin_file = defined('SPEEDX_SECURITY_PATCH_MAIN_FILE') ? SPEEDX_SECURITY_PATCH_MAIN_FILE : __FILE__;
            register_activation_hook($plugin_file, [$this, 'activate']);
            register_deactivation_hook($plugin_file, [$this, 'deactivate']);

            add_action('admin_menu', [$this, 'admin_menu']);
            add_action('admin_init', [$this, 'register_settings']);
            add_action('admin_init', [$this, 'enforce_non_wp_content_write_requests'], 1);
            add_action('admin_init', [$this, 'maybe_detect_core_file_changes'], 20);
            add_action('admin_post_speedx_save_settings', [$this, 'save_settings']);
            add_action('admin_post_speedx_mark_attack_resolved', [$this, 'mark_attack_resolved']);
            add_action('admin_notices', [$this, 'admin_notices']);

            add_action('admin_enqueue_scripts', [$this, 'admin_assets']);
            add_action('admin_head', [$this, 'admin_menu_branding_css']);
            add_action('admin_footer', [$this, 'force_remove_country_blocking_ui'], 99);

            add_action('init', [$this, 'intercept_login_requests'], 1);

            add_filter('site_url', [$this, 'filter_login_url'], 10, 4);
            add_filter('network_site_url', [$this, 'filter_login_url'], 10, 3);
            add_filter('login_url', [$this, 'custom_login_url'], 10, 3);
            add_filter('logout_url', [$this, 'custom_logout_url'], 10, 2);
            add_filter('lostpassword_url', [$this, 'custom_lostpassword_url'], 10, 2);
            add_filter('register_url', [$this, 'custom_register_url'], 10, 1);

            add_filter('authenticate', [$this, 'check_login_attempt_limit'], 1, 3);
            add_action('wp_login_failed', [$this, 'record_failed_login']);
            add_action('wp_login', [$this, 'clear_login_attempts'], 10, 2);
            add_filter('login_message', [$this, 'login_lockout_message']);
            add_filter('login_errors', [$this, 'filter_login_errors']);
            add_action('login_enqueue_scripts', [$this, 'lock_login_form_ui']);
        }

        public function activate() {
            $defaults = [
                'custom_login_slug' => 'secure-login',
                'protect_wp_config_htaccess' => 0,
                'disallow_file_edit' => 0,
                'core_file_change_alert' => 0,
                'lock_non_wp_content_writes' => 0,
                'login_attempt_limit' => 'none',
            ];

            if (!get_option($this->option_name)) {
                add_option($this->option_name, $defaults);
            }

            $this->remove_country_blocking_settings();

        }

        public function deactivate() {
            $settings = $this->get_settings();

            if (!empty($settings['protect_wp_config_htaccess'])) {
                $this->remove_htaccess_rule();
            }

            if (!empty($settings['disallow_file_edit'])) {
                $this->remove_wp_config_rule();
            }

            if (!empty($settings['lock_non_wp_content_writes'])) {
                $this->remove_non_wp_content_lock();
            }

            $this->remove_country_blocking_settings();

            delete_transient($this->file_monitor_notice_transient);
            delete_transient('speedx_security_patch_file_monitor_scan_lock');
            delete_option($this->file_monitor_snapshot_option);
            delete_option($this->file_monitor_hash_option);
        }

        private function get_settings() {
            $defaults = [
                'custom_login_slug' => 'secure-login',
                'protect_wp_config_htaccess' => 0,
                'disallow_file_edit' => 0,
                'core_file_change_alert' => 0,
                'lock_non_wp_content_writes' => 0,
                'login_attempt_limit' => 'none',
            ];

            $settings = get_option($this->option_name, []);
            $settings = wp_parse_args($settings, $defaults);

            return $settings;
        }

        public function admin_menu() {
            add_menu_page(
                'ClickTrack Security Patch',
                'Security Patch',
                'manage_options',
                'speedx-security-patch',
                [$this, 'settings_page'],
                'dashicons-shield-alt',
                80
            );
        }

        public function register_settings() {
            register_setting($this->option_name, $this->option_name);
        }

        public function admin_assets($hook) {
            if ($hook !== 'toplevel_page_speedx-security-patch') {
                return;
            }

            wp_enqueue_style('dashicons');
        }

        public function admin_menu_branding_css() {
            ?>
            <style>
                #adminmenu .toplevel_page_speedx-security-patch .wp-menu-image:before{
                    color:#18bfff !important;
                }
                #adminmenu .toplevel_page_speedx-security-patch.current .wp-menu-image:before,
                #adminmenu .toplevel_page_speedx-security-patch.wp-has-current-submenu .wp-menu-image:before,
                #adminmenu .toplevel_page_speedx-security-patch:hover .wp-menu-image:before{
                    color:#40d4ff !important;
                }
            </style>
            <?php
        }

        public function force_remove_country_blocking_ui() {
            if (!is_admin() || !current_user_can('manage_options')) {
                return;
            }

            $page = isset($_GET['page']) ? sanitize_key(wp_unslash($_GET['page'])) : '';
            if ($page !== 'speedx-security-patch') {
                return;
            }
            ?>
            <script>
                (function () {
                    function removeCountryBlockingUi() {
                        var headingNodes = document.querySelectorAll('h1,h2,h3,strong,span,p,label,div');
                        headingNodes.forEach(function (node) {
                            var text = (node.textContent || '').trim().toLowerCase();
                            if (!text) return;

                            if (text === 'country blocking') {
                                var section = node.closest('.ctm-section, .ctm-field');
                                if (section) {
                                    section.remove();
                                }
                            }

                            if (text === 'blocked countries') {
                                var metric = node.closest('.ctm-mini-metric');
                                if (metric) {
                                    metric.remove();
                                }
                            }
                        });

                        document.querySelectorAll('input[name*=\"country\"], select[name*=\"country\"], textarea[name*=\"country\"]').forEach(function (el) {
                            el.remove();
                        });
                    }

                    document.addEventListener('DOMContentLoaded', removeCountryBlockingUi);
                    removeCountryBlockingUi();
                    var observer = new MutationObserver(removeCountryBlockingUi);
                    observer.observe(document.body, { childList: true, subtree: true });
                })();
            </script>
            <?php
        }

        public function settings_page() {
            if (!current_user_can('manage_options')) {
                return;
            }

            $settings = $this->get_settings();
            $custom_login_url = home_url('/' . trim($settings['custom_login_slug'], '/') . '/');
            $malicious_logs = get_option($this->file_monitor_log_option, []);
            if (!is_array($malicious_logs)) {
                $malicious_logs = [];
            }
            $uploaded_file_logs = array_filter($malicious_logs, function ($log_item) {
                return isset($log_item['type']) && $log_item['type'] === 'uploaded file' && empty($log_item['resolved']);
            });
            ?>
            <div class="wrap speedx-security-wrap">
                <div class="ctm-hero">
                    <div class="ctm-hero__badge">ClickTrack Marketing Security Suite</div>
                    <div class="ctm-hero__top">
                        <div>
                            <h1>Security Patch</h1>
                            <p>Harden WordPress sites with ClickTrack-style protection, cleaner controls, and a dark premium admin experience.</p>
                        </div>
                        <div class="ctm-stats">
                            <div class="ctm-stat">
                                <span class="ctm-stat__value"><?php echo esc_html(strtoupper($settings['login_attempt_limit'])); ?></span>
                                <span class="ctm-stat__label">Login Limit</span>
                            </div>
                        </div>
                    </div>
                </div>

                <div class="ctm-card-grid">
                    <div class="ctm-card ctm-card--main">
                        <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>">
                            <?php wp_nonce_field('speedx_save_settings_action', 'speedx_nonce'); ?>
                            <input type="hidden" name="action" value="speedx_save_settings">

                            <div class="ctm-section">
                                <div class="ctm-section__head">
                                    <h2>Custom Login Access</h2>
                                    <p>Replace the default WordPress login path with your own secure URL.</p>
                                </div>

                                <div class="ctm-field">
                                    <label for="custom_login_slug">Custom Login URL</label>
                                    <div class="ctm-url-row">
                                        <span class="ctm-url-prefix"><?php echo esc_html(home_url('/')); ?></span>
                                        <input type="text" id="custom_login_slug" name="custom_login_slug" value="<?php echo esc_attr($settings['custom_login_slug']); ?>" />
                                    </div>
                                    <p class="ctm-help">Only type the slug part. Example: <strong>secure-entry</strong></p>
                                    <div class="ctm-highlight-row">
                                        <span class="ctm-pill-label">Current Login URL</span>
                                        <a class="ctm-current-url" href="<?php echo esc_url($custom_login_url); ?>" target="_blank"><?php echo esc_html($custom_login_url); ?></a>
                                    </div>
                                </div>
                            </div>

                            <div class="ctm-section">
                                <div class="ctm-section__head">
                                    <h2>Core Security Patches</h2>
                                    <p>Enable the most common filesystem hardening controls from one place.</p>
                                </div>

                                <label class="ctm-toggle-card">
                                    <span class="ctm-toggle-card__text">
                                        <strong>Protect wp-config.php in .htaccess</strong>
                                        <small>Adds the protection rule at the end of the root .htaccess file.</small>
                                    </span>
                                    <span class="ctm-switch">
                                        <input type="checkbox" name="protect_wp_config_htaccess" value="1" <?php checked(!empty($settings['protect_wp_config_htaccess'])); ?> />
                                        <span class="ctm-slider"></span>
                                    </span>
                                </label>

                                <label class="ctm-toggle-card">
                                    <span class="ctm-toggle-card__text">
                                        <strong>Disable File Editor</strong>
                                        <small>Places <code>define('DISALLOW_FILE_EDIT', true);</code> directly below the Happy publishing line in wp-config.php.</small>
                                    </span>
                                    <span class="ctm-switch">
                                        <input type="checkbox" name="disallow_file_edit" value="1" <?php checked(!empty($settings['disallow_file_edit'])); ?> />
                                        <span class="ctm-slider"></span>
                                    </span>
                                </label>

                                <label class="ctm-toggle-card">
                                    <span class="ctm-toggle-card__text">
                                        <strong>Alert on Core File Changes</strong>
                                        <small>Shows a red admin alert when files outside <code>wp-content</code> are created, removed, or edited.</small>
                                    </span>
                                    <span class="ctm-switch">
                                        <input type="checkbox" name="core_file_change_alert" value="1" <?php checked(!empty($settings['core_file_change_alert'])); ?> />
                                        <span class="ctm-slider"></span>
                                    </span>
                                </label>

                                <label class="ctm-toggle-card">
                                    <span class="ctm-toggle-card__text">
                                        <strong>Disable file editing and uploading completely except wp-content</strong>
                                        <small>Sets files/folders outside <code>wp-content</code> to read-only so they appear greyed out and cannot be edited/uploaded.</small>
                                    </span>
                                    <span class="ctm-switch">
                                        <input type="checkbox" name="lock_non_wp_content_writes" value="1" <?php checked(!empty($settings['lock_non_wp_content_writes'])); ?> />
                                        <span class="ctm-slider"></span>
                                    </span>
                                </label>
                            </div>

                            <div class="ctm-section">
                                <div class="ctm-section__head">
                                    <h2>Login Protection</h2>
                                    <p>Block repeated failed logins and freeze the form for 30 minutes once the limit is reached.</p>
                                </div>

                                <div class="ctm-field">
                                    <label for="login_attempt_limit">Limit Login Attempts</label>
                                    <select id="login_attempt_limit" name="login_attempt_limit">
                                        <option value="none" <?php selected($settings['login_attempt_limit'], 'none'); ?>>None</option>
                                        <option value="3" <?php selected($settings['login_attempt_limit'], '3'); ?>>3 Attempts</option>
                                        <option value="5" <?php selected($settings['login_attempt_limit'], '5'); ?>>5 Attempts</option>
                                    </select>
                                    <p class="ctm-help">After the selected number of failed login attempts, the login form is locked for <?php echo esc_html($this->lockout_minutes); ?> minutes.</p>
                                </div>
                            </div>

                            <div class="ctm-section">
                                <div class="ctm-section__head">
                                    <h2>Malicious Attack Alerts</h2>
                                    <p>Recent uploaded files detected outside <code>wp-content</code>, including full path and detection date/time.</p>
                                </div>

                                <?php if (empty($uploaded_file_logs)) : ?>
                                    <p class="ctm-help">No uploaded files detected yet outside <code>wp-content</code>.</p>
                                <?php else : ?>
                                    <div class="ctm-attack-table-wrap">
                                        <table class="ctm-attack-table">
                                            <thead>
                                                <tr>
                                                    <th>Type</th>
                                                    <th>Full Path</th>
                                                    <th>Day</th>
                                                    <th>Date &amp; Time</th>
                                                    <th>Resolve</th>
                                                </tr>
                                            </thead>
                                            <tbody>
                                                <?php foreach (array_slice($uploaded_file_logs, 0, 25, true) as $log_key => $log_item) : ?>
                                                    <tr>
                                                        <td><?php echo esc_html(isset($log_item['type']) ? ucwords($log_item['type']) : 'Unknown'); ?></td>
                                                        <td><code><?php echo esc_html(isset($log_item['path']) ? $log_item['path'] : ''); ?></code></td>
                                                        <td><?php echo esc_html(isset($log_item['day']) ? $log_item['day'] : ''); ?></td>
                                                        <td><?php echo esc_html(isset($log_item['datetime']) ? $log_item['datetime'] : ''); ?></td>
                                                        <td>
                                                            <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>">
                                                                <?php wp_nonce_field('speedx_mark_attack_resolved_action', 'speedx_resolve_nonce'); ?>
                                                                <input type="hidden" name="action" value="speedx_mark_attack_resolved">
                                                                <input type="hidden" name="log_key" value="<?php echo esc_attr((string) $log_key); ?>">
                                                                <input type="hidden" name="log_id" value="<?php echo esc_attr(isset($log_item['id']) ? (string) $log_item['id'] : ''); ?>">
                                                                <button type="submit" class="button ctm-resolve-btn" title="Mark as resolved">✔</button>
                                                            </form>
                                                        </td>
                                                    </tr>
                                                <?php endforeach; ?>
                                            </tbody>
                                        </table>
                                    </div>
                                <?php endif; ?>
                            </div>

                            <div class="ctm-submit-row">
                                <?php submit_button('Save Security Settings', 'primary', 'submit', false); ?>
                            </div>
                        </form>
                    </div>

                    <div class="ctm-card ctm-card--side">
                        <div class="ctm-side-block">
                            <h3>Live Summary</h3>
                            <div class="ctm-mini-metric">
                                <span>Custom Login</span>
                                <strong><?php echo esc_html('/' . trim($settings['custom_login_slug'], '/')); ?></strong>
                            </div>
                            <div class="ctm-mini-metric">
                                <span>Login Attempts</span>
                                <strong><?php echo esc_html($settings['login_attempt_limit']); ?></strong>
                            </div>
                            <div class="ctm-mini-metric">
                                <span>Core File Alert</span>
                                <strong><?php echo !empty($settings['core_file_change_alert']) ? 'On' : 'Off'; ?></strong>
                            </div>
                            <div class="ctm-mini-metric">
                                <span>Non-wp-content Lock</span>
                                <strong><?php echo !empty($settings['lock_non_wp_content_writes']) ? 'On' : 'Off'; ?></strong>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <style>
                @import url('https://fonts.googleapis.com/css2?family=Poppins:wght@400;500;600;700;800&display=swap');
                body.toplevel_page_speedx-security-patch{
                    background:#0b1119;
                }
                body.toplevel_page_speedx-security-patch #wpcontent{
                    background:linear-gradient(180deg, #0b1119 0%, #090f17 100%);
                }
                body.toplevel_page_speedx-security-patch #wpbody-content{
                    padding-bottom:24px;
                }
                .speedx-security-wrap{
                    margin:18px 12px 0 2px;
                    color:#d8ecff;
                    font-family: Poppins, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Arial, sans-serif;
                }
                .speedx-security-wrap,
                .speedx-security-wrap *{
                    font-family: Poppins, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Arial, sans-serif;
                }
                .speedx-security-wrap *, .speedx-security-wrap *:before, .speedx-security-wrap *:after{
                    box-sizing:border-box;
                }
                .speedx-security-wrap .notice{
                    margin-left:0;
                }
                .ctm-hero{
                    max-width:none;
                    width:100%;
                    padding:28px;
                    border-radius:22px;
                    background:
                        linear-gradient(180deg, rgba(5,19,42,.9), rgba(3,11,27,.96)),
                        radial-gradient(circle at top right, rgba(33,191,255,.28), transparent 35%),
                        radial-gradient(circle at bottom left, rgba(0,117,255,.18), transparent 30%);
                    border:1px solid rgba(76,188,255,.22);
                    box-shadow:0 10px 40px rgba(0,0,0,.22);
                    margin-top:16px;
                    position:relative;
                    overflow:hidden;
                }
                .ctm-hero:before{
                    content:"";
                    position:absolute;
                    inset:auto -90px -120px auto;
                    width:260px;
                    height:260px;
                    border-radius:50%;
                    border:1px solid rgba(77,203,255,.18);
                    box-shadow:0 0 0 30px rgba(77,203,255,.05), 0 0 0 60px rgba(77,203,255,.03);
                    pointer-events:none;
                }
                .ctm-hero__badge{
                    display:inline-flex;
                    align-items:center;
                    gap:8px;
                    padding:8px 14px;
                    border-radius:999px;
                    background:rgba(24,191,255,.12);
                    color:#66d4ff;
                    border:1px solid rgba(70,198,255,.2);
                    font-size:12px;
                    font-weight:600;
                    letter-spacing:.04em;
                    text-transform:uppercase;
                    margin-bottom:18px;
                }
                .ctm-hero__top{
                    display:flex;
                    justify-content:space-between;
                    align-items:flex-start;
                    gap:20px;
                    flex-wrap:wrap;
                }
                .ctm-hero h1{
                    margin:0 0 10px 0;
                    color:#fff;
                    font-size:34px;
                    line-height:1.1;
                    font-weight:800;
                }
                .ctm-hero p{
                    margin:0;
                    font-size:15px;
                    line-height:1.7;
                    color:#ffffff;
                    max-width:860px;
                }
                .ctm-stats{
                    display:flex;
                    gap:14px;
                    flex-wrap:wrap;
                }
                .ctm-stat{
                    min-width:145px;
                    padding:16px 18px;
                    border-radius:16px;
                    background:linear-gradient(180deg, rgba(13,30,59,.95), rgba(8,19,40,.95));
                    border:1px solid rgba(76,188,255,.16);
                    box-shadow:inset 0 1px 0 rgba(255,255,255,.03);
                }
                .ctm-stat__value{
                    display:block;
                    color:#1fcbff;
                    font-size:24px;
                    font-weight:800;
                    line-height:1;
                    margin-bottom:8px;
                }
                .ctm-stat__label{
                    display:block;
                    color:#ffffff;
                    font-size:12px;
                    text-transform:uppercase;
                    letter-spacing:.06em;
                }
                .ctm-card-grid{
                    max-width:none;
                    width:100%;
                    margin-top:22px;
                    display:grid;
                    grid-template-columns:minmax(0,1fr) minmax(300px, 26%);
                    gap:22px;
                    align-items:start;
                }
                .ctm-card{
                    background:linear-gradient(180deg, #07162f 0%, #041122 100%);
                    border:1px solid rgba(79,192,255,.16);
                    border-radius:22px;
                    box-shadow:0 14px 40px rgba(0,0,0,.2);
                }
                .ctm-card--main{
                    padding:26px;
                }
                .ctm-card--side{
                    padding:22px;
                    position:sticky;
                    top:32px;
                }
                .ctm-section{
                    padding:22px;
                    border-radius:18px;
                    background:linear-gradient(180deg, rgba(10,25,49,.9), rgba(5,15,30,.95));
                    border:1px solid rgba(74,180,255,.11);
                    margin-bottom:18px;
                }
                .ctm-section__head{
                    margin-bottom:18px;
                }
                .ctm-section__head h2{
                    margin:0 0 6px 0;
                    color:#fff;
                    font-size:22px;
                    font-weight:750;
                }
                .ctm-section__head p{
                    margin:0;
                    color:#ffffff;
                    font-size:14px;
                    line-height:1.7;
                }
                .ctm-field label{
                    display:block;
                    margin-bottom:10px;
                    color:#dff3ff;
                    font-size:13px;
                    font-weight:700;
                    text-transform:uppercase;
                    letter-spacing:.04em;
                }
                .ctm-url-row{
                    display:flex;
                    align-items:center;
                    flex-wrap:wrap;
                    gap:10px;
                }
                .ctm-url-prefix{
                    display:inline-flex;
                    align-items:center;
                    min-height:46px;
                    padding:0 14px;
                    border-radius:12px;
                    background:#07101b;
                    border:1px solid rgba(82,197,255,.18);
                    color:#7bbad7;
                }
                .speedx-security-wrap input[type="text"],
                .speedx-security-wrap select{
                    min-height:46px;
                    padding:0 14px;
                    border-radius:12px;
                    border:1px solid rgba(86,199,255,.18);
                    background:#07101b;
                    color:#f0fbff;
                    box-shadow:none;
                }
                .speedx-security-wrap input[type="text"]::placeholder{
                    color:#6f94aa;
                }
                .speedx-security-wrap input[type="text"]:focus,
                .speedx-security-wrap select:focus{
                    border-color:#1cc8ff;
                    box-shadow:0 0 0 1px #1cc8ff;
                    outline:none;
                }
                .ctm-help{
                    margin:10px 0 0;
                    color:#ffffff;
                }
                .ctm-attack-table-wrap{
                    overflow:auto;
                    border:1px solid rgba(82,197,255,.13);
                    border-radius:14px;
                }
                .ctm-attack-table{
                    width:100%;
                    border-collapse:collapse;
                    min-width:700px;
                    background:rgba(5,14,27,.92);
                }
                .ctm-attack-table th,
                .ctm-attack-table td{
                    text-align:left;
                    padding:11px 12px;
                    border-bottom:1px solid rgba(82,197,255,.1);
                    color:#cbe8fb;
                    font-size:13px;
                    vertical-align:top;
                }
                .ctm-attack-table th{
                    color:#7fd3fb;
                    font-size:12px;
                    text-transform:uppercase;
                    letter-spacing:.05em;
                    background:rgba(11,28,52,.95);
                }
                .ctm-attack-table tr:last-child td{
                    border-bottom:0;
                }
                .ctm-attack-table code{
                    color:#9fe2ff;
                    background:transparent;
                    padding:0;
                }
                .ctm-resolve-btn{
                    min-width:34px;
                    height:30px;
                    line-height:1;
                    padding:0;
                    border-radius:8px;
                    border:1px solid rgba(84,206,132,.45) !important;
                    color:#8fffc5 !important;
                    background:rgba(15,57,33,.8) !important;
                    font-weight:700;
                }
                .ctm-resolve-btn:hover{
                    background:rgba(20,76,43,.95) !important;
                    color:#ffffff !important;
                }
                .ctm-highlight-row{
                    margin-top:14px;
                    display:flex;
                    align-items:center;
                    flex-wrap:wrap;
                    gap:10px;
                }
                .ctm-pill-label{
                    display:inline-flex;
                    padding:7px 12px;
                    border-radius:999px;
                    background:rgba(20,177,255,.11);
                    border:1px solid rgba(20,177,255,.18);
                    color:#74d7ff;
                    font-size:12px;
                    font-weight:700;
                    text-transform:uppercase;
                    letter-spacing:.05em;
                }
                .ctm-current-url{
                    color:#a5e8ff;
                    text-decoration:none;
                    font-weight:700;
                    word-break:break-all;
                }
                .ctm-current-url:hover{
                    color:#fff;
                }
                .ctm-toggle-card{
                    display:flex;
                    justify-content:space-between;
                    align-items:center;
                    gap:16px;
                    padding:16px 18px;
                    border-radius:16px;
                    background:rgba(6,19,37,.85);
                    border:1px solid rgba(82,197,255,.1);
                    margin-bottom:12px;
                }
                .ctm-toggle-card__text{
                    display:block;
                }
                .ctm-toggle-card__text strong{
                    display:block;
                    color:#fff;
                    font-size:15px;
                    margin-bottom:5px;
                }
                .ctm-toggle-card__text small{
                    display:block;
                    color:#ffffff;
                    line-height:1.7;
                    font-size:13px;
                }
                .ctm-switch{
                    position:relative;
                    width:58px;
                    height:32px;
                    flex:0 0 auto;
                }
                .ctm-switch input{
                    opacity:0;
                    width:0;
                    height:0;
                    position:absolute;
                }
                .ctm-slider{
                    position:absolute;
                    inset:0;
                    background:#243649;
                    border:1px solid rgba(255,255,255,.08);
                    border-radius:999px;
                    transition:.2s ease;
                }
                .ctm-slider:before{
                    content:"";
                    position:absolute;
                    width:22px;
                    height:22px;
                    left:4px;
                    top:4px;
                    background:#fff;
                    border-radius:50%;
                    transition:.2s ease;
                }
                .ctm-switch input:checked + .ctm-slider{
                    background:linear-gradient(90deg, #0b9bff, #22d1ff);
                }
                .ctm-switch input:checked + .ctm-slider:before{
                    transform:translateX(26px);
                }
                .speedx-security-wrap .button,
                .speedx-security-wrap .button-secondary,
                .speedx-security-wrap .button-primary{
                    border-radius:12px;
                    min-height:42px;
                    padding:0 16px !important;
                    border:1px solid rgba(79,192,255,.22);
                    box-shadow:none !important;
                    transition:.2s ease;
                }
                .speedx-security-wrap .button-secondary{
                    background:#091726 !important;
                    color:#d8efff !important;
                }
                .speedx-security-wrap .button-secondary:hover{
                    background:#102338 !important;
                    color:#fff !important;
                    border-color:#24caff !important;
                }
                .speedx-security-wrap .button-primary{
                    background:linear-gradient(90deg, #008bff, #1ecfff) !important;
                    border-color:transparent !important;
                    color:#fff !important;
                    font-weight:700;
                }
                .speedx-security-wrap .button-primary:hover{
                    filter:brightness(1.06);
                }
                .ctm-submit-row{
                    display:flex;
                    justify-content:flex-start;
                    padding-top:8px;
                }
                .ctm-side-block{
                    padding:18px;
                    border-radius:16px;
                    background:rgba(255,255,255,.025);
                    border:1px solid rgba(83,197,255,.1);
                    margin-bottom:14px;
                }
                .ctm-side-block h3{
                    margin:0 0 10px 0;
                    color:#fff;
                    font-size:17px;
                }
                .ctm-side-block p,
                .ctm-side-block li{
                    color:#ffffff;
                    line-height:1.75;
                    margin:0;
                    font-size:14px;
                }
                .ctm-side-block ul{
                    margin:0;
                    padding-left:18px;
                }
                .ctm-mini-metric{
                    display:flex;
                    justify-content:space-between;
                    gap:12px;
                    padding:10px 0;
                    border-bottom:1px solid rgba(255,255,255,.06);
                }
                .ctm-mini-metric:last-child{
                    border-bottom:0;
                    padding-bottom:0;
                }
                .ctm-mini-metric span{
                    color:#ffffff;
                }
                .ctm-mini-metric strong{
                    color:#33d0ff;
                }
                .speedx-security-wrap code{
                    background:#0a1625;
                    color:#8fdfff;
                    padding:2px 6px;
                    border-radius:6px;
                }
                @media (max-width: 1160px){
                    .ctm-card-grid{
                        grid-template-columns:1fr;
                    }
                    .ctm-card--side{
                        position:static;
                    }
                }
                @media (max-width: 680px){
                    .ctm-hero{
                        padding:22px;
                    }
                    .ctm-card--main,
                    .ctm-card--side{
                        padding:18px;
                    }
                    .ctm-section{
                        padding:18px;
                    }
                }
            </style>

            <?php
        }

        public function save_settings() {
            if (!current_user_can('manage_options')) {
                wp_die('Unauthorized access.');
            }

            check_admin_referer('speedx_save_settings_action', 'speedx_nonce');

            $new_slug = isset($_POST['custom_login_slug']) ? sanitize_title(wp_unslash($_POST['custom_login_slug'])) : 'secure-login';
            $new_slug = !empty($new_slug) ? $new_slug : 'secure-login';

            $login_attempt_limit = isset($_POST['login_attempt_limit']) ? sanitize_text_field(wp_unslash($_POST['login_attempt_limit'])) : 'none';
            if (!in_array($login_attempt_limit, ['none', '3', '5'], true)) {
                $login_attempt_limit = 'none';
            }

            $new_settings = [
                'custom_login_slug' => $new_slug,
                'protect_wp_config_htaccess' => isset($_POST['protect_wp_config_htaccess']) ? 1 : 0,
                'disallow_file_edit' => isset($_POST['disallow_file_edit']) ? 1 : 0,
                'core_file_change_alert' => isset($_POST['core_file_change_alert']) ? 1 : 0,
                'lock_non_wp_content_writes' => isset($_POST['lock_non_wp_content_writes']) ? 1 : 0,
                'login_attempt_limit' => $login_attempt_limit,
            ];

            update_option($this->option_name, $new_settings);
            $this->remove_country_blocking_settings();
            if (!empty($new_settings['protect_wp_config_htaccess'])) {
                $this->add_htaccess_rule();
            } else {
                $this->remove_htaccess_rule();
            }

            if (!empty($new_settings['disallow_file_edit'])) {
                $this->add_wp_config_rule();
            } else {
                $this->remove_wp_config_rule();
            }

            if (!empty($new_settings['lock_non_wp_content_writes'])) {
                $this->apply_non_wp_content_lock();
            } else {
                $this->remove_non_wp_content_lock();
            }

            if ($login_attempt_limit === 'none') {
                delete_transient($this->get_attempts_key());
                delete_transient($this->get_lockout_key());
            }

            if (!empty($new_settings['core_file_change_alert'])) {
                if (!get_option($this->file_monitor_snapshot_option)) {
                    $baseline_snapshot = $this->collect_core_file_snapshot();
                    if (!empty($baseline_snapshot)) {
                        update_option($this->file_monitor_snapshot_option, $baseline_snapshot, false);
                        update_option($this->file_monitor_hash_option, $this->hash_snapshot($baseline_snapshot), false);
                    }
                }
            } else {
                delete_option($this->file_monitor_hash_option);
                delete_option($this->file_monitor_snapshot_option);
                delete_option($this->file_monitor_log_option);
                delete_transient($this->file_monitor_notice_transient);
                delete_transient('speedx_security_patch_file_monitor_scan_lock');
            }

            $redirect_url = add_query_arg(
                [
                    'page' => 'speedx-security-patch',
                    'speedx_saved' => '1',
                ],
                admin_url('admin.php')
            );

            wp_safe_redirect($redirect_url);
            exit;
        }

        /**
         * Permanently remove legacy country-blocking settings/options.
         */
        private function remove_country_blocking_settings() {
            $settings = get_option($this->option_name, []);
            if (!is_array($settings)) {
                $settings = [];
            }

            $country_blocking_keys = [
                'country_blocking_enabled',
                'blocked_countries',
                'allowed_countries',
                'country_blocking_mode',
            ];

            $updated = false;
            foreach ($country_blocking_keys as $key) {
                if (array_key_exists($key, $settings)) {
                    unset($settings[$key]);
                    $updated = true;
                }
            }

            if ($updated) {
                update_option($this->option_name, $settings);
            }

            delete_option('speedx_security_patch_country_blocking_enabled');
            delete_option('speedx_security_patch_blocked_countries');
            delete_option('speedx_security_patch_allowed_countries');
            delete_option('speedx_security_patch_country_blocking_mode');
        }

        public function admin_notices() {
            if (!current_user_can('manage_options')) {
                return;
            }

            $monitor_notice = get_transient($this->file_monitor_notice_transient);
            if (!empty($monitor_notice)) {
                echo '<div class="notice notice-error"><p><strong>Security Alert:</strong> ' . esc_html($monitor_notice) . '</p></div>';
            }

            if (!isset($_GET['page']) || $_GET['page'] !== 'speedx-security-patch') {
                return;
            }

            if (!empty($_GET['speedx_saved'])) {
                $settings = $this->get_settings();
                $login_url = home_url('/' . trim($settings['custom_login_slug'], '/') . '/');
                echo '<div class="notice notice-success is-dismissible"><p><strong>Settings saved.</strong> Login URL: <a href="' . esc_url($login_url) . '" target="_blank">' . esc_html($login_url) . '</a></p></div>';
            }
        }

        public function mark_attack_resolved() {
            if (!current_user_can('manage_options')) {
                wp_die('Unauthorized access.');
            }

            check_admin_referer('speedx_mark_attack_resolved_action', 'speedx_resolve_nonce');

            $log_key = isset($_POST['log_key']) ? sanitize_text_field(wp_unslash($_POST['log_key'])) : '';
            $log_id = isset($_POST['log_id']) ? sanitize_text_field(wp_unslash($_POST['log_id'])) : '';
            $logs = get_option($this->file_monitor_log_option, []);

            if (is_array($logs)) {
                foreach ($logs as $index => $entry) {
                    $entry_id = isset($entry['id']) ? (string) $entry['id'] : '';
                    if ((string) $index === (string) $log_key || (!empty($log_id) && $entry_id === $log_id)) {
                        $logs[$index]['resolved'] = 1;
                        break;
                    }
                }
                update_option($this->file_monitor_log_option, $logs, false);
            }

            $redirect_url = add_query_arg(
                [
                    'page' => 'speedx-security-patch',
                ],
                admin_url('admin.php')
            );

            wp_safe_redirect($redirect_url);
            exit;
        }

        private function apply_non_wp_content_lock() {
            if (!function_exists('chmod')) {
                return;
            }

            $root_path = wp_normalize_path(trailingslashit(ABSPATH));
            $excluded_path = wp_normalize_path($root_path . 'wp-content' . DIRECTORY_SEPARATOR);
            $permission_map = [];

            $root_current_perms = @fileperms($root_path);
            if ($root_current_perms !== false) {
                $permission_map[$root_path] = substr(sprintf('%o', $root_current_perms), -4);
            }
            @chmod($root_path, 0555);

            try {
                $iterator = new RecursiveIteratorIterator(
                    new RecursiveDirectoryIterator($root_path, FilesystemIterator::SKIP_DOTS),
                    RecursiveIteratorIterator::SELF_FIRST,
                    RecursiveIteratorIterator::CATCH_GET_CHILD
                );
            } catch (Exception $e) {
                return;
            }

            foreach ($iterator as $item) {
                $pathname = wp_normalize_path($item->getPathname());
                if (strpos($pathname, $excluded_path) === 0 || is_link($pathname)) {
                    continue;
                }

                $relative = str_replace($root_path, '', $pathname);
                if ($relative === '') {
                    continue;
                }

                $current_perms = @fileperms($pathname);
                if ($current_perms !== false) {
                    $permission_map[$pathname] = substr(sprintf('%o', $current_perms), -4);
                }

                if (is_link($pathname)) {
                    continue;
                }

                if ($item->isDir()) {
                    @chmod($pathname, 0555);
                } elseif ($item->isFile()) {
                    @chmod($pathname, 0444);
                }
            }

            update_option($this->readonly_permissions_option, $permission_map, false);
        }

        private function remove_non_wp_content_lock() {
            if (!function_exists('chmod')) {
                return;
            }

            $permission_map = get_option($this->readonly_permissions_option, []);
            if (!is_array($permission_map) || empty($permission_map)) {
                return;
            }

            foreach ($permission_map as $pathname => $mode) {
                if (!file_exists($pathname)) {
                    continue;
                }
                @chmod($pathname, octdec((string) $mode));
            }

            delete_option($this->readonly_permissions_option);
        }

        public function enforce_non_wp_content_write_requests() {
            if (!is_admin() || strtoupper((string) ($_SERVER['REQUEST_METHOD'] ?? 'GET')) !== 'POST') {
                return;
            }

            $settings = $this->get_settings();
            if (empty($settings['lock_non_wp_content_writes'])) {
                return;
            }

            $action = isset($_REQUEST['action']) ? sanitize_text_field(wp_unslash($_REQUEST['action'])) : '';
            if (in_array($action, ['speedx_save_settings', 'speedx_mark_attack_resolved'], true)) {
                return;
            }

            if (!$this->is_probable_write_request()) {
                return;
            }

            $paths = $this->extract_request_paths_for_lock_check();
            foreach ($paths as $path) {
                if ($this->is_non_wp_content_path($path)) {
                    wp_die('Blocked by Security Patch: Editing/uploading outside wp-content is disabled.', 403);
                }
            }

            if (empty($paths) && $this->is_known_file_manager_write_action($action)) {
                wp_die('Blocked by Security Patch: Editing/uploading outside wp-content is disabled.', 403);
            }
        }

        private function is_probable_write_request() {
            $write_cmds = ['upload', 'put', 'rename', 'rm', 'mkdir', 'mkfile', 'paste', 'duplicate', 'archive', 'extract', 'chmod', 'save'];
            $write_action_hints = ['upload', 'save', 'edit', 'delete', 'remove', 'rename', 'mkdir', 'mkfile', 'paste', 'extract', 'archive', 'chmod'];

            $cmd = isset($_REQUEST['cmd']) ? strtolower(sanitize_text_field(wp_unslash($_REQUEST['cmd']))) : '';
            if (in_array($cmd, $write_cmds, true)) {
                return true;
            }

            $action = isset($_REQUEST['action']) ? strtolower(sanitize_text_field(wp_unslash($_REQUEST['action']))) : '';
            foreach ($write_action_hints as $hint) {
                if ($action !== '' && strpos($action, $hint) !== false) {
                    return true;
                }
            }

            return false;
        }

        private function is_known_file_manager_write_action($action) {
            $action = strtolower((string) $action);
            $known_actions = [
                'upload_file_folder_manager',
                'save_file_folder_manager',
                'delete_file_folder_manager',
                'rename_file_folder_manager',
                'mk_file_folder_manager',
                'paste_file_folder_manager',
                'archive_file_folder_manager',
                'extract_file_folder_manager',
                'chmod_file_folder_manager',
                'duplicate_file_folder_manager',
            ];

            return in_array($action, $known_actions, true);
        }

        private function extract_request_paths_for_lock_check() {
            $candidates = [];

            $walker = function ($value) use (&$walker, &$candidates) {
                if (is_array($value)) {
                    foreach ($value as $nested) {
                        $walker($nested);
                    }
                    return;
                }

                if (!is_string($value) || $value === '') {
                    return;
                }

                $raw = wp_unslash($value);
                $candidates[] = $raw;

                $decoded = base64_decode(strtr($raw, '-_', '+/'), true);
                if (is_string($decoded) && $decoded !== '') {
                    $candidates[] = $decoded;
                }

                if (strpos($raw, '_') !== false) {
                    $parts = explode('_', $raw);
                    $tail = end($parts);
                    $tail_decoded = base64_decode(strtr((string) $tail, '-_', '+/'), true);
                    if (is_string($tail_decoded) && $tail_decoded !== '') {
                        $candidates[] = $tail_decoded;
                    }
                    return;
                }

                if (!is_string($value) || $value === '') {
                    return;
                }

                $raw = wp_unslash($value);
                $candidates[] = $raw;

                $decoded = base64_decode(strtr($raw, '-_', '+/'), true);
                if (is_string($decoded) && $decoded !== '') {
                    $candidates[] = $decoded;
                }

                if (strpos($raw, '_') !== false) {
                    $parts = explode('_', $raw);
                    $tail = end($parts);
                    $tail_decoded = base64_decode(strtr((string) $tail, '-_', '+/'), true);
                    if (is_string($tail_decoded) && $tail_decoded !== '') {
                        $candidates[] = $tail_decoded;
                    }
                }
            };

            $walker($_REQUEST);
            $normalized = [];
            foreach ($candidates as $candidate) {
                $candidate = trim((string) $candidate);
                if ($candidate === '') {
                    continue;
                }

                $path = $candidate;
                if ($candidate[0] !== '/' && strpos($candidate, ':\\') === false) {
                    $path = trailingslashit(ABSPATH) . ltrim($candidate, '/');
                }
                $normalized[] = wp_normalize_path($path);
            }

            return array_values(array_unique($normalized));
        }

        private function is_non_wp_content_path($path) {
            $path = wp_normalize_path((string) $path);
            $root = wp_normalize_path(trailingslashit(ABSPATH));
            $allowed = wp_normalize_path($root . 'wp-content' . DIRECTORY_SEPARATOR);

            if (strpos($path, $root) !== 0) {
                return false;
            }

            return strpos($path, $allowed) !== 0;
        }

        public function maybe_detect_core_file_changes() {
            if (!is_admin() || !current_user_can('manage_options')) {
                return;
            }

            $settings = $this->get_settings();
            if (empty($settings['core_file_change_alert'])) {
                return;
            }

            $current_snapshot = $this->collect_core_file_snapshot();
            if (empty($current_snapshot)) {
                return;
            }

            $stored_snapshot = get_option($this->file_monitor_snapshot_option, []);
            if (!is_array($stored_snapshot) || empty($stored_snapshot)) {
                update_option($this->file_monitor_snapshot_option, $current_snapshot, false);
                update_option($this->file_monitor_hash_option, $this->hash_snapshot($current_snapshot), false);
                return;
            }

            $current_hash = $this->hash_snapshot($current_snapshot);
            $stored_hash = (string) get_option($this->file_monitor_hash_option, '');

            if (empty($stored_hash) || !hash_equals($stored_hash, $current_hash)) {
                $changes = $this->detect_core_snapshot_changes($stored_snapshot, $current_snapshot);
                $new_count = $this->append_core_file_attack_logs($changes);
                if ($new_count > 0) {
                    $timestamp = current_time('mysql');
                    set_transient(
                        $this->file_monitor_notice_transient,
                        $new_count . ' uploaded file(s) detected outside wp-content on ' . $timestamp . '. Check the Malicious Attack Alerts section.',
                        DAY_IN_SECONDS
                    );
                }
                update_option($this->file_monitor_snapshot_option, $current_snapshot, false);
                update_option($this->file_monitor_hash_option, $current_hash, false);
            }
        }

        private function collect_core_file_snapshot() {
            $root_path = wp_normalize_path(trailingslashit(ABSPATH));
            $excluded_path = wp_normalize_path($root_path . 'wp-content' . DIRECTORY_SEPARATOR);
            $snapshot = [];

            try {
                $iterator = new RecursiveIteratorIterator(
                    new RecursiveDirectoryIterator($root_path, FilesystemIterator::SKIP_DOTS),
                    RecursiveIteratorIterator::SELF_FIRST,
                    RecursiveIteratorIterator::CATCH_GET_CHILD
                );
            } catch (Exception $e) {
                return '';
            }

            foreach ($iterator as $item) {
                $pathname = wp_normalize_path($item->getPathname());
                if (strpos($pathname, $excluded_path) === 0) {
                    continue;
                }

                $relative = str_replace($root_path, '', $pathname);
                if ($relative === '') {
                    continue;
                }

                if (is_link($pathname)) {
                    continue;
                }

                if ($item->isDir()) {
                    $mtime = @filemtime($pathname);
                    if ($mtime === false) {
                        continue;
                    }
                    $snapshot['dir:' . rtrim($relative, '/')] = (string) $mtime;
                } elseif ($item->isFile()) {
                    $mtime = @filemtime($pathname);
                    $size = @filesize($pathname);
                    if ($mtime === false || $size === false) {
                        continue;
                    }
                    $snapshot['file:' . $relative] = $mtime . '|' . $size;
                }
            }

            ksort($snapshot);
            return $snapshot;
        }

        private function hash_snapshot($snapshot) {
            if (!is_array($snapshot)) {
                return '';
            }

            ksort($snapshot);
            return hash('sha256', wp_json_encode($snapshot));
        }

        private function detect_core_snapshot_changes($old_snapshot, $new_snapshot) {
            $changes = [];

            foreach ($new_snapshot as $path => $meta) {
                if (!isset($old_snapshot[$path])) {
                    $changes[] = ['type' => 'added', 'path' => $path];
                    continue;
                }

                if ((string) $old_snapshot[$path] !== (string) $meta) {
                    $changes[] = ['type' => 'modified', 'path' => $path];
                }
            }

            foreach ($old_snapshot as $path => $meta) {
                if (!isset($new_snapshot[$path])) {
                    $changes[] = ['type' => 'deleted', 'path' => $path];
                }
            }

            return $changes;
        }

        private function append_core_file_attack_logs($changes) {
            if (empty($changes) || !is_array($changes)) {
                return 0;
            }

            $existing_logs = get_option($this->file_monitor_log_option, []);
            if (!is_array($existing_logs)) {
                $existing_logs = [];
            }

            $time_for_display = current_time('Y-m-d H:i:s');
            $day_for_display = current_time('l');
            $new_rows = [];

            foreach ($changes as $change) {
                if (empty($change['path'])) {
                    continue;
                }

                $raw_path = (string) $change['path'];
                $change_type = isset($change['type']) ? (string) $change['type'] : '';

                if ($change_type !== 'added' || strpos($raw_path, 'file:') !== 0) {
                    continue;
                }

                $raw_path = substr($raw_path, 5);

                $new_rows[] = [
                    'id' => wp_generate_uuid4(),
                    'type' => 'uploaded file',
                    'path' => wp_normalize_path(trailingslashit(ABSPATH) . ltrim($raw_path, '/')),
                    'day' => $day_for_display,
                    'datetime' => $time_for_display,
                    'resolved' => 0,
                ];
            }

            if (!empty($new_rows)) {
                $updated_logs = array_merge($new_rows, $existing_logs);
                $updated_logs = array_slice($updated_logs, 0, 300);
                update_option($this->file_monitor_log_option, $updated_logs, false);
            }

            return count($new_rows);
        }

        public function intercept_login_requests() {
            $settings = $this->get_settings();
            $slug = trim($settings['custom_login_slug'], '/');
            $request_path = isset($_SERVER['REQUEST_URI']) ? wp_parse_url(wp_unslash($_SERVER['REQUEST_URI']), PHP_URL_PATH) : '';
            $request_path = trim((string) $request_path, '/');
            $script_name = isset($_SERVER['SCRIPT_NAME']) ? basename(wp_unslash($_SERVER['SCRIPT_NAME'])) : '';

            if ($request_path === $slug) {
                $_SERVER['REQUEST_URI'] = '/' . $slug . '/';
                require_once ABSPATH . 'wp-login.php';
                exit;
            }

            $is_default_login_request = false;

            if ($script_name === 'wp-login.php' || $request_path === 'wp-login.php') {
                $is_default_login_request = true;
            }

            if (($request_path === 'wp-admin' || $request_path === 'wp-admin/') && !is_user_logged_in() && !wp_doing_ajax()) {
                $is_default_login_request = true;
            }

            if ($is_default_login_request && !$this->is_whitelisted_login_action()) {
                wp_safe_redirect(home_url('/404'));
                exit;
            }
        }

        private function is_whitelisted_login_action() {
            $allowed_actions = ['logout'];
            $action = isset($_REQUEST['action']) ? sanitize_key(wp_unslash($_REQUEST['action'])) : '';
            return in_array($action, $allowed_actions, true);
        }

        public function filter_login_url($url, $path, $scheme = null, $blog_id = null) {
            if (strpos($url, 'wp-login.php') !== false) {
                return home_url('/' . trim($this->get_settings()['custom_login_slug'], '/') . '/');
            }
            return $url;
        }

        public function custom_login_url($login_url, $redirect, $force_reauth) {
            $url = home_url('/' . trim($this->get_settings()['custom_login_slug'], '/') . '/');

            if (!empty($redirect)) {
                $url = add_query_arg('redirect_to', rawurlencode($redirect), $url);
            }

            if ($force_reauth) {
                $url = add_query_arg('reauth', '1', $url);
            }

            return $url;
        }

        public function custom_logout_url($logout_url, $redirect) {
            $args = ['action' => 'logout'];

            if (!empty($redirect)) {
                $args['redirect_to'] = $redirect;
            }

            $url = add_query_arg($args, home_url('/' . trim($this->get_settings()['custom_login_slug'], '/') . '/'));
            return wp_nonce_url($url, 'log-out');
        }

        public function custom_lostpassword_url($lostpassword_url, $redirect) {
            $url = add_query_arg('action', 'lostpassword', home_url('/' . trim($this->get_settings()['custom_login_slug'], '/') . '/'));

            if (!empty($redirect)) {
                $url = add_query_arg('redirect_to', $redirect, $url);
            }

            return $url;
        }

        public function custom_register_url($register_url) {
            return add_query_arg('action', 'register', home_url('/' . trim($this->get_settings()['custom_login_slug'], '/') . '/'));
        }

        private function add_htaccess_rule() {
            $htaccess_file = ABSPATH . '.htaccess';
            if (!file_exists($htaccess_file) || !is_writable($htaccess_file)) {
                return false;
            }

            $rule = "# BEGIN {$this->htaccess_marker}\n<Files wp-config.php>\norder allow,deny\ndeny from all\n</Files>\n# END {$this->htaccess_marker}\n";
            $contents = file_get_contents($htaccess_file);

            if ($contents === false) {
                return false;
            }

            if (strpos($contents, $this->htaccess_marker) !== false) {
                return true;
            }

            $contents = rtrim($contents) . "\n\n" . $rule;
            return file_put_contents($htaccess_file, $contents) !== false;
        }

        private function remove_htaccess_rule() {
            $htaccess_file = ABSPATH . '.htaccess';
            if (!file_exists($htaccess_file) || !is_writable($htaccess_file)) {
                return false;
            }

            $contents = file_get_contents($htaccess_file);
            if ($contents === false) {
                return false;
            }

            $pattern = '/\n?# BEGIN ' . preg_quote($this->htaccess_marker, '/') . '.*?# END ' . preg_quote($this->htaccess_marker, '/') . '\n?/s';
            $contents = preg_replace($pattern, "\n", $contents);

            return file_put_contents($htaccess_file, trim($contents) . "\n") !== false;
        }

        private function add_wp_config_rule() {
            $config_file = ABSPATH . 'wp-config.php';
            if (!file_exists($config_file) || !is_writable($config_file)) {
                return false;
            }

            $contents = file_get_contents($config_file);
            if ($contents === false) {
                return false;
            }

            $rule_line = "define('DISALLOW_FILE_EDIT', true);";
            $contents = preg_replace('/^[ \t]*define\s*\(\s*[\'"]DISALLOW_FILE_EDIT[\'"]\s*,\s*true\s*\)\s*;\s*\R?/mi', '', $contents);
            $pattern = '/(\/\*\s*That\'?s all,\s*stop editing!\s*Happy (publishing|blogging)\.\s*\*\/\s*\R?)/i';

            if (preg_match($pattern, $contents)) {
                $contents = preg_replace($pattern, "$1" . $rule_line . "\n", $contents, 1);
            } else {
                $contents = rtrim($contents) . "\n" . $rule_line . "\n";
            }

            return file_put_contents($config_file, $contents) !== false;
        }

        private function remove_wp_config_rule() {
            $config_file = ABSPATH . 'wp-config.php';
            if (!file_exists($config_file) || !is_writable($config_file)) {
                return false;
            }

            $contents = file_get_contents($config_file);
            if ($contents === false) {
                return false;
            }

            $contents = preg_replace('/^[ \t]*define\s*\(\s*[\'"]DISALLOW_FILE_EDIT[\'"]\s*,\s*true\s*\)\s*;\s*\R?/mi', '', $contents);

            return file_put_contents($config_file, $contents) !== false;
        }

        private function get_client_ip() {
            $keys = ['HTTP_CF_CONNECTING_IP', 'HTTP_X_FORWARDED_FOR', 'REMOTE_ADDR'];

            foreach ($keys as $key) {
                if (!empty($_SERVER[$key])) {
                    $value = sanitize_text_field(wp_unslash($_SERVER[$key]));
                    if ($key === 'HTTP_X_FORWARDED_FOR') {
                        $parts = explode(',', $value);
                        $value = trim($parts[0]);
                    }

                    if (filter_var($value, FILTER_VALIDATE_IP)) {
                        return $value;
                    }
                }
            }

            return 'unknown';
        }

        private function get_login_attempt_limit_value() {
            $settings = $this->get_settings();
            $limit = isset($settings['login_attempt_limit']) ? $settings['login_attempt_limit'] : 'none';

            if (!in_array($limit, ['none', '3', '5'], true)) {
                $limit = 'none';
            }

            return $limit;
        }

        private function get_lockout_key() {
            return 'speedx_login_lock_' . md5($this->get_client_ip());
        }

        private function get_attempts_key() {
            return 'speedx_login_attempts_' . md5($this->get_client_ip());
        }

        private function is_ip_locked() {
            $limit = $this->get_login_attempt_limit_value();
            if ($limit === 'none') {
                return false;
            }

            $lockout_until = get_transient($this->get_lockout_key());
            return !empty($lockout_until) && time() < (int) $lockout_until;
        }

        private function get_remaining_lockout_minutes() {
            $lockout_until = (int) get_transient($this->get_lockout_key());
            if ($lockout_until <= time()) {
                return 0;
            }

            return max(1, (int) ceil(($lockout_until - time()) / 60));
        }

        public function check_login_attempt_limit($user, $username, $password) {
            if (defined('XMLRPC_REQUEST') && XMLRPC_REQUEST) {
                return $user;
            }

            if ($this->is_ip_locked()) {
                $minutes = $this->get_remaining_lockout_minutes();
                return new WP_Error(
                    'speedx_login_locked',
                    sprintf('Blocked: Too many failed login attempts. Try again after %d minute(s).', $minutes)
                );
            }

            return $user;
        }

        public function record_failed_login($username) {
            $limit = $this->get_login_attempt_limit_value();
            if ($limit === 'none') {
                return;
            }

            $attempts_key = $this->get_attempts_key();
            $attempts = (int) get_transient($attempts_key);
            $attempts++;
            set_transient($attempts_key, $attempts, $this->lockout_minutes * MINUTE_IN_SECONDS);

            if ($attempts >= (int) $limit) {
                set_transient($this->get_lockout_key(), time() + ($this->lockout_minutes * MINUTE_IN_SECONDS), $this->lockout_minutes * MINUTE_IN_SECONDS);
            }
        }

        public function clear_login_attempts($user_login, $user) {
            delete_transient($this->get_attempts_key());
            delete_transient($this->get_lockout_key());
        }

        public function login_lockout_message($message) {
            if ($this->is_ip_locked()) {
                $minutes = $this->get_remaining_lockout_minutes();
                $message .= '<div id="login_error"><strong>Blocked:</strong> Too many failed login attempts. Try again after ' . esc_html($minutes) . ' minute(s).</div>';
            }

            return $message;
        }

        public function filter_login_errors($error) {
            if ($this->is_ip_locked()) {
                return '';
            }

            return $error;
        }

        public function lock_login_form_ui() {
            if (!$this->is_ip_locked()) {
                return;
            }
            ?>
            <style>
                body.login form#loginform input[type="text"],
                body.login form#loginform input[type="password"],
                body.login form#loginform input[type="email"],
                body.login form#loginform input[type="submit"],
                body.login form#loginform button,
                body.login form#loginform .button,
                body.login form#loginform .wp-pwd button {
                    pointer-events: none !important;
                    opacity: 0.45 !important;
                    background: #bfbfbf !important;
                    border-color: #bfbfbf !important;
                    color: #666 !important;
                    box-shadow: none !important;
                    cursor: not-allowed !important;
                }

                body.login form#loginform input[type="text"],
                body.login form#loginform input[type="password"],
                body.login form#loginform input[type="email"] {
                    background: #efefef !important;
                }
            </style>
            <script>
                document.addEventListener('DOMContentLoaded', function () {
                    var form = document.getElementById('loginform');
                    if (!form) return;

                    var fields = form.querySelectorAll('input[type="text"], input[type="password"], input[type="email"]');
                    fields.forEach(function(field) {
                        field.setAttribute('readonly', 'readonly');
                        field.setAttribute('disabled', 'disabled');
                    });

                    var buttons = form.querySelectorAll('input[type="submit"], button, .button');
                    buttons.forEach(function(button) {
                        button.setAttribute('disabled', 'disabled');
                    });
                });
            </script>
            <?php
        }

    }

    new SpeedX_Security_Patch();
}
