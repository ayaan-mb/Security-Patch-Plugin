<?php
/**
 * Plugin Name: Security Patch By Click Track Marketing
 * Description: Custom login URL changer and security patch manager for WordPress.
 * Version: 1.3.0
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

        public function __construct() {
            register_activation_hook(__FILE__, [$this, 'activate']);
            register_deactivation_hook(__FILE__, [$this, 'deactivate']);

            add_action('admin_menu', [$this, 'admin_menu']);
            add_action('admin_init', [$this, 'register_settings']);
            add_action('admin_post_speedx_save_settings', [$this, 'save_settings']);
            add_action('admin_notices', [$this, 'admin_notices']);

            add_action('admin_enqueue_scripts', [$this, 'admin_assets']);
            add_action('admin_head', [$this, 'admin_menu_branding_css']);

            add_action('init', [$this, 'maybe_block_country'], 0);
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
                'login_attempt_limit' => 'none',
                'blocked_countries' => [],
            ];

            if (!get_option($this->option_name)) {
                add_option($this->option_name, $defaults);
            }
        }

        public function deactivate() {
            $settings = $this->get_settings();

            if (!empty($settings['protect_wp_config_htaccess'])) {
                $this->remove_htaccess_rule();
            }

            if (!empty($settings['disallow_file_edit'])) {
                $this->remove_wp_config_rule();
            }
        }

        private function get_settings() {
            $defaults = [
                'custom_login_slug' => 'secure-login',
                'protect_wp_config_htaccess' => 0,
                'disallow_file_edit' => 0,
                'login_attempt_limit' => 'none',
                'blocked_countries' => [],
            ];

            $settings = get_option($this->option_name, []);
            $settings = wp_parse_args($settings, $defaults);

            if (!is_array($settings['blocked_countries'])) {
                $settings['blocked_countries'] = [];
            }

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

        public function settings_page() {
            if (!current_user_can('manage_options')) {
                return;
            }

            $settings = $this->get_settings();
            $custom_login_url = home_url('/' . trim($settings['custom_login_slug'], '/') . '/');
            $countries = $this->get_country_list();
            $blocked_count = is_array($settings['blocked_countries']) ? count($settings['blocked_countries']) : 0;
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
                                <span class="ctm-stat__value"><?php echo esc_html($blocked_count); ?></span>
                                <span class="ctm-stat__label">Blocked Countries</span>
                            </div>
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
                                    <h2>Country Blocking</h2>
                                    <p>Search countries and tick as many as you want to block. Visitors from selected countries will see a blocked screen.</p>
                                </div>

                                <div class="ctm-country-toolbar">
                                    <input type="text" id="speedx-country-search" placeholder="Search countries..." />
                                    <button type="button" class="button button-secondary" id="speedx-select-all-visible">Select Visible</button>
                                    <button type="button" class="button button-secondary" id="speedx-clear-all-countries">Clear All</button>
                                </div>

                                <div class="speedx-country-box" id="speedx-country-box">
                                    <?php foreach ($countries as $code => $name) : ?>
                                        <label class="speedx-country-item" data-country-text="<?php echo esc_attr(strtolower($name . ' ' . $code)); ?>">
                                            <input type="checkbox" name="blocked_countries[]" value="<?php echo esc_attr($code); ?>" <?php checked(in_array($code, $settings['blocked_countries'], true)); ?> />
                                            <span><?php echo esc_html($name . ' (' . $code . ')'); ?></span>
                                        </label>
                                    <?php endforeach; ?>
                                </div>
                            </div>

                            <div class="ctm-submit-row">
                                <?php submit_button('Save Security Settings', 'primary', 'submit', false); ?>
                            </div>
                        </form>
                    </div>

                    <div class="ctm-card ctm-card--side">
                        <div class="ctm-side-block">
                            <h3>Brand Theme</h3>
                            <p>Styled to match the dark ClickTrack Marketing look with electric blue highlights, glossy cards, and a cleaner premium admin feel.</p>
                        </div>

                        <div class="ctm-side-block">
                            <h3>Quick Notes</h3>
                            <ul>
                                <li>All existing plugin functionality remains unchanged.</li>
                                <li>Sidebar shield icon is now branded blue.</li>
                                <li>Country blocking still requires a country-code header from your server or CDN.</li>
                            </ul>
                        </div>

                        <div class="ctm-side-block">
                            <h3>Live Summary</h3>
                            <div class="ctm-mini-metric">
                                <span>Custom Login</span>
                                <strong><?php echo esc_html('/' . trim($settings['custom_login_slug'], '/')); ?></strong>
                            </div>
                            <div class="ctm-mini-metric">
                                <span>Blocked Countries</span>
                                <strong><?php echo esc_html($blocked_count); ?></strong>
                            </div>
                            <div class="ctm-mini-metric">
                                <span>Login Attempts</span>
                                <strong><?php echo esc_html($settings['login_attempt_limit']); ?></strong>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <style>
                .speedx-security-wrap{
                    margin: 18px 20px 0 2px;
                    color:#d8ecff;
                    font-family: Poppins, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Arial, sans-serif;
                }
                .speedx-security-wrap *, .speedx-security-wrap *:before, .speedx-security-wrap *:after{
                    box-sizing:border-box;
                }
                .speedx-security-wrap .notice{
                    margin-left:0;
                }
                .ctm-hero{
                    max-width:1180px;
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
                    color:#a7c7df;
                    max-width:720px;
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
                    color:#9ec0da;
                    font-size:12px;
                    text-transform:uppercase;
                    letter-spacing:.06em;
                }
                .ctm-card-grid{
                    max-width:1180px;
                    margin-top:22px;
                    display:grid;
                    grid-template-columns:minmax(0,1fr) 320px;
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
                    color:#9dc0d9;
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
                    color:#89abc2;
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
                    color:#95b7cf;
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
                .ctm-country-toolbar{
                    display:flex;
                    gap:10px;
                    align-items:center;
                    flex-wrap:wrap;
                    margin-bottom:14px;
                }
                .ctm-country-toolbar input{
                    min-width:260px;
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
                .speedx-country-box{
                    width:100%;
                    min-height:330px;
                    max-height:460px;
                    overflow:auto;
                    border:1px solid rgba(84,198,255,.18);
                    border-radius:18px;
                    background:linear-gradient(180deg, #06111d, #08192b);
                    padding:16px;
                    display:grid;
                    grid-template-columns:repeat(3, minmax(220px, 1fr));
                    gap:10px 16px;
                }
                .speedx-country-item{
                    display:flex;
                    align-items:flex-start;
                    gap:10px;
                    padding:11px 12px;
                    border:1px solid rgba(255,255,255,.05);
                    border-radius:12px;
                    background:rgba(255,255,255,.02);
                    color:#dff2ff;
                    cursor:pointer;
                    line-height:1.5;
                    transition:.2s ease;
                }
                .speedx-country-item:hover{
                    border-color:rgba(34,206,255,.24);
                    background:rgba(34,206,255,.05);
                }
                .speedx-country-item input{
                    margin-top:3px;
                    accent-color:#19c6ff;
                    flex:0 0 auto;
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
                    color:#a6c5db;
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
                    color:#92b4cb;
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
                @media (max-width: 900px){
                    .speedx-country-box{
                        grid-template-columns:repeat(2, minmax(220px, 1fr));
                    }
                }
                @media (max-width: 680px){
                    .speedx-country-box{
                        grid-template-columns:1fr;
                    }
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

            <script>
                document.addEventListener('DOMContentLoaded', function () {
                    var search = document.getElementById('speedx-country-search');
                    var items = document.querySelectorAll('.speedx-country-item');
                    var selectVisibleBtn = document.getElementById('speedx-select-all-visible');
                    var clearAllBtn = document.getElementById('speedx-clear-all-countries');

                    if (search) {
                        search.addEventListener('input', function () {
                            var term = this.value.toLowerCase().trim();
                            items.forEach(function (item) {
                                var text = item.getAttribute('data-country-text') || '';
                                item.style.display = text.indexOf(term) !== -1 ? '' : 'none';
                            });
                        });
                    }

                    if (selectVisibleBtn) {
                        selectVisibleBtn.addEventListener('click', function () {
                            items.forEach(function (item) {
                                if (item.style.display !== 'none') {
                                    var checkbox = item.querySelector('input[type="checkbox"]');
                                    if (checkbox) checkbox.checked = true;
                                }
                            });
                        });
                    }

                    if (clearAllBtn) {
                        clearAllBtn.addEventListener('click', function () {
                            items.forEach(function (item) {
                                var checkbox = item.querySelector('input[type="checkbox"]');
                                if (checkbox) checkbox.checked = false;
                            });
                        });
                    }
                });
            </script>
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

            $countries = $this->get_country_list();
            $blocked_countries = [];
            if (isset($_POST['blocked_countries']) && is_array($_POST['blocked_countries'])) {
                foreach (wp_unslash($_POST['blocked_countries']) as $country_code) {
                    $country_code = strtoupper(sanitize_text_field($country_code));
                    if (isset($countries[$country_code])) {
                        $blocked_countries[] = $country_code;
                    }
                }
            }
            $blocked_countries = array_values(array_unique($blocked_countries));

            $new_settings = [
                'custom_login_slug' => $new_slug,
                'protect_wp_config_htaccess' => isset($_POST['protect_wp_config_htaccess']) ? 1 : 0,
                'disallow_file_edit' => isset($_POST['disallow_file_edit']) ? 1 : 0,
                'login_attempt_limit' => $login_attempt_limit,
                'blocked_countries' => $blocked_countries,
            ];

            update_option($this->option_name, $new_settings);

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

            if ($login_attempt_limit === 'none') {
                delete_transient($this->get_attempts_key());
                delete_transient($this->get_lockout_key());
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

        public function admin_notices() {
            if (!isset($_GET['page']) || $_GET['page'] !== 'speedx-security-patch') {
                return;
            }

            if (!empty($_GET['speedx_saved'])) {
                $settings = $this->get_settings();
                $login_url = home_url('/' . trim($settings['custom_login_slug'], '/') . '/');
                $count = is_array($settings['blocked_countries']) ? count($settings['blocked_countries']) : 0;
                echo '<div class="notice notice-success is-dismissible"><p><strong>Settings saved.</strong> Login URL: <a href="' . esc_url($login_url) . '" target="_blank">' . esc_html($login_url) . '</a> | Blocked Countries: ' . esc_html((string) $count) . '</p></div>';

                if (!$this->can_detect_country_code()) {
                    echo '<div class="notice notice-warning"><p><strong>Country blocking note:</strong> This feature works when your server or CDN provides a visitor country code header such as <code>CF-IPCountry</code> or <code>GEOIP_COUNTRY_CODE</code>. If your hosting stack does not provide country detection, country blocking will not trigger.</p></div>';
                }
            }
        }

        public function maybe_block_country() {
            if (is_admin() || (defined('WP_CLI') && WP_CLI)) {
                return;
            }

            $settings = $this->get_settings();
            if (empty($settings['blocked_countries']) || !is_array($settings['blocked_countries'])) {
                return;
            }

            $country_code = $this->get_visitor_country_code();
            if (empty($country_code)) {
                return;
            }

            if (in_array($country_code, $settings['blocked_countries'], true)) {
                status_header(403);
                nocache_headers();
                wp_die(
                    '<h1>Access Blocked</h1><p>This website is not available in your country.</p>',
                    'Access Blocked',
                    ['response' => 403]
                );
            }
        }

        private function get_visitor_country_code() {
            $possible_headers = [
                'HTTP_CF_IPCOUNTRY',
                'CF-IPCountry',
                'GEOIP_COUNTRY_CODE',
                'HTTP_GEOIP_COUNTRY_CODE',
                'HTTP_X_COUNTRY_CODE',
                'HTTP_X_GEO_COUNTRY',
            ];

            foreach ($possible_headers as $header) {
                if (isset($_SERVER[$header]) && !empty($_SERVER[$header])) {
                    $country = strtoupper(trim(sanitize_text_field(wp_unslash($_SERVER[$header]))));
                    if (preg_match('/^[A-Z]{2}$/', $country)) {
                        return $country;
                    }
                }
            }

            return '';
        }

        private function can_detect_country_code() {
            return !empty($this->get_visitor_country_code()) ||
                isset($_SERVER['HTTP_CF_IPCOUNTRY']) ||
                isset($_SERVER['GEOIP_COUNTRY_CODE']) ||
                isset($_SERVER['HTTP_GEOIP_COUNTRY_CODE']);
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

        private function get_country_list() {
            return [
                'AF' => 'Afghanistan','AL' => 'Albania','DZ' => 'Algeria','AD' => 'Andorra','AO' => 'Angola','AG' => 'Antigua and Barbuda','AR' => 'Argentina','AM' => 'Armenia','AU' => 'Australia','AT' => 'Austria','AZ' => 'Azerbaijan','BS' => 'Bahamas','BH' => 'Bahrain','BD' => 'Bangladesh','BB' => 'Barbados','BY' => 'Belarus','BE' => 'Belgium','BZ' => 'Belize','BJ' => 'Benin','BT' => 'Bhutan','BO' => 'Bolivia','BA' => 'Bosnia and Herzegovina','BW' => 'Botswana','BR' => 'Brazil','BN' => 'Brunei','BG' => 'Bulgaria','BF' => 'Burkina Faso','BI' => 'Burundi','CV' => 'Cabo Verde','KH' => 'Cambodia','CM' => 'Cameroon','CA' => 'Canada','CF' => 'Central African Republic','TD' => 'Chad','CL' => 'Chile','CN' => 'China','CO' => 'Colombia','KM' => 'Comoros','CG' => 'Congo','CD' => 'Congo (DRC)','CR' => 'Costa Rica','CI' => 'Côte d’Ivoire','HR' => 'Croatia','CU' => 'Cuba','CY' => 'Cyprus','CZ' => 'Czechia','DK' => 'Denmark','DJ' => 'Djibouti','DM' => 'Dominica','DO' => 'Dominican Republic','EC' => 'Ecuador','EG' => 'Egypt','SV' => 'El Salvador','GQ' => 'Equatorial Guinea','ER' => 'Eritrea','EE' => 'Estonia','SZ' => 'Eswatini','ET' => 'Ethiopia','FJ' => 'Fiji','FI' => 'Finland','FR' => 'France','GA' => 'Gabon','GM' => 'Gambia','GE' => 'Georgia','DE' => 'Germany','GH' => 'Ghana','GR' => 'Greece','GD' => 'Grenada','GT' => 'Guatemala','GN' => 'Guinea','GW' => 'Guinea-Bissau','GY' => 'Guyana','HT' => 'Haiti','HN' => 'Honduras','HU' => 'Hungary','IS' => 'Iceland','IN' => 'India','ID' => 'Indonesia','IR' => 'Iran','IQ' => 'Iraq','IE' => 'Ireland','IL' => 'Israel','IT' => 'Italy','JM' => 'Jamaica','JP' => 'Japan','JO' => 'Jordan','KZ' => 'Kazakhstan','KE' => 'Kenya','KI' => 'Kiribati','KP' => 'Korea (North)','KR' => 'Korea (South)','KW' => 'Kuwait','KG' => 'Kyrgyzstan','LA' => 'Laos','LV' => 'Latvia','LB' => 'Lebanon','LS' => 'Lesotho','LR' => 'Liberia','LY' => 'Libya','LI' => 'Liechtenstein','LT' => 'Lithuania','LU' => 'Luxembourg','MG' => 'Madagascar','MW' => 'Malawi','MY' => 'Malaysia','MV' => 'Maldives','ML' => 'Mali','MT' => 'Malta','MH' => 'Marshall Islands','MR' => 'Mauritania','MU' => 'Mauritius','MX' => 'Mexico','FM' => 'Micronesia','MD' => 'Moldova','MC' => 'Monaco','MN' => 'Mongolia','ME' => 'Montenegro','MA' => 'Morocco','MZ' => 'Mozambique','MM' => 'Myanmar','NA' => 'Namibia','NR' => 'Nauru','NP' => 'Nepal','NL' => 'Netherlands','NZ' => 'New Zealand','NI' => 'Nicaragua','NE' => 'Niger','NG' => 'Nigeria','MK' => 'North Macedonia','NO' => 'Norway','OM' => 'Oman','PK' => 'Pakistan','PW' => 'Palau','PA' => 'Panama','PG' => 'Papua New Guinea','PY' => 'Paraguay','PE' => 'Peru','PH' => 'Philippines','PL' => 'Poland','PT' => 'Portugal','QA' => 'Qatar','RO' => 'Romania','RU' => 'Russia','RW' => 'Rwanda','KN' => 'Saint Kitts and Nevis','LC' => 'Saint Lucia','VC' => 'Saint Vincent and the Grenadines','WS' => 'Samoa','SM' => 'San Marino','ST' => 'Sao Tome and Principe','SA' => 'Saudi Arabia','SN' => 'Senegal','RS' => 'Serbia','SC' => 'Seychelles','SL' => 'Sierra Leone','SG' => 'Singapore','SK' => 'Slovakia','SI' => 'Slovenia','SB' => 'Solomon Islands','SO' => 'Somalia','ZA' => 'South Africa','SS' => 'South Sudan','ES' => 'Spain','LK' => 'Sri Lanka','SD' => 'Sudan','SR' => 'Suriname','SE' => 'Sweden','CH' => 'Switzerland','SY' => 'Syria','TW' => 'Taiwan','TJ' => 'Tajikistan','TZ' => 'Tanzania','TH' => 'Thailand','TL' => 'Timor-Leste','TG' => 'Togo','TO' => 'Tonga','TT' => 'Trinidad and Tobago','TN' => 'Tunisia','TR' => 'Turkey','TM' => 'Turkmenistan','TV' => 'Tuvalu','UG' => 'Uganda','UA' => 'Ukraine','AE' => 'United Arab Emirates','GB' => 'United Kingdom','US' => 'United States','UY' => 'Uruguay','UZ' => 'Uzbekistan','VU' => 'Vanuatu','VA' => 'Vatican City','VE' => 'Venezuela','VN' => 'Vietnam','YE' => 'Yemen','ZM' => 'Zambia','ZW' => 'Zimbabwe',
            ];
        }
    }

    new SpeedX_Security_Patch();
}
