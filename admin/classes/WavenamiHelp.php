<?php

class WavenamiHelp {

    public static $key = 'wavenami_help';

    function __construct() {

        add_action( 'admin_init', array( &$this, 'register_settings' ) );
    }

    function register_settings() {
        // register_setting( $option_group, $option_name, $sanitize_callback );
        register_setting( self::$key, self::$key, array( &$this, 'sanitize_help_settings' ) );

        // add_settings_section( $id, $title, $callback, $page );
        add_settings_section( 'section_help', 'Help and Setup Information', array( &$this, 'section_help_desc' ), self::$key );
    }

    function section_help_desc() { ?>

        <p>Need help? Please contact us at <a href="mailto:support@wavenami.com">support@wavenami.com</a> with any setup questions you have.</p>
        <h3><strong>API SETUP</strong></h3>
        <p><strong>Using shortcodes to setup online applications:</strong></p>
        <p style="padding-left: 20px;">Log into your <a
                    href="https://www.wavenami.com" target="_blank"
                    rel="noopener">Wavenami account</a> and click on
            Settings &gt; WordPress API. From this screen, click the Generate
            button to create your API key. If one already exists, you may use it or
            Regenerate a new one if you need to. Your API key is meant to be kept
            private, so you may regenerate it at any time.</p>
        <p style="padding-left: 20px;">Once you create your key,
            copy and save it to the plugin API Settings screen. Your events and
            shortcodes should now be listed in the Events tab.</p>
        <h3><strong>FORM & MAP PAGE SETUP</strong></h3>
        <h3>1) Add a registration form or venue map to your website:</h3>
        <p style="padding-left: 20px;">Create a new blank PAGE
            (not a Post!) and paste the corresponding Shortcode into the page.</p>
        <h3>2) Select page Template: Wavenami Blank Template</h3>
        <p style="padding-left: 20px;">Some WP theme templates
            contain formatting that may break the responsive design of Wavenami forms.
        </p>

    <?php }

    function sanitize_help_settings() {
        // nothing to sanitize here folks, move along...
    }

}