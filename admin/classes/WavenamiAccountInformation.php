<?php

class WavenamiAccountInformation {

    public static $key = 'wvnmi_account_information';

    public static $settings = array();

    function __construct() {

        add_action( 'admin_init', array( &$this, 'register_settings' ) );

        add_action( 'wp_ajax_wvnmi_add_group', array( &$this, 'wvnmi_add_group_callback' ) );

        self::$settings = $this->get_settings_options();
    }

    public static function get_settings_options() {

        // load the settings from the database
        if(false === get_option(self::$key)) {
            update_option(self::$key, self::get_settings_defaults(), 'yes');
        }

        $settings_options = (array) get_option( self::$key );

        // merge with defaults
        $settings_options = array_merge( self::get_settings_defaults(), $settings_options );

        return $settings_options;

    }

    public static function get_settings_defaults() {
        $defaults = array(
            'privateAPIkey' => '',
            'displayPoweredBy' => '',
        );
        return $defaults;
    }

    function register_settings() {
        register_setting( self::$key, self::$key, array( &$this, 'sanitize_account_information_settings' ) );

        add_settings_section( 'section_login', 'Wavenami API Settings', array( &$this, 'section_login_desc' ), self::$key );

        add_settings_field( 'privateAPIkey', 'Private API Key', array( &$this, 'field_private_api_key' ), self::$key, 'section_login' );

        add_settings_field( 'displayPoweredBy', 'Footer Options', array( &$this, 'field_display_powered_by' ), self::$key, 'section_login' );

        add_settings_field( 'disableNonce', 'Disable Sessions', array( &$this, 'field_disable_sessions' ), self::$key, 'section_login' );
    }

    function section_login_desc() {
        if (self::$settings['privateAPIkey'] == '' ) {
            echo "<div class='notice inline notice-warning notice-alt'>
            <p>Don't have a Wavenami account? <a href='https://app.wavenami.com/signup' target='_blank'>Sign up here</a>.</p>
            <p>After you have registered for an Event Organizer account, go to [<b>Wavenami > Settings > Wordpress API</b>] to generate your API key, then paste it below.</p>
            <p>NOTE: before using the API, please introduce yourself to us at <a href='mailto:support@wavenami.com'>support@wavenami.com</a></p>
            <p>Need help? We are always available to answer your questions via chat or email from <a href='https://app.wavenami.com' target='_blank'>Wavenami</a>.</p></div>";
        }
    }

    function field_private_api_key() { ?>
        <input id="wavenami_privateapikey"
               type="text"
               size="50"
               name="<?php echo self::$key ?>[privateAPIkey]"
               value="<?php echo esc_attr( self::$settings['privateAPIkey'] ); ?>"
        />
    <?php }

    function field_display_powered_by() { ?>
        <input id="wavenami_displaypoweredby"
               type="checkbox"
               name="<?php echo self::$key ?>[displayPoweredBy]"
               value="1"
            <?php checked("1", esc_attr( self::$settings['displayPoweredBy'])); ?>
        /> Show "Powered by Wavenami" in form footer (We do appreciate it!)
    <?php }

    function field_disable_sessions() { ?>
        <input id="wavenami_disable_sessions"
               type="checkbox"
               name="<?php echo self::$key ?>[disableNonce]"
               value="1"
            <?php
            if(isset(self::$settings['disableNonce'])) {
                checked("1", esc_attr(self::$settings['disableNonce']));
            }
            ?>
        /> Check this only if people are having problems saving their profile.
    <?php }

    function sanitize_account_information_settings( $input ) {

        // get the current options
        // $valid_input = self::$settings;
        $valid_input = self::get_settings_defaults();

        // check which button was clicked, submit or reset,
        $submit = ( ! empty( $input['submit'] ) ? true : false );
        $reset = ( ! empty( $input['reset'])  ? true : false );
        $refresh = ( ! empty( $input['refresh']) ? true : false );

        // if the submit or refresh button was clicked
        if ( $submit || $refresh ) {

            /**
             * validate the account information settings, and add error messages
             * add_settings_error( $setting, $code, $message, $type )
             * $setting here refers to the $id of add_settings_field
             * add_settings_field( $id, $title, $callback, $page, $section, $args );
             */

            // private API key
            if((strlen($input['privateAPIkey']) > 0)) {
                // make sure it's only 20 characters and contains only upper / lowercase letters and numbers
                if ( preg_match('/[0-9a-zA-Z_-]{32}/', $input['privateAPIkey']) ) {
                    $valid_input['privateAPIkey'] = $input['privateAPIkey'];
                }else {
                    add_settings_error(
                        'private_api_key',
                        'wvnmi_error',
                        'Please add a valid PrivateAPIKey',
                        'error'
                    );
                }
            }else {
                add_settings_error(
                    'private_api_key',
                    'wvnmi_error',
                    'You should add you PrivateAPIKey.',
                    'error'
                );
            }

            // Footer Settings
            // make sure it's only 1 int char
            if ( preg_match('/[0-9]{1}/', $input['displayPoweredBy']) ) {
                if ((strlen($input['displayPoweredBy']) > 0)) {
                    $valid_input['displayPoweredBy'] = $input['displayPoweredBy'];
                }
            }
            // Session Settings
            // make sure it's only 1 int char
            if ( preg_match('/[0-9]{1}/', $input['disableNonce']) ) {
                if ((strlen($input['disableNonce']) > 0)) {
                    $valid_input['disableNonce'] = $input['disableNonce'];
                }
            }
        }

        return $valid_input;

    } // end sanitize_account_information_settings
}