<?php

class WavenamiIframes {

    public static $key = 'wavenami_iframes';

    function __construct() {

        add_action( 'admin_init', array( &$this, 'register_settings' ) );
    }

    function register_settings() {
        // register_setting( $option_group, $option_name, $sanitize_callback );
        register_setting( self::$key, self::$key, array( &$this, 'sanitize_help_settings' ) );

        // add_settings_section( $id, $title, $callback, $page );
        add_settings_section( 'section_help', 'Display Forms and Maps inside your own WP Theme with iframes', array( &$this, 'section_iframes_desc' ), self::$key );
    }

    function section_iframes_desc() { ?>

        <p>Need help? Please contact us at
            <a href="mailto:support@wavenami.com">support@wavenami.com</a>
            with any setup questions you have.</p>
        <h3><strong>This shows you how to embed the forms
                and maps into your own WP theme to keep the look and feel of your
                website.</strong></h3>
        <p style="padding-left: 20px;">Wavenami forms are best served
            without surrounding designs for maximum usability and
            responsiveness. But if you want to keep the branding and look of
            your website, you can generally serve the forms and maps from
            within your own WP design using iframes. Please TEST your iframe forms &amp;
            maps to make sure it works with your own theme.
        </p>
        <p style="padding-left: 40px; margin-bottom:30px">IFRAME SHORTCODE:<br>
            <input style="width: 650px; font-size: larger;" name="" type="text" id="" value="[wavenami-iframe page_url=https://www.yoursite.com/page-with-shortcode/]" class="regular-text">
        </p>
        <h3><strong>HOW TO SETUP IFRAMED FORMS</strong></h3>
        <h3>1) Add a form or map shortcode to a blank Page:</h3>
        <p style="padding-left: 20px;">Create a new blank PAGE (not a Post!)
            and paste the corresponding Shortcode into the page.<br>
        </p>
        <p style="padding-left: 40px;">Example Page URL:
            <strong>https://www.yoursite.com/page-with-shortcode/</strong></p>
        <p style="padding-left: 20px;">This page will be the SOURCE page to
            be served up IN your iframe. You must create the form page on your
            own site because iframes work best when both pages are on the same
            domain.
        </p>
        <p style="padding-left: 20px;">TIP: Use the Text tab on the editor
            to make sure there's no extra formatting added to it.</p>
        <p style="padding-left: 20px;">Be sure to select Template: Wavenami Blank Template.</p>
        <h3>2) Add the iframe shortcode to a Page to serve up the form or
            map:</h3>
        <p style="padding-left: 20px;">Create a new blank PAGE and paste the
            iframe shortcode along with the page URL you created in Step 1.</p>
        <p style="padding-left: 40px;">Example iframe shortcode:<br>
            <input style="width:600px" name="" type="text" id="" value="[wavenami-iframe page_url=https://www.yoursite.com/page-with-shortcode/]" class="regular-text">
        </p>

        <h3><strong>ADDING BOTTOM PADDING (optional)</strong></h3>
        <h3>Use "padding_px" to add more space to the bottom of the form. Defaults to 100.</h3>
        <p style="padding-left: 20px;">If your iframed form appears to be cut off at the bottom, you can add more space to the bottom like the example below.<br>
        </p>
        <p style="padding-left: 40px;">Example iframe shortcode with 300px of padding:<br>
            <input style="width:700px" name="" type="text" id="" value="[wavenami-iframe page_url=https://www.yoursite.com/page-with-shortcode/ padding_px=300]" class="regular-text">
        </p>

        <h3><strong>SETTING FIXED HEIGHT (optional)</strong></h3>
        <h3>Use "height" to set a hard height to your iframe. Defaults to auto-height.</h3>
        <p style="padding-left: 20px;">If your iframed form appears to be cut off or display partially, you can set the height like the example below.<br>
        </p>
        <p style="padding-left: 40px;">Example iframe shortcode with 800px height:<br>
            <input style="width:700px" name="" type="text" id="" value="[wavenami-iframe page_url=https://www.yoursite.com/page-with-shortcode/ height=800]" class="regular-text">
        </p>

    <?php }

    function sanitize_help_settings() {
        // nothing to sanitize here folks, move along...
    }

}