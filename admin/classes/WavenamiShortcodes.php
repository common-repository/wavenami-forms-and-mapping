<?php

class WavenamiShortcodes
{
    public $base_request_url = '';
    public $base_site_url = '';
    public $plugin_base_name = 'wvnmi';
    public $plugin_api_auth_key;

    private $application_steps;
    private $current_screen;
    private $attributes;
    private $event_attributes;
    private $form_steps;
    private $backup_attributes;
    private $default_args = ['method'=>'', 'timeout'=>60, 'headers'=>'', 'body'=>null, 'compress'=>false, 'decompress'=>true, 'sslverify'=>false];
    private $default_headers = ["Content-Type"=>"application/json; charset=utf-8"];

    /**
     * WavenamiShortcodes constructor.
     */
    public function __construct()
    {
        $account_information = get_option($this->plugin_base_name . '_account_information');
        $api_auth_key = (isset($account_information['privateAPIkey'])) ? $account_information['privateAPIkey'] . ':' : '';
        $this->footer_powered_by_option = (isset($account_information['displayPoweredBy'])) ? $account_information['displayPoweredBy'] : 0;

        /*
         * disable nonce by default - seems to be causing issues
         * */
        // $this->disable_nonce = (isset($account_information['disableNonce'])) ? $account_information['disableNonce'] : false;
        $this->disable_nonce = true;

        if(isset($_SERVER['SERVER_ADDR'])) {
            $ip_addr = explode(".", $_SERVER['SERVER_ADDR']);
            if ($ip_addr[0] == '192' && $ip_addr[1] == '168') {
                $this->base_request_url = "http://api.wavenami.net/v1/apply/";
                $this->base_site_url = "https://app.wavenami.net";
            } else {
                $this->base_request_url = "https://api.wavenami.com/v1/apply/";
                $this->base_site_url = "https://app.wavenami.com";
            }
        }else{
            $this->base_request_url = "https://api.wavenami.com/v1/apply/";
            $this->base_site_url = "https://app.wavenami.com";
        }

        $this->plugin_api_auth_key = base64_encode($api_auth_key);

        add_action('wp_ajax_wvnmi_form_submission', array($this, 'handle_form_submission'));
        add_action('wp_ajax_nopriv_wvnmi_form_submission', array($this, 'handle_form_submission'));

        add_action('wp_ajax_wvnmi_map_submission', array($this, 'handle_map_submission'));
        add_action('wp_ajax_nopriv_wvnmi_map_submission', array($this, 'handle_map_submission'));

        add_action('wp_ajax_wvnmi_signature_submission', array($this, 'handle_signature_submission'));
        add_action('wp_ajax_nopriv_wvnmi_signature_submission', array($this, 'handle_signature_submission'));

        add_shortcode('wavenami_form', array($this, 'wavenami_form_shortcode'));
        add_shortcode('wavenami-iframe', array($this, 'wavenami_iframe_shortcode'));

        session_start();

        if(isset($_SERVER['SERVER_NAME'])) {
            if (stristr($_SERVER['SERVER_NAME'],"forms.wavenami")) {
                if(!empty( $_SESSION['title'] )) {
                    add_filter('pre_get_document_title', 'wavenami_change_page_title');
                    function wavenami_change_page_title()
                    {
                        $title = isset($_SESSION['title']) ? sanitize_text_field($_SESSION['title']) : '';
                        unset($_SESSION['title']);
                        return $title;
                    }
                }
            }
        }
    }

    /**
     * @param $atts
     * @return string
     */
    public function wavenami_form_shortcode($atts)
    {
        global $wp_query;

        $request_url = $is_hosted_form = "";
        $register_url = false;
        $request_url_info = [];

        $attributes = shortcode_atts(array(
            'form_key' => '',
            'map_key' => '',
        ), $atts, 'wavenami_form');

        // Dynamic form_key with url slug
        $attributes['form_key'] = $attributes['form_key'] == 'dynamic' ? $wp_query->query_vars['form_key'] : $attributes['form_key'];

        // Dynamic form_key with url slug
        $attributes['id_hash'] = isset($wp_query->query_vars['id_hash']) ? $wp_query->query_vars['id_hash'] : 0;

        $headers = $this->_set_request_header(['Accept' => "application/json, text/javascript, */*; q=0.01", 'Authorization' => 'Basic ' . $this->plugin_api_auth_key]);

        $request_args = $this->_get_request_args([
                'method' => 'GET',
                'headers' => $headers
            ]
        );

        ///////////////////////
        // check active session
        $session_active = $temp_session_active = false;
        $regenerate_event_attributes = false;

        if(isset($_GET['pk']) && isset($_GET['at'])){

            ///////////////////////
            // inject token session
            // print_r($_SESSION); die;

            session_start();

            // Unset all of the session variables.
            $_SESSION = [];

            // If it's desired to kill the session, also delete the session cookie.
            // Note: This will destroy the session, and not just the session data!
            if (ini_get("session.use_cookies")) {
                $params = session_get_cookie_params();
                setcookie(session_name(), '', time() - 42000,
                    $params["path"], $params["domain"],
                    $params["secure"], $params["httponly"]
                );
            }

            // Finally, destroy the session.
            session_destroy();

            $redirect_url = home_url() . "/" . $attributes['id_hash'] . "/" . $attributes['form_key'] . "/?profile&pk=" . sanitize_text_field($_GET['pk']) . "." . sanitize_text_field($_GET['at']);

            $mt = str_replace('.', '', microtime(true));
            $redirect_url .= "&v=".$mt;
            wp_redirect($redirect_url);
            exit();
        }

        if(!isset($_SESSION['api_token']) && isset($_SESSION['pk'])){ // might already do this above

            if(stristr($_SESSION['pk'],".")){
                list($profile_key, $api_token) = explode(".", sanitize_text_field($_SESSION['pk']),2);

                if($api_token == 'tickets'){
                    $temp_session_active = true;

                }elseif(strpos($api_token, 'aud_') == 0){
                    $temp_session_active = true;
                }

                if (PHP_VERSION_ID < 70300) {
                    setcookie('api_token', sanitize_text_field($api_token), 30 * DAY_IN_SECONDS, COOKIEPATH, COOKIE_DOMAIN, true, true);
                    $_SESSION['api_token'] = sanitize_text_field($api_token);
                    session_write_close();
                }else{
                    setcookie('api_token', sanitize_text_field($api_token), 30 * DAY_IN_SECONDS, COOKIEPATH, COOKIE_DOMAIN, true, true);
                    $_SESSION['api_token'] = sanitize_text_field($api_token);
                    session_write_close();
                }
            }

        }elseif(isset($_SESSION['api_token']) && isset( $_GET['pk'])){

            if(stristr($_GET['pk'],".")){
                list($profile_key, $api_token) = explode(".", sanitize_text_field($_GET['pk']),2);

                if(sanitize_text_field($_SESSION['api_token']) == $api_token){
                    $session_active = true;

                }elseif($api_token == 'tickets'){
                    $session_active = true;
                }
            }

        }else{
            $register_url = true;
        }

        $request_url_event_attributes = $this->base_request_url . $attributes['id_hash'] . "/" . $attributes['form_key'] . "/event";

        $event_form_attributes = wp_remote_retrieve_body(wp_remote_request($request_url_event_attributes, $request_args));

        $event_form_attributes = json_decode($event_form_attributes, true);

        $this->current_screen = $this->_get_current_screen($event_form_attributes['event_a']['rec_type'], $event_form_attributes['event_a']['nav_order']);

        if(isset($attributes['map_key']) && $attributes['map_key'] != ''){

            $request_url_event_attributes = $this->base_request_url . "map-event/" . $attributes['map_key'];

            $event_form_attributes = wp_remote_retrieve_body(wp_remote_request($request_url_event_attributes, $request_args));
            $event_form_attributes = json_decode($event_form_attributes, true);

            $this->current_screen = 'mapview';
            $this->event_attributes = $event_form_attributes;

            $map_key = $attributes['map_key'];
            list($event_code, $amenity_id) = explode("-", $map_key,2);
            $request_url = $this->base_request_url . $this->current_screen . "/" . $event_code . "/" . $amenity_id;
            $request_url_info =  array(
                "base_request_url" => $this->base_request_url,
                "event_code" => $event_code,
                "amenity_id" => $amenity_id
            );
            if (isset( $_GET['kid'] ) && $_GET['kid'] != null) {
                $request_url .= "/" . sanitize_text_field($_GET['kid']);
            }

            //echo $request_url_event_attributes;
            //print_r($attributes);
            //print_r($request_args);
            //print_r($event_form_attributes); die;

            return $this->_mapview_screen($request_url_info);

        }else{

            if($this->current_screen == 'clearsession'){

                if (isset($_SESSION['api_token']) && isset( $_GET['pk'])) {
                    $request_url = $this->base_request_url . $attributes['id_hash'] . "/" . $attributes['form_key'] . "/clearsession/" . sanitize_text_field($_GET['pk']);

                    $responses = wp_remote_retrieve_body( wp_remote_request( $request_url, $request_args ) );
                }

                $redirect_url = "//" . $_SERVER['HTTP_HOST'] . strtok($_SERVER["REQUEST_URI"], '?') . '?logout';

                wp_redirect($redirect_url);
                exit();

            }elseif(!$session_active && !$temp_session_active && isset($_GET['pk'])){

                $redirect_url = "//" . $_SERVER['HTTP_HOST'] . strtok($_SERVER["REQUEST_URI"], '?') . "?clearsession";

                wp_redirect($redirect_url);
                exit();

            }else{

                /////////////////////////////////////////
                // ATTRIBUTE REQUEST for FORM PAGE HEADERS

                if ($this->current_screen == "login") {
                    if (isset( $_SESSION['pk'])) {
                        $request_url_event_attributes = $this->base_request_url . $attributes['id_hash'] . "/" . $attributes['form_key'] . "/event/" . sanitize_text_field($_SESSION['pk']);
                    }else{
                        $request_url_event_attributes = $this->base_request_url . $attributes['id_hash'] . "/" . $attributes['form_key'] . "/event";
                    }

                }elseif (isset( $_GET['pk']) && $_GET['pk'] != null) {
                    $request_url_event_attributes = $this->base_request_url . $attributes['id_hash'] . "/" . $attributes['form_key'] . "/event/" . sanitize_text_field($_GET['pk']);
                    if (isset( $_GET['rfc'] ) && $_GET['rfc'] != null) {
                        $request_url_event_attributes .=  "/" . filter_var($_GET['rfc']);

                        // regenerate attribs to catch new applicant model created inline during
                        // login call with ticketing form
                        $regenerate_event_attributes = true;
                    }

                } elseif (($this->current_screen == "passreset" || $this->current_screen == "register") && isset( $_SESSION['pk'] )) {

                    // called for active ticketing form > register
                    $request_url_event_attributes = $this->base_request_url . $attributes['id_hash'] . "/" . $attributes['form_key'] . "/event/rpk/" . sanitize_text_field($_SESSION['pk']);

                } elseif (isset( $_SESSION['rpk']) && $_GET['rpk'] != null) {

                    if (isset( $_GET['rfc'] ) && $_GET['rfc'] != null) {
                        $request_url_event_attributes = $this->base_request_url . $attributes['id_hash'] . "/" . $attributes['form_key'] . "/event/" . sanitize_text_field($_GET['rpk']);
                        $request_url_event_attributes .=  "/" . filter_var($_GET['rfc']);
                    }else{
                        // called for active ticketing form > register
                        $request_url_event_attributes = $this->base_request_url . $attributes['id_hash'] . "/" . $attributes['form_key'] . "/event/rpk/" . sanitize_text_field($_GET['rpk']);
                    }

                } else {
                    $request_url_event_attributes = $this->base_request_url . $attributes['id_hash'] . "/" . $attributes['form_key'] . "/event";
                }

                // echo $request_url_event_attributes;
                $this->event_attributes = wp_remote_retrieve_body(wp_remote_request($request_url_event_attributes, $request_args));
                //echo "<pre>";
                //print_r(json_decode($this->event_attributes, true));
                //echo "</pre>";
                //die;

                $attr_tmp = json_decode($this->event_attributes, true);

                if (isset($attr_tmp['event_a'])) {
                    if (isset($_SERVER['SERVER_NAME'])) {
                        if (stristr($_SERVER['SERVER_NAME'], "forms.wavenami")) {
                            $is_hosted_form = true;

                            if (!empty($attr_tmp['event_a']['title'])) {
                                $_SESSION['title'] = $attr_tmp['event_a']['form_name'];
                                session_write_close();
                            }
                        }
                    }
                }

                // used on signature screen for signature retrieval
                $this->backup_attributes['profile'] = $this->event_attributes;

                $request_url_model = $this->base_request_url . $attributes['id_hash'] . "/" . $attributes['form_key'] . "/" . $this->current_screen . "/attributes";
                $this->attributes[$this->current_screen] = wp_remote_retrieve_body(wp_remote_request($request_url_model, $request_args));

                // trigger return if admin action
                if(isset($_GET['action']) && isset($_GET['post'])) {
                    return true;
                }

                if (isset( $_GET['maprel'] ) && $_GET['pk'] != null) {

                    if (isset( $_GET['pk']) && $_GET['pk'] != null) {
                        $request_url = $this->base_request_url . $attributes['id_hash'] . "/" . $attributes['form_key'] . "/" . $this->current_screen . "/release/" . sanitize_text_field($_GET['maprel']) . "/" . sanitize_text_field($_GET['pk']);
                    } else {
                        $request_url = $this->base_request_url . $attributes['id_hash'] . "/" . $attributes['form_key'] . "/" . $this->current_screen;
                    }

                } elseif ($this->current_screen == "map") {

                    if (isset( $_GET['pk']) && $_GET['pk'] != null) {
                        $request_url_info =  array(
                            "base_request_url" => $this->base_request_url,
                            "id_hash" => $attributes['id_hash'],
                            "form_key" => $attributes['form_key'],
                            "pk" => sanitize_text_field($_GET['pk']),
                            "map" => sanitize_text_field($_GET['map']),
                            "wvnmi_map_submission" => wp_create_nonce("wvnmi_map_submission")
                        );
                    } else {
                        $request_url_info =  array(
                            "base_request_url" => $this->base_request_url,
                            "id_hash" => $attributes['id_hash'],
                            "form_key" => $attributes['form_key'],
                            "pk" => null,
                            "map" => sanitize_text_field($_GET['map']),
                            "wvnmi_map_submission" => wp_create_nonce("wvnmi_map_submission")
                        );
                    }
                    return $this->_map_screen($request_url_info);

                } elseif ($this->current_screen == "payment") {

                    if (isset( $_GET['clear']) && $_GET['clear'] != null) {
                        $request_url = $this->base_request_url . $attributes['id_hash'] . "/" . $attributes['form_key'] . "/" . $this->current_screen . "/" . sanitize_text_field($_GET['pk']) . "/clear/" . sanitize_text_field($_GET['clear']);
                    } elseif (isset( $_GET['odp']) && $_GET['odp'] != null) {
                        $request_url = $this->base_request_url . $attributes['id_hash'] . "/" . $attributes['form_key'] . "/" . $this->current_screen . "/" . sanitize_text_field($_GET['pk']) . "/split/" . sanitize_text_field($_GET['odp']);
                    } elseif (isset( $_GET['pbc']) && $_GET['pbc'] != null) {
                        $request_url = $this->base_request_url . $attributes['id_hash'] . "/" . $attributes['form_key'] . "/" . $this->current_screen . "/" . sanitize_text_field($_GET['pk']) . "/paybycheck/" . sanitize_text_field($_GET['pbc']);
                    } else {
                        $request_url = $this->base_request_url . $attributes['id_hash'] . "/" . $attributes['form_key'] . "/" . $this->current_screen . "/" . sanitize_text_field($_GET['pk']);
                    }

                } else {

                    if( $this->current_screen == 'logout') {

                        $request_url = $this->base_request_url . $attributes['id_hash'] . "/" . $attributes['form_key'] . "/login";

                    }elseif( $this->current_screen == 'login') {

                        $request_url = $this->base_request_url . $attributes['id_hash'] . "/" . $attributes['form_key'] . "/" . $this->current_screen;

                        if (isset( $_SESSION['pk'])) {
                            $profile_key = $_SESSION['pk'];
                            $request_url .= "/" . sanitize_text_field($profile_key);

                        }elseif(isset( $_GET['cpk'])) {
                            $request_url .= "/cpk/" . sanitize_text_field($_GET['cpk']);

                        }else{
                            if(isset( $_GET['rpk'])) {
                                $request_url .= "/rpk/" . sanitize_text_field($_GET['rpk']);

                            }elseif(isset( $_COOKIE['rpk'])) {
                                $request_url .= "/rpk/" . sanitize_text_field($_COOKIE['rpk']);
                            }
                        }

                        $register_url = true;

                    } elseif( $this->current_screen == 'register') {

                        if(isset( $_GET['cpk']) && isset( $_GET['token'])) {
                            $mode = 'passcreate';
                            $request_url = $this->base_request_url . $attributes['id_hash'] . "/" . $attributes['form_key'] . "/" . $this->current_screen . "/" . $mode. "/cpk/" . sanitize_text_field($_GET['cpk']);
                            $register_url = true;

                        }elseif(isset( $_GET['cpk'])) {
                            $mode = 'regconfirm';
                            $request_url = $this->base_request_url . $attributes['id_hash'] . "/" . $attributes['form_key'] . "/" . $this->current_screen . "/" . $mode . "/cpk/" . $_GET['cpk'];
                            $register_url = true;

                        }else{
                            $mode = 'register';
                            $request_url = $this->base_request_url . $attributes['id_hash'] . "/" . $attributes['form_key'] . "/" . $this->current_screen . "/" . $mode;
                            $register_url = true;

                            if(isset( $_SESSION['pk'])) {
                                $request_url .= "/rpk/" . sanitize_text_field($_SESSION['pk']);

                            }elseif(isset( $_COOKIE['rpk'])) {
                                $request_url .= "/rpk/" . sanitize_text_field($_COOKIE['rpk']);

                            }elseif(isset( $_GET['rpk'])) {
                                $request_url .= "/rpk/" . sanitize_text_field($_GET['rpk']);
                            }
                        }

                    } elseif( $this->current_screen == 'passreset') {

                        if(isset( $_GET['cpk']) && isset( $_GET['token'])) {
                            $mode = 'passreset';

                            $request_url = $this->base_request_url . $attributes['id_hash'] . "/" . $attributes['form_key'] . "/" . $this->current_screen . "/" . $mode. "/cpk/" . sanitize_text_field($_GET['cpk']);
                            $register_url = true;

                        }elseif(isset( $_GET['cpk'])) {
                            $mode = 'passtoken';

                            $request_url = $this->base_request_url . $attributes['id_hash'] . "/" . $attributes['form_key'] . "/" . $this->current_screen . "/" . $mode . "/cpk/" . $_GET['cpk'];
                            $register_url = true;

                        }else{
                            $mode = 'passforgot';

                            $request_url = $this->base_request_url . $attributes['id_hash'] . "/" . $attributes['form_key'] . "/" . $this->current_screen . "/" . $mode;
                            if (isset( $_SESSION['pk'])) {
                                $request_url .= "/pk/" . sanitize_text_field($profile_key);
                            }
                            $register_url = true;
                        }

                    } else {

                        if (isset( $_GET['pk']) && !empty($_GET['pk'])) {
                            $request_url = $this->base_request_url . $attributes['id_hash'] . "/" . $attributes['form_key'] . "/" . $this->current_screen . "/" . sanitize_text_field($_GET['pk']);

                            if(isset( $_GET['rfc'])) {
                                $request_url .= "/" . sanitize_text_field($_GET['rfc']);
                            }elseif(isset( $_COOKIE['rfc'])) {
                                $request_url .= "/" . sanitize_text_field($_COOKIE['rfc']);
                            }

                        } elseif(isset( $_GET['rpk']) && isset($_GET['rfc'])) {

                            $request_url = $this->base_request_url . $attributes['id_hash'] . "/" . $attributes['form_key'] . "/" . $this->current_screen . "/" . $_GET['rpk'] . "/" . $_GET['rfc'];

                        } elseif(isset($_COOKIE['rpk']) && isset($_COOKIE['rfc'])) {

                            $request_url = $this->base_request_url . $attributes['id_hash'] . "/" . $attributes['form_key'] . "/" . $this->current_screen . "/" . $_COOKIE['rpk'] . "/" . $_COOKIE['rfc'];

                        }elseif($this->current_screen == "amenities" && isset( $_GET['ok'] )){

                            $form_key = $attributes['form_key'];
                            $form_key .= "_".sanitize_text_field($_GET['ok']);

                            $request_url = $this->base_request_url . $attributes['id_hash'] . "/" . $form_key . "/" . $this->current_screen;

                        }elseif($this->current_screen == "profile" && isset( $_GET['ok'] )){
                            $form_key = $attributes['form_key'];
                            $form_key .= "_".sanitize_text_field($_GET['ok']);

                            $request_url = $this->base_request_url . $attributes['id_hash'] . "/" . $form_key . "/" . $this->current_screen;

                        } else {
                            $request_url = $this->base_request_url . $attributes['id_hash'] . "/" . $attributes['form_key'] . "/" . $this->current_screen;
                        }
                    }
                }
            }
        }

        // $audit = isset($_SESSION['pk']) ? 1 : 0;

        if($this->current_screen == "amenities" && isset( $_SESSION['r1_book_code'] )){

            if(!empty($_SESSION['r1_book_code']) && isset($_GET['pk'])){
                $form_attr = json_decode($this->event_attributes,true);

                $amenity_id = $map_area_id = $booth_label = '';
                list($amenity_id, $map_area_id, $booth_label) = explode("-",base64_decode( sanitize_text_field($_SESSION['r1_book_code'])));
                $booth_label = base64_decode($booth_label);

                $data['data'] = "{$map_area_id}.{$booth_label}";
                $data['wvnmi_screen_name'] = 'map';
                $data['map'] = $amenity_id;
                $data['action'] = 'wvnmi_map_submission';
                $data['wvnmi_verify_submission'] = wp_nonce_field('wvnmi_form_submission', 'wvnmi_verify_submission');
                $data['form_code'] = $form_attr['event_a']['form_code'];
                $data['profile_key'] = sanitize_text_field($_GET['pk']);
                $data['no_return'] = true;

                $this->_execute_map_screen_submission($data);

                $redirect_url = wp_guess_url() . $_SERVER['REQUEST_URI'];
                $redirect_url .= "&book=added";

                wp_redirect($redirect_url);
                exit();
            }

        }elseif($this->current_screen == "amenities" && empty($_GET['pk']) && isset($_SESSION['temp_pk'])){
            $request_url .= "/" . $_SESSION['temp_pk'] . ".temp_pk";

        }elseif($this->current_screen == "badges" && empty($_GET['pk']) && isset($_SESSION['temp_pk'])){
            $request_url .= "/" . $_SESSION['temp_pk'] . ".temp_pk";
        }

        if($register_url){
            if($form_url = $this->_get_base_url()) {
                $request_args['body']['form_url'] = $form_url;
            }
        }

        if(1 == 2) {
            echo "<pre>";
            // print_r($this->event_attributes);
            echo $request_url;
            echo "</pre>";
            die;
        }

        $responses = wp_remote_retrieve_body( wp_remote_request( $request_url, $request_args ) );
        $return_local = json_decode($responses,true);

        $return_local['status'] = isset($return_local['status']) ? $return_local['status'] : 0;

        if(1 == 2) {
            // die($this->current_screen);

            echo "<pre>";
            print_r(json_decode($responses,true));
            echo "</pre>";
            die;
            /*
            [name] => PHP Notice
            [message] => Trying to get property of non-object
            [code] => 8
            [type] => yii\base\ErrorException
             * */
        }

        if($regenerate_event_attributes){
            $this->event_attributes = wp_remote_retrieve_body(wp_remote_request($request_url_event_attributes, $request_args));
        }

        /* If WP_Error, throw exception */
        $return_api_error = false;
        if (is_wp_error($responses)) {
            throw new Exception('Request failed. ' . $responses->get_error_messages());

        }elseif(isset($_SERVER['SERVER_ADDR'])) {
            $return_local = json_decode($responses,true);

            $return_local['status'] = isset($return_local['status']) ? $return_local['status'] : 0;

            if(isset($return_local['type'])){
                if(stristr($return_local['type'], 'ErrorException')){
                    $return_api_error = true;
                }
            }
            $ip_addr = explode(".", $_SERVER['SERVER_ADDR']);
            if($return_api_error){
                if ($ip_addr[0] == '192' && $ip_addr[1] == '168') {
                    if(stristr($return_local['type'], 'ErrorException')){
                        echo "<pre>";
                        print_r(json_decode($responses,true));
                        echo "</pre>";
                        die;
                    }
                } else {
                    $screen = $this->_generate_screen($responses, 'error');
                    return $screen;
                }
            }
        }

        if(is_array(json_decode($responses,true))){

            if ($return_local['status'] == 401){
                $redirect_url = "//" . $_SERVER['HTTP_HOST'] . strtok($_SERVER["REQUEST_URI"], '?');
                $redirect_url .= "?clearsession";

                wp_redirect($redirect_url);
                exit();

            }elseif ($return_local['status'] == 406){

                $redirect_url = "//" . $_SERVER['HTTP_HOST'] . strtok($_SERVER["REQUEST_URI"], '?');
                $redirect_url .= "?login";

                if (isset( $_GET['pk'])) {
                    $redirect_url .= "&pk=" . sanitize_text_field($_GET['pk']);
                }

                wp_redirect($redirect_url);
                exit();

            }elseif(isset($return_local['sign_redirect'])){

                $redirect_url = $this->_get_form_root_path(wp_get_referer()) . "?privacysign&pk=" . sanitize_text_field($_GET['pk']);
                if(isset($_GET['rfc'])){
                    if ($_GET['rfc'] != '') {
                        $redirect_url .= "&rfc=".sanitize_text_field($_GET['rfc']);
                    }
                }
                $mt = str_replace('.', '', microtime(true));
                $redirect_url .= "&v=".$mt;

                wp_redirect($redirect_url);
                exit();
            }
        }

        $screen = $this->_generate_screen($responses, $this->current_screen, $request_url_info);

        return $screen;
    }

    /**
     * @param $atts
     * @return string
     */
    public function wavenami_iframe_shortcode( $atts ) {

        $frame_id = 'wavenami-iframe';

        if( !is_array( $atts ) ) { return ''; }

        // load jquery as fallback if not included in theme
        wp_enqueue_script('jquery');

        $page_url = '';
        if( array_key_exists( 'page_url', $atts ) ) { $page_url = htmlentities(trim( $atts['page_url'] ), ENT_QUOTES ); }

        if( $page_url == '' ) { return ''; }

        $width = '100%';
        if( array_key_exists( 'width', $atts ) ) { $width = htmlentities(trim( $atts['width'] ), ENT_QUOTES ); }

        $height = 'auto';
        if( array_key_exists( 'height', $atts ) ) { $height = htmlentities(trim( $atts['height'] ), ENT_QUOTES ); }

        $autosize = true;
        if( array_key_exists( 'autosize', $atts ) ) { if( strtolower( $atts['autosize'] ) != 'yes' ) { $autosize = false; } ; }

        $padding_px = 100;
        if( array_key_exists( 'padding_px', $atts ) ) { $padding_px = intval( $atts['padding_px'] ); }

        $border = '0';
        if( array_key_exists( 'border', $atts ) ) { $border = htmlentities(trim( $atts['border'] ), ENT_QUOTES ); }

        $scrolling = 'no';
        if( array_key_exists( 'scroll', $atts ) ) { if( strtolower( $atts['autosize'] ) != 'yes' ) { $scrolling = 'yes'; } ; }

        if( !array_key_exists( 'passquerydisable', $atts ) ) {
            $qs_len = strlen( $_SERVER['QUERY_STRING'] );

            if( strstr( $page_url, '?' ) === FALSE && $qs_len > 0 ) {
                $page_url = $page_url . '?' . $_SERVER['QUERY_STRING'];
            } else if( $qs_len > 0 ) {
                $page_url = $page_url . '&' . $_SERVER['QUERY_STRING'];
            }
        }

        $page_url = esc_url(sanitize_url($page_url));

        $iframe_autosize = '';
        $result = '';

        if( $autosize ) {
            wp_enqueue_script('wvnmi iframe js', WAVENAMI_WORDPRESS_CLIENT_URL . '/front-end/assets/iframe/wavenami-iframe.js', array(), $script_rev);
            wp_enqueue_script('wvnmi iframe js');

$result = <<< JS
<script type="text/javascript">
    jQuery(document).ready(function(){
        WavenamiAutoFrame( 'wavenami-iframe', $padding_px);
        function iFrameWindowAdjust() {
            WavenamiAutoFrame( 'wavenami-iframe', $padding_px);
        }        
        window.onresize = iFrameWindowAdjust;
    });
</script>
JS;

            $iframe_autosize = ' onload="window.parent.scrollTo(0,0); WavenamiAutoFrame(\'' . $frame_id . '\',' . $padding_px . ');"';
        }

        $result = '
    <div id="r1if_spinner" style="position: fixed; margin-top: 150px; left: 50%;">
        <div>
             <img style="" src="'. WAVENAMI_WORDPRESS_CLIENT_URL . '/front-end/assets/img/loader.gif" />
        </div>
    </div>';

        $result .= '<iframe 
        id="' . $frame_id . '" 
        name="' . $frame_id . '" 
        src="' . $page_url . '" 
        width="' . $width . '" 
        height="' . $height . '" 
        frameborder="' . $border . '" 
        scrolling="' . $scrolling . '"
        ></iframe>';

        $result .= '
        <script type="text/javascript">
        document.getElementById(\'' . $frame_id . '\').onload = function() {
          window.parent.scrollTo(0,0); WavenamiAutoFrame(\'' . $frame_id . '\',' . $padding_px . ');
          var wavenamispinner = document.getElementById(\'r1if_spinner\');
          if (wavenamispinner) { wavenamispinner.remove(); }
        };
        </script>';

        return $result;
    }

    /**
     * @param string $data
     * @param $screen
     * @return string
     */
    private function _generate_screen($data = "", $screen)
    {
        $formData = json_decode($data, true);

        // print_r($formData); die;
        $error_code_a = ['503', '401', '404', '405', '407', '409', '410', '411', '402','0'];

        /*
        if(isset($_GET['status'])){
            $screen = "error";
        }
        */

        $formData['code'] = isset($formData['code']) ? $formData['code'] : '';

        if(in_array($formData['code'], $error_code_a)){
            $screen = "error";
        }

        $audit = isset($_SESSION['pk']) ? 1 : 0;

        switch( $screen ) {

            case "logout":
                return $this->_login_screen($formData);
                break;

            case "login":
                return $this->_login_screen($formData, $audit);
                break;

            case "register":
                return $this->_register_screen($formData);
                break;

            case "passreset":
                return $this->_passreset_screen($formData);
                break;

            case "privacysign":
                return $this->_privacysign_screen($formData);
                break;

            case "profile":
                return $this->_profile_screen($formData);
                break;

            case "session":
                return $this->_session_screen($formData);
                break;

            case "uploads":
                return $this->_uploads_screen($formData);
                break;

            case "amenities":
                return $this->_amenities_screen($formData);
                break;

            case "badges":
                return $this->_amenities_screen($formData);
                break;

            case "terms":
                return $this->_terms_screen($formData);
                break;

            case "signature":
                return $this->_signature_screen($formData);
                break;

            case "payment":
                return $this->_payment_screen($formData);
                break;

            case "error":
                $this->_clear_cookies();
                return $this->_error_screen($formData);
                break;

            default:
                return "<p>Something went wrong.</p>";
        }
    }

    /**
     * @param int $map_id
     * @param string $pk
     * @return array|mixed|object
     */
    private function _get_map_data_by_id($map_id = 0, $pk = '')
    {
        global $wp_query;

        $attributes = json_decode($this->event_attributes, true);

        $headers = $this->_set_request_header(['Accept' => "application/json, text/javascript, */*; q=0.01", 'Authorization' => 'Basic ' . $this->plugin_api_auth_key]);

        $request_args = $this->_get_request_args([
                'method'  => 'GET',
                'headers' =>  $headers
            ]
        );

        // Dynamic form_key with url slug
        $attributes['id_hash'] = $wp_query->query_vars['id_hash'] ? $wp_query->query_vars['id_hash'] : 0;

        $request_url = $this->base_request_url . $attributes['id_hash'] . "/" . $attributes['event_a']['form_code'] . "/map/" . $pk . "/" . $map_id;

        // die($request_url)
        // http://api.wavenami.net/v1/apply/m2v/QNQUqf/map/gZ9dhY1GvNiZ68wEj0Za.temp_pk/182;

        $map_data = wp_remote_retrieve_body(wp_remote_request($request_url, $request_args));
        return json_decode($map_data, true);
    }

    /**
     * @param int $key
     * @param array $map
     * @return mixed
     */
    private function _get_area_data_by_id($key = 0, $map = [])
    {
        foreach($map['imagemap_areas_a'] as $areaKey => $area) {
            if($area['map_area_id'] == $key) {
                return $area;
            }
        }
    }

    /**
     * @param array $attributes
     * @return string
     */
    private function _get_paypal_data($attributes = [], $odp = '')
    {
        global $wp_query;
        $odp = str_replace(".","_",$odp);

        $pk = $attributes['applicant_a']['profile_key'];
        if(isset($_SESSION['api_token'])){
            $pk .= "." . sanitize_text_field($_SESSION['api_token']);
        }

        if(isset($attributes['event_a']['form_code']) && isset($attributes['client_a']['profile_key'])) {

            $headers = $this->_set_request_header(['Accept' => "application/json, text/javascript, */*; q=0.01", 'Authorization' => 'Basic ' . $this->plugin_api_auth_key]);

            $request_args = $this->_get_request_args([
                    'method'  => 'POST',
                    'headers' =>  $headers,
                    'body' => ['return_url' => $this->_get_skip_url(['payment' => '', 'pk' => $pk, 'odp' => $odp, 'return' => 1])]
                ]
            );

            // Dynamic form_key with url slug
            $attributes['id_hash'] = $wp_query->query_vars['id_hash'] ? $wp_query->query_vars['id_hash'] : 0;

            $request_url = $this->base_request_url . $attributes['id_hash'] . "/" . $attributes['event_a']['form_code'] . "/payment/" . $pk . "/paypal";
            if($odp) {
                $request_url .= "/{$odp}";
            }

            $response = wp_remote_retrieve_body(wp_remote_request($request_url, $request_args));

            return $response;
        }
    }

    /**
     * @param string $option
     * @param $formData
     * @return mixed|string
     */
    private function _get_data($option = "", $formData)
    {
        global $wp_query;

        if(isset($formData['event_a']['form_code']) && isset($_GET['pk'])) {

            $headers = $this->_set_request_header(['Accept' => "application/json, text/javascript, */*; q=0.01", 'Authorization' => 'Basic ' . $this->plugin_api_auth_key]);

            $request_args = $this->_get_request_args([
                    'method'  => 'GET',
                    'headers' =>  $headers
                ]
            );

            // Dynamic form_key with url slug
            $attributes['id_hash'] = $wp_query->query_vars['id_hash'] ? $wp_query->query_vars['id_hash'] : 0;

            $request_url = $this->base_request_url . $attributes['id_hash'] . "/" . $formData['event_a']['form_code'] . "/" . $option . "/" . sanitize_text_field($_GET['pk']);

            $this->backup_attributes[$option] = wp_remote_retrieve_body(wp_remote_request($request_url, $request_args));

            return $this->backup_attributes[$option];
        }

        return json_encode([]);
    }

    /**
     * @param int $policy
     * @return string
     */
    private function _get_approval_status($approval_status = 0, $event_attributes_a) {

        $approval_status = $event_attributes_a['rec_type'] == 3 ? 99 : $approval_status;
        $application_label = $event_attributes_a['application_label'];

        switch ($approval_status) {
            case 0:
                $status = '<p><h4>' . $application_label . ' Status: <span class="green-alert">Pending Review</span></h4></p>';
                break;

            case 1:
                $status = '<p><h4>' . $application_label . ' Status: <span class="green-alert">Approved</span></h4></p>';
                break;

            case 2:
                $status = '<p><h4>' . $application_label . ' Status: On Wait-list</h4></p>';
                break;

            case 3:
                $status = '<p><h4>' . $application_label . ' Status: <span class="red-alert">Declined</span></h4></p>';
                break;

            default:
                break;
        }

        return $status;
        // return $event_attributes_a['rec_type'];
    }

    /**
     * @param int $policy
     * @return string
     */
    private function _display_payment_info($event_attributes_a) {
        ob_start();

        if($event_attributes_a['pay_policy'] == 4){
            // no payments form
            $cart_info_a = ["notice1_enable"];

        }elseif($event_attributes_a['rec_type'] == 3){
            $cart_info_a = [
                "notice1_enable",
                "is_applic_deposit",
                "discount_scope",
                "discount_exp"];

        }else{
            $cart_info_a = [
                "notice1_enable",
                "is_applic_deposit",
                "fee_structure",
                "fee_details",
                "discount_scope",
                "discount_exp",
                "fee_policy"];
        }
        ?>

        <div class="cart-bottom-details">
            <div class="" style="margin-top: 20px; margin-bottom: 5px;">
                <h4></h4>
            </div>
            <table style="width: 100%;" class="table table-striped table-bordered detail-view">
                <tbody>

                <?php
                foreach($cart_info_a AS $info_key){
                    $cld_label = ucwords(str_replace("_"," ",$info_key));
                    $cld_val = false;
                    $add_br = true;

                    switch ($info_key) {
                        case "notice1_enable":
                            $cld_label = false;
                            if($event_attributes_a[$info_key] == 1) {
                                $cld_val = $event_attributes_a['notice1_body_merged'];
                                $add_br = false;
                            }else{
                                $cld_val = false;
                            }
                            break;

                        case "fee_policy":
                            $cld_label = "Service Fees";
                            $cld_val = $event_attributes_a[$info_key] == 1 ? "Wavenami services fees will be applied to your total" : false;
                            break;

                        case "pay_policy":
                            if($event_attributes_a[$info_key] == 1) {
                                $cld_val = "Event payment is required AFTER you are approved.";
                            }elseif($event_attributes_a[$info_key] == 2) {
                                $cld_val = "You MAY make payment before application approval";
                            }elseif($event_attributes_a[$info_key] == 3) {
                                $cld_val = "Full payment MUST be made with the application before being approved";
                            }
                            break;

                        case "is_applic_deposit":
                            $cld_label = "{$event_attributes_a['application_label']} Fee";
                            if($event_attributes_a["application_fee"] > 0) {
                                $cld_val = $event_attributes_a[$info_key] == 1 ? "Deposit is required. Deposits are subtracted from your remaining balance." : "Application fee is required";
                            }
                            break;

                        case "discount_scope":
                            // discount_type - 1 = percentage, 2 = absolute
                            $cld_label = "Discounts";

                            if($event_attributes_a['discount_scope'] == 1) {
                                $discount_scope = "{$event_attributes_a['application_label']} Fee/Deposit";
                                $discount_percentage = (int)$event_attributes_a['discount_rate'];

                            }elseif($event_attributes_a['discount_scope'] == 2) {
                                $discount_scope = "Attendance Fee/Remaining Balance";
                                $discount_percentage = (int)$event_attributes_a['discount_rate'];

                            }elseif($event_attributes_a['discount_scope'] == 3) {
                                $discount_scope = "{$event_attributes_a['application_label']} Fee and Remaining Balance";
                                $discount_percentage = (int)$event_attributes_a['discount_rate'];
                            }

                            $cld_val = isset($discount_percentage) ? "{$discount_percentage}% off of {$discount_scope}" : false;
                            $discount_exists = isset($discount_percentage) ? "{$discount_percentage}% off of {$discount_scope}" : false;
                            break;

                        case "discount_exp":
                            $cld_label = "Discount Deadline";
                            $cld_val = $event_attributes_a['discount_scope'] != 0 ? date_format(date_create($event_attributes_a[$info_key]), 'm/d/Y') . ' 11:59pm EST' : false;
                            break;

                        default;
                            $cld_val = $event_attributes_a[$info_key];
                            break;
                    }

                    if($cld_val){
                        $cld_val = $add_br ? nl2br($cld_val) : $cld_val;
                        ?>
                        <tr>
                            <?php if($cld_label): ?>
                            <th style="white-space: nowrap;"><?php echo $cld_label; ?></th>
                            <?php endif; ?>
                            <td style="text-align: left;"><?php echo $cld_val; ?></td>
                        </tr>
                    <?php
                    }
                }
                ?>
                </tbody>
            </table>
        </div>

        <?php
        return ob_get_clean();
    }

    /**
     * @param int $policy
     * @return string
     */
    private function _get_notice_by_pay_policy($policy = 1) {
        ob_start();
        switch ($policy) {
            case 1:
                ?>
                <div style="margin-bottom:5px; margin-top:5px;">
                    <h4>Payment is required <span style="text-decoration: underline;">AFTER</span> application approval.</h4>
                </div>
                <?php
                break;
            case 2:
                ?>
                <div style="margin-bottom:5px; margin-top:5px;">
                    <h4>Payment is <span style="text-decoration: underline">OPTIONAL</span> with application.</h4>
                </div>
                <?php
                break;
            case 3:
                ?>
                <div style="margin-bottom:5px; margin-top:5px;">
                    <h4>Payment is <span style="text-decoration: underline;">REQUIRED</span> with application.</h4>
                </div>
                <?php
                break;
            default:
                break;
        }

        return ob_get_clean();
    }

    /**
     * handle form submissions
     */
    public function handle_form_submission()
    {
        if(empty( $_POST )) {
            echo "Error: no post values (form_post_submission)";

        }elseif(!wp_verify_nonce( sanitize_text_field($_POST['wvnmi_verify_submission']), 'wvnmi_form_submission') && $this->disable_nonce == false) {
            echo "Error: unable to verify secure post (wp_verify_nonce)";

        }else{
            $this->_execute_form_submission($_REQUEST, $this->_get_form_root_path(wp_get_referer()));
        }
    }

    /**
     * handle map selection submission
     */
    public function handle_map_submission()
    {
        if(empty( $_POST )) {
            echo "Test failed! (handle_map_submission)";

        }elseif(!wp_verify_nonce( sanitize_text_field($_POST['wvnmi_verify_submission']), 'wvnmi_map_submission') && $this->disable_nonce == false) {
            echo "Error: unable to verify secure post (wp_verify_nonce)";

        }else{
            $this->_execute_form_submission($_REQUEST, "");
        }
    }

    /**
     * handle signature submission
     */
    public function handle_signature_submission()
    {
        if(empty( $_POST )) {
            echo "Test failed! (handle_signature_submission)";

        }elseif(!wp_verify_nonce( sanitize_text_field($_POST['wvnmi_verify_submission']), 'wvnmi_signature_submission') && $this->disable_nonce == false) {
            echo "Error: unable to verify secure post (wp_verify_nonce)";

        }else{
            $this->_execute_form_submission($_REQUEST, "");
        }
    }

    /**
     * @param array $args
     * @return array|string
     */
    private function _get_skip_url($args = [])
    {
        global $wp;
        // https://developer.wordpress.org/reference/functions/add_query_arg/
        // https://codex.wordpress.org/Function_Reference/home_url
        $skip_url = home_url(add_query_arg($args, $wp->request));
        if($this->_count_array($args) > 0) {
            $skip_url = explode("?", $skip_url);
            $skip_url[0] = rtrim($skip_url[0]) . '/';
            $skip_url = $skip_url[0] . '?' . $skip_url[1];
        } else {
            $skip_url = rtrim($skip_url) . '/';
        }
        $mt = str_replace('.', '', microtime(true));
        $skip_url .= "&v=".$mt;

        return $skip_url;
    }

    /**
     * @return mixed
     */
    private function _check_php_version()
    {
        return version_compare(PHP_VERSION, '5.5.0', '>=');
    }

    /**
     * @param string $path
     * @return mixed
     */
    private function _get_form_root_path($path = "")
    {
        $temp = explode("?", $path);
        return $temp[0];
    }

    /**
     * @param $data
     * @param string $root
     * @return bool|int
     */
    private function _execute_form_submission($data, $root = "")
    {
        switch($data['wvnmi_screen_name']) {

            case "login":

                $responses = json_decode( $this->_execute_login_screen_submission($data), true);

                // print_r($responses); die;

                if($responses['code'] == 201) {

                    $next_step_a = $responses['next_step'][0];
                    $key_pos = (int)array_search($data['wvnmi_screen_name'],$next_step_a);
                    $key_pos++;

                    $redirect_url = $root;
                    $redirect_url .= "?".$next_step_a[$key_pos];

                    /////////////////////////////
                    // ADD api_token session here
                    if(isset($responses['api_token']) && $responses['api_token'] != '') {
                        if(isset($_SESSION['api_token'])){
                            unset($_SESSION['api_token']);
                        }
                        $_SESSION['api_token'] = $responses['api_token'];
                        session_write_close();
                    }

                    if(isset($responses['rpk']) && $responses['rpk'] != '') {

                        $redirect_url .= "&rpk=" . $responses['profile_key'];

                        if(isset($_SESSION['api_token'])){
                            $redirect_url .= "." . sanitize_text_field($_SESSION['api_token']);
                        }
                    }elseif(isset($_COOKIE['rpk']) && $_COOKIE['rpk'] != '') {

                        $redirect_url .= "&rpk=" . $_COOKIE['rpk'];

                        if(isset($_SESSION['api_token'])){
                            $redirect_url .= "." . sanitize_text_field($_SESSION['api_token']);
                        }
                    }elseif(isset($responses['profile_key']) && $responses['profile_key'] != '') {
                        $redirect_url .= "&pk=" . $responses['profile_key'];

                        if(isset($_SESSION['api_token'])){
                            $redirect_url .= "." . sanitize_text_field($_SESSION['api_token']);
                        }
                    }

                    if(isset($responses['rfc']) && $responses['rfc'] != '') {
                        $redirect_url .= "&rfc=" . $responses['rfc'];

                    }elseif(isset($_COOKIE['rfc']) && $_COOKIE['rfc'] != '') {
                        $redirect_url .= "&rfc=" . $_COOKIE['rfc'];

                    }elseif(isset($responses['new_applic']) && $responses['new_applic'] == 1) {
                        // new client, no application yet
                        $redirect_url .= "&rfc=new";
                    }

                    $mt = str_replace('.', '', microtime(true));
                    $redirect_url .= "&v=".$mt;

                    wp_redirect($redirect_url);
                    exit();

                }else{

                    $redirect_url = $root;
                    $redirect_url .= "?login";

                    $redirect_url .= "&res=".$responses['code'];

                    $mt = str_replace('.', '', microtime(true));
                    $redirect_url .= "&v=".$mt;

                    wp_redirect($redirect_url);
                    exit();
                }
                break;

            case "passreset":

                $responses = json_decode( $this->_execute_passreset_screen_submission($data), true);

                if($responses['code'] == 201) {

                    $next_step_a = $responses['next_step'][0];
                    $key_pos = (int)array_search($data['wvnmi_screen_name'],$next_step_a);
                    $key_pos++;

                    $redirect_url = $root;
                    $redirect_url .= "?passreset";

                    if($data['mode'] == 'passforgot'){
                        $redirect_url .= "&cpk=" . $responses['cpk'];

                    }elseif($data['mode'] == 'passtoken'){
                        $redirect_url .= "&cpk=" . $responses['cpk'];
                        $redirect_url .= "&token=" . $responses['token'];

                    }elseif($data['mode'] == 'passreset'){
                        $redirect_url = $root;
                        $redirect_url .= "?login&pr=1";
                    }

                    if(isset($responses['profile_key']) && $responses['profile_key'] != '') {
                        $redirect_url .= "&pk=" . $responses['profile_key'];
                    }

                    $mt = str_replace('.', '', microtime(true));
                    $redirect_url .= "&v=".$mt;

                    wp_redirect($redirect_url);
                    exit();

                }elseif($responses['code'] == 401) {

                    $next_step_a = $responses['next_step'][0];
                    $key_pos = (int)array_search($data['wvnmi_screen_name'],$next_step_a);
                    $key_pos++;

                    $redirect_url = $root;
                    $redirect_url .= "?passreset";

                    if($data['mode'] == 'passtoken'){
                        $redirect_url .= "&cpk=" . $responses['cpk'];
                    }

                    $mt = str_replace('.', '', microtime(true));
                    $redirect_url .= "&pr=0&v=".$mt;

                    wp_redirect($redirect_url);
                    exit();

                }elseif($responses['code'] == 0) {

                    $redirect_url = $root;
                    $redirect_url .= "?login&pr=0";

                    $mt = str_replace('.', '', microtime(true));
                    $redirect_url .= "&v=".$mt;

                    wp_redirect($redirect_url);
                    exit();
                }
                break;

            case "register":

                $responses = json_decode( $this->_execute_register_screen_submission($data), true);

                // print_r($responses); die;

                if($responses['code'] == 201) {

                    if($responses['mode'] == 'register') {

                        $redirect_url = $root;
                        $redirect_url .= "?register";

                        if(isset($responses['cpk']) && $responses['cpk'] != '') {
                            $redirect_url .= "&cpk=" . $responses['cpk'];
                        }

                    }elseif($responses['mode'] == 'regconfirm'){

                        $redirect_url = $root;
                        $redirect_url .= "?register";

                        if(isset($responses['cpk']) && $responses['cpk'] != '') {
                            $redirect_url .= "&cpk=" . $responses['cpk'];
                        }

                        if(isset($responses['token']) && $responses['token'] != '') {
                            $redirect_url .= "&token=" . $responses['token'];
                        }

                    }elseif($responses['mode'] == 'passcreate'){

                        if(isset($_SESSION['redirect'])){
                            $next_step_a = [$_SESSION['redirect'], $_SESSION['redirect']];
                            if(isset($_SESSION['redirect'])){
                                unset($_SESSION['redirect']);
                            }
                        }else{
                            $next_step_a = $responses['next_step'][0];
                        }
                        $key_pos = (int)array_search($data['wvnmi_screen_name'],$next_step_a);
                        $key_pos++;

                        $redirect_url = $root;
                        $redirect_url .= "?".$next_step_a[$key_pos];

                        if(isset($responses['api_token']) && !empty($responses['api_token'])) {
                            if(isset($_SESSION['api_token'])){
                                unset($_SESSION['api_token']);
                            }
                            $_SESSION['api_token'] = $responses['api_token'];
                            session_write_close();
                        }

                        if(isset($responses['profile_key']) && !empty($responses['profile_key'])) {
                            $redirect_url .= "&pk=" . $responses['profile_key'];

                            if(isset($_SESSION['api_token'])){
                                $redirect_url .= "." . sanitize_text_field($_SESSION['api_token']);
                            }

                            if(isset($responses['rfc'])){
                                $redirect_url .= "&rfc=" . sanitize_text_field($responses['rfc']);
                            }else{
                                 // new client with no application yet, or exists
                                $redirect_url .= $responses['new_applic'] == 1 ? "&rfc=new" : '';
                            }
                        }
                    }

                    $mt = str_replace('.', '', microtime(true));
                    $redirect_url .= "&v=".$mt;

                    wp_redirect($redirect_url);
                    exit();

                }elseif($responses['code'] == 401) {

                    $redirect_url = $root;
                    $redirect_url .= "?register";

                    if(isset($responses['cpk']) && $responses['cpk'] != '') {
                        $redirect_url .= "&cpk=" . $responses['cpk'];
                    }

                    $mt = str_replace('.', '', microtime(true));
                    $redirect_url .= "&pr=0&v=".$mt;

                    wp_redirect($redirect_url);
                    exit();

                }elseif($responses['code'] == 402) {

                    $redirect_url = $root;
                    $redirect_url .= "?register";

                    $mt = str_replace('.', '', microtime(true));
                    $redirect_url .= "&dup=1&v=".$mt;

                    wp_redirect($redirect_url);
                    exit();

                }elseif($responses['code'] == 409) {

                    $redirect_url = $root;
                    $redirect_url .= "?login";

                    if(isset($responses['cpk']) && $responses['cpk'] != '') {
                        $redirect_url .= "&cpk=" . $responses['cpk'];
                    }

                    $mt = str_replace('.', '', microtime(true));
                    $redirect_url .= "&v=".$mt;

                    wp_redirect($redirect_url);
                    exit();

                }elseif($responses['code'] == 0) {

                    $redirect_url = $root;
                    $redirect_url .= "?register";

                    if(isset($responses['profile_key']) && $responses['profile_key'] != '') {
                        $redirect_url .= "&pk=" . $responses['profile_key'];

                        if(isset($_SESSION['api_token'])){
                            $redirect_url .= "." . sanitize_text_field($_SESSION['api_token']);
                        }
                    }

                    $redirect_url .= "&status=" . $responses['status'];
                    wp_redirect($redirect_url);
                    exit();
                }
                break;

            case "privacysign":

                $responses = json_decode( $this->_execute_privacysign_screen_submission($data), true);

                if($responses['code'] == 201) {

                    $next_step_a = $responses['next_step'][0];
                    $key_pos = (int)array_search($data['wvnmi_screen_name'],$next_step_a);
                    $key_pos++;

                    $redirect_url = $root;
                    $redirect_url .= "?".$next_step_a[$key_pos];

                    /////////////////////////////
                    // ADD api_token session here
                    if(isset($responses['api_token']) && $responses['api_token'] != '') {
                        if(isset($_SESSION['api_token'])){
                            unset($_SESSION['api_token']);
                        }
                        $_SESSION['api_token'] = $responses['api_token'];
                        session_write_close();
                    }

                    if(isset($responses['rpk']) && $responses['rpk'] != '') {

                        $redirect_url .= "&rpk=" . $responses['profile_key'];

                        if(isset($_SESSION['api_token'])){
                            $redirect_url .= "." . sanitize_text_field($_SESSION['api_token']);
                        }
                    }elseif(isset($_COOKIE['rpk']) && $_COOKIE['rpk'] != '') {

                        $redirect_url .= "&rpk=" . $_COOKIE['rpk'];

                        if(isset($_SESSION['api_token'])){
                            $redirect_url .= "." . sanitize_text_field($_SESSION['api_token']);
                        }
                    }elseif(isset($responses['profile_key']) && $responses['profile_key'] != '') {
                        $redirect_url .= "&pk=" . $responses['profile_key'];

                        if(isset($_SESSION['api_token'])){
                            $redirect_url .= "." . sanitize_text_field($_SESSION['api_token']);
                        }
                    }

                    if(isset($responses['rfc']) && $responses['rfc'] != '') {
                        $redirect_url .= "&rfc=" . $responses['rfc'];

                    }elseif(isset($_COOKIE['rfc']) && $_COOKIE['rfc'] != '') {
                        $redirect_url .= "&rfc=" . $_COOKIE['rfc'];

                    }elseif(isset($responses['new_applic']) && $responses['new_applic'] == 1) {
                        // new client, no application yet
                        $redirect_url .= "&rfc=new";
                    }

                    $mt = str_replace('.', '', microtime(true));
                    $redirect_url .= "&v=".$mt;

                    wp_redirect($redirect_url);
                    exit();

                }elseif($responses['code'] == 0) {

                    $redirect_url = $root;
                    $redirect_url .= "?profile";

                    if(isset($responses['profile_key']) && $responses['profile_key'] != '') {
                        $redirect_url .= "&pk=" . $responses['profile_key'];

                        if(isset($_SESSION['api_token'])){
                            $redirect_url .= "." . sanitize_text_field($_SESSION['api_token']);
                        }
                    }

                    $redirect_url .= "&status=" . $responses['status'];
                    wp_redirect($redirect_url);
                    exit();
                }
                break;

            case "profile":

                $responses = json_decode( $this->_execute_profile_screen_submission($data), true);

                if($responses['code'] == 201) {

                    $next_step_a = $responses['next_step'][0];

                    $key_pos = (int)array_search($data['wvnmi_screen_name'], $next_step_a);
                    if($this->_count_array($next_step_a) > 1) { $key_pos++; }

                    $redirect_url = $root;
                    $redirect_url .= "?".$next_step_a[$key_pos];

                    if($next_step_a[$key_pos] == 'badges' && isset($responses['next_step'][2])){
                        $extra_amenity_id = $responses['next_step'][2];
                        $redirect_url .= "&extra={$extra_amenity_id}";
                    }

                    if(isset($responses['ticket_api_token']) && isset($responses['profile_key'])){
                        // if returned by profile, is attendee "tickets" token

                        $redirect_url .= "&pk=" . $responses['profile_key'];
                        $redirect_url .= "." . sanitize_text_field($responses['ticket_api_token']);

                        /////////////////////////////
                        // ADD api_token session here
                        if(isset($_SESSION['ticket_api_token'])){
                            unset($_SESSION['ticket_api_token']);
                        }
                        $_SESSION['api_token'] = $responses['ticket_api_token'];
                        session_write_close();

                    }elseif(isset($responses['profile_key']) && $responses['profile_key'] != '') {

                        $redirect_url .= "&pk=" . $responses['profile_key'];

                        if(isset($_SESSION['api_token'])){
                            $redirect_url .= "." . sanitize_text_field($_SESSION['api_token']);

                        }elseif(isset($responses['api_token'])){
                            $redirect_url .= "." . sanitize_text_field($responses['api_token']);

                            /////////////////////////////
                            // ADD api_token session here
                            if(isset($_SESSION['api_token'])){
                                unset($_SESSION['api_token']);
                            }
                            $_SESSION['api_token'] = $responses['api_token'];
                            session_write_close();
                        }
                    }

                    if(isset($responses['is_badge_post'])){
                        $redirect_url .= "&saved=1";
                    }

                    $mt = str_replace('.', '', microtime(true));
                    $redirect_url .= "&v=".$mt;

                    wp_redirect($redirect_url);
                    exit();

                }elseif($responses['code'] == 0) {

                    $redirect_url = $root;
                    $redirect_url .= "?profile";

                    if(isset($responses['profile_key']) && $responses['profile_key'] != '') {
                        $redirect_url .= "&pk=" . $responses['profile_key'];

                        if(isset($_SESSION['api_token'])){
                            $redirect_url .= "." . sanitize_text_field($_SESSION['api_token']);
                        }
                    }

                    $redirect_url .= "&status=" . $responses['status'];
                    wp_redirect($redirect_url);
                    exit();
                }
                break;

            case "session":

                $responses = json_decode( $this->_execute_session_screen_submission($data), true);

                if($responses['code'] == 201) {

                    $next_step_a = $responses['next_step'][0];

                    $key_pos = (int)array_search($data['wvnmi_screen_name'],$next_step_a);
                    if($this->_count_array($next_step_a) > 1) { $key_pos++; }

                    $redirect_url = $root;
                    $redirect_url .= "?".$next_step_a[$key_pos];

                    // if returned by profile, is attendee "tickets" token
                    if(isset($responses['ticket_api_token']) && isset($responses['profile_key'])){

                        $redirect_url .= "&pk=" . $responses['profile_key'];
                        $redirect_url .= "." . sanitize_text_field($responses['ticket_api_token']);

                        /////////////////////////////
                        // ADD api_token session here
                        if(isset($_SESSION['ticket_api_token'])){
                            unset($_SESSION['ticket_api_token']);
                        }
                        $_SESSION['api_token'] = $responses['ticket_api_token'];
                        session_write_close();

                    }elseif(isset($responses['profile_key']) && $responses['profile_key'] != '') {

                        $redirect_url .= "&pk=" . $responses['profile_key'];

                        if(isset($_SESSION['api_token'])){
                            $redirect_url .= "." . sanitize_text_field($_SESSION['api_token']);

                        }elseif(isset($responses['api_token'])){
                            $redirect_url .= "." . sanitize_text_field($responses['api_token']);

                            /////////////////////////////
                            // ADD api_token session here
                            if(isset($_SESSION['api_token'])){
                                unset($_SESSION['api_token']);
                            }
                            $_SESSION['api_token'] = $responses['api_token'];
                            session_write_close();
                        }
                    }

                    if(isset($responses['is_badge_post'])){
                        $redirect_url .= "&saved=1";
                    }

                    $mt = str_replace('.', '', microtime(true));
                    $redirect_url .= "&v=".$mt;

                    wp_redirect($redirect_url);
                    exit();

                }elseif($responses['code'] == 0) {

                    $redirect_url = $root;
                    $redirect_url .= "?profile";

                    if(isset($responses['profile_key']) && $responses['profile_key'] != '') {
                        $redirect_url .= "&pk=" . $responses['profile_key'];

                        if(isset($_SESSION['api_token'])){
                            $redirect_url .= "." . sanitize_text_field($_SESSION['api_token']);
                        }
                    }

                    $redirect_url .= "&status=" . $responses['status'];
                    wp_redirect($redirect_url);
                    exit();
                }
                break;

            case "uploads":

                $responses = $this->_execute_uploads_screen_submission($data);

                $next_step_a = $responses['upload_status']['next_step'][0];
                $key_pos = (int)array_search($data['wvnmi_screen_name'],$next_step_a);
                $key_pos++;

                $redirect_url = $root;
                $redirect_url .= "?".$next_step_a[$key_pos];

                if(isset($responses['profile_key']) && $responses['profile_key'] != '') {
                    $redirect_url .="&pk=" . $responses['profile_key'];
                }

                wp_redirect($redirect_url);
                exit();
                break;

            case "amenities":

                // inject api_token into profile key
                if(isset($data['Clients']['Value']['applic_profile_key'] ) && $data['Clients']['Value']['applic_profile_key'] != '' ) {
                    if(isset($_SESSION['api_token'])){
                        $data['Clients']['Value']['applic_profile_key'] .= "." . sanitize_text_field($_SESSION['api_token']);
                    }
                }

                $responses = json_decode($this->_execute_amenities_screen_submission($data), true);

                $redirect_url = $root;

                if($responses['code'] == 203) {
                    // redirect to badge page if duplicate found

                    if(isset($responses['add_extra_fields'])){
                        $extra_amenity_id = $responses['next_step'][2];
                        $redirect_url .= "?badges&extra={$extra_amenity_id}";
                        // dupflag
                    }

                    $dup_id_a = [];
                    if(isset($responses['duplicates'])){
                        if(is_array($responses['duplicates'])){
                            foreach($responses['duplicates'] AS $dup_id => $email){
                                $dup_id_a[] .= $dup_id;
                            }
                        }
                        $dup_id_uri = implode("_", $dup_id_a);
                        $redirect_url .= "&dupflag=".$dup_id_uri;
                    }

                }elseif($responses['code'] == 202 ||
                    $responses['code'] == 201 ||
                    $responses['code'] == 200) {

                    $next_step_a = $responses['next_step'][0];

                    // badge post returns 202
                    if($responses['code'] == 202){
                        $key_pos = (int)array_search('badges', $next_step_a);
                    }else{
                        $key_pos = (int)array_search($data['wvnmi_screen_name'],$next_step_a);
                    }
                    $key_pos++;

                    $redirect_url = $root;
                    $redirect_url .= "?".$next_step_a[$key_pos];

                    if($next_step_a[$key_pos] == 'badges' && isset($responses['next_step'][2])){
                        $extra_amenity_id = $responses['next_step'][2];
                        $redirect_url .= "&extra={$extra_amenity_id}";
                    }

                }else{
                    $redirect_url .= "?amenities";
                }

                if(!empty($responses['profile_key'])){
                    $redirect_url .= "&pk=" . $responses['profile_key'];

                }elseif($_SESSION['pk']){
                    $redirect_url .= "&pk=" . $_SESSION['pk'];

                }elseif($_SESSION['temp_pk']){
                    $redirect_url .= "&pk=" . $_SESSION['temp_pk'].".temp_pk";
                }

                $mt = str_replace('.', '', microtime(true));
                $redirect_url .= "&v=".$mt;

                wp_redirect($redirect_url);
                exit();
                break;

            case "map":

                $this->_execute_map_screen_submission($data);
                break;

            case "signature":

                $this->_execute_signature_screen_submission($data);
                break;

            case "terms_confirm":

                // call signature function to process
                $data['wvnmi_screen_name'] = 'signature';
                $responses = json_decode($this->_execute_terms_confirm_submission($data), true);

                $redirect_url = $root;

                if($responses['code'] == 202 ||
                    $responses['code'] == 201 ||
                    $responses['code'] == 200) {

                    // set to terms for navigation redirect
                    $data['wvnmi_screen_name'] = 'terms';

                    $next_step_a = $responses['next_step'][0];
                    $key_pos = (int)array_search($data['wvnmi_screen_name'], $next_step_a);
                    $key_pos++;

                    $redirect_url = $root;
                    $redirect_url .= "?".$next_step_a[$key_pos];
                }

                if(!empty($responses['profile_key'])){
                    $redirect_url .= "&pk=" . $responses['profile_key'];

                }elseif($_SESSION['pk']){
                    $redirect_url .= "&pk=" . $_SESSION['pk'];

                }elseif($_SESSION['temp_pk']){
                    $redirect_url .= "&pk=" . $_SESSION['temp_pk'].".temp_pk";
                }

                $mt = str_replace('.', '', microtime(true));
                $redirect_url .= "&v=".$mt;

                wp_redirect($redirect_url);
                exit();
                break;

            case "payment":

                $this->_execute_payment_screen_submission($data);

                $redirect_url = $root;
                $redirect_url .= "?payment";
                $redirect_url .= "&pk=" . $data['profile_key'];

                if(isset($data['discount_code'])) {
                    $redirect_url .= "&v=".str_replace('.', '', microtime(true));
                }

                wp_redirect($redirect_url);
                exit();
                break;

            default:
                return 1;
        }

        return false;
    }

    /**
     * @param $data
     */
    private function _execute_map_screen_submission($data)
    {
        $headers = $this->_set_request_header(['Accept' => "application/json, text/javascript, */*; q=0.01", 'Authorization' => 'Basic ' . $this->plugin_api_auth_key]);

        $map_data = ['data' => $data['data'], 'audit' => $data['audit']];
        $request_args = $this->_get_request_args([
                'method'  => 'POST',
                'headers' =>  $headers,
                'body'    => $map_data
            ]
        );

        $request_url = $this->base_request_url . $data['form_code'] . "/" . $data['wvnmi_screen_name'] . "/" . $data['profile_key'] . "/" . $data['map'];

        $responses = wp_remote_retrieve_body(wp_remote_request($request_url, $request_args));

        // no_return set by book from map session
        if(!isset($data['no_return'])) {
            echo $responses;
            die();
        }
    }

    /**
     * @param $data
     */
    private function _execute_signature_screen_submission($data) {

        $headers = $this->_set_request_header(['Accept' => "application/json, text/javascript, */*; q=0.01", 'Authorization' => 'Basic ' . $this->plugin_api_auth_key]);

        $signatureData = ['confirm_ip' => $_SERVER['REMOTE_ADDR'], 'svg_xml' => $data['svg_xml'], 'svg' => $data['svg'], 'terms_scope' => $data['terms_scope']];
        $request_args = $this->_get_request_args([
                'method'  => 'POST',
                'headers' =>  $headers,
                'body'    => $signatureData
            ]
        );

        $request_url = $this->base_request_url . $data['form_code'] . "/" . $data['wvnmi_screen_name'] . "/" . $data['profile_key'];

        $responses = wp_remote_retrieve_body(wp_remote_request($request_url, $request_args));

        echo $responses;
        die();
    }

    /**
     * @param $data
     */
    private function _execute_terms_confirm_submission($data) {

        $headers = $this->_set_request_header(['Accept' => "application/json, text/javascript, */*; q=0.01", 'Authorization' => 'Basic ' . $this->plugin_api_auth_key]);

        $confirmData = ['confirm_ip' => $_SERVER['REMOTE_ADDR'], 'terms_scope' => 3];
        $request_args = $this->_get_request_args([
                'method'  => 'POST',
                'headers' =>  $headers,
                'body'    => $confirmData
            ]
        );

        $request_url = $this->base_request_url . $data['form_code'] . "/" . $data['wvnmi_screen_name'] . "/" . $data['profile_key'];

        $responses = wp_remote_retrieve_body(wp_remote_request($request_url, $request_args));

        return $responses;
    }

     /**
     * @param $data
     * @return string
     */
    private function _execute_login_screen_submission($data)
    {
        global $wp;

        $headers = $this->_set_request_header(['Accept' => "application/json, text/javascript, */*; q=0.01", 'Authorization' => 'Basic ' . $this->plugin_api_auth_key]);

        $redirect_url = esc_url(sanitize_url($_SERVER['HTTP_REFERER']));
        $data['Clients']['referring_url'] = json_encode($redirect_url);

        // if INVITE, form_code will be BLANK
        $data['Clients']['form_code'] = $data['form_code'];

        $data['Clients']['rpk'] = isset($data['rpk']) ? $data['rpk'] : false;
        $data['Clients']['rfc'] = isset($data['rfc']) ? $data['rfc'] : false;
        $data['Clients']['login_redirect'] = isset($data['login_redirect']) ? $data['login_redirect'] : false;

        $request_args = $this->_get_request_args([
                'method' => 'POST',
                'headers' => $headers,
                'body' => $data['Clients']
            ]
        );

        /////////////////////////////////
        // register form_key = register
        // replace $attributes['form_key'] to display register form
        $data['form_code'] = 'login';

        if (isset($data['rpk']) && $data['rpk'] != '') {
            if (isset($data['rfc']) && $data['rfc'] != '') {
                $request_url = $this->base_request_url . $data['form_code'] . "/" . $data['wvnmi_screen_name'] . "/rpk/" . $data['rpk'] . "/rfc/" . $data['rfc'];
            }
        } else {
            if (isset($data['return_vendor'])) {
                $request_url = $this->base_request_url . $data['form_code'] . "/return/" . (int)$data['return_vendor'];
            }else{
                $request_url = $this->base_request_url . $data['form_code'] . "/" . $data['wvnmi_screen_name'];
            }
        }

        $responses = wp_remote_retrieve_body(wp_remote_post($request_url, $request_args));

        // invite who logs in WITHOUT proper rfc/rpk:
        // $responses needs to return rpk and cpk if
        // applicants::client_id and applicants::pproval_status = 4,
        // pulled from relations of applicants::applic_invite_id

        return $responses;
    }

     /**
     * @param $data
     * @return string
     */
    private function _execute_register_screen_submission($data)
    {
        global $wp;

        $headers = $this->_set_request_header(['Accept' => "application/json, text/javascript, */*; q=0.01", 'Authorization' => 'Basic ' . $this->plugin_api_auth_key]);

        $redirect_url = esc_url(sanitize_url($_SERVER['HTTP_REFERER']));
        $data['Clients']['referring_url'] = json_encode($redirect_url);
        $data['Clients']['gdpr_ip'] = isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : null;

        $data['Clients']['rpk'] = isset($_COOKIE['rpk']) ? sanitize_text_field($_COOKIE['rpk']) : null;
        $data['Clients']['rfc'] = isset($_COOKIE['rfc']) ? sanitize_text_field($_COOKIE['rfc']) : null;

        $request_args = $this->_get_request_args([
                'method' => 'POST',
                'headers' => $headers,
                'body' => $data['Clients']
            ]
        );

        if (isset($data['mode']) && $data['mode'] == 'regconfirm') {
            $request_url = $this->base_request_url . $data['form_code'] . "/" . $data['wvnmi_screen_name'] . "/" . $data['mode'] . "/cpk/" . $data['cpk'];

        } elseif (isset($data['profile_key']) && $data['profile_key'] != '') {
            if (isset($data['rfc']) && $data['rfc'] != '') {
                $request_url = $this->base_request_url . $data['form_code'] . "/" . $data['wvnmi_screen_name'] . "/" . $data['profile_key'] . "/" . $data['rfc'];
            }else{
                $request_url = $this->base_request_url . $data['form_code'] . "/" . $data['wvnmi_screen_name'] . "/" . $data['profile_key'];
            }
        } else {
            if (isset($data['return_vendor'])) {
                $request_url = $this->base_request_url . $data['form_code'] . "/return/" . (int)$data['return_vendor'];
            }else{
                $request_url = $this->base_request_url . $data['form_code'] . "/" . $data['wvnmi_screen_name'] . "/" . $data['mode'];
            }
        }

        $responses = wp_remote_retrieve_body(wp_remote_post($request_url, $request_args));

        return $responses;
    }

     /**
     * @param $data
     * @return string
     */
    private function _execute_passreset_screen_submission($data)
    {
        global $wp;

        $headers = $this->_set_request_header(['Accept' => "application/json, text/javascript, */*; q=0.01", 'Authorization' => 'Basic ' . $this->plugin_api_auth_key]);

        $redirect_url = $_SERVER['HTTP_REFERER'];
        $data['Clients']['referring_url'] = json_encode($redirect_url);
        $data['Clients']['mode'] = $data['mode'];

        $request_args = $this->_get_request_args([
                'method' => 'POST',
                'headers' => $headers,
                'body' => $data['Clients']
            ]
        );

        /////////////////////////////////
        // passreset form_key = passreset
        // replace $attributes['form_key'] to display passreset form

        $request_url = $this->base_request_url . $data['form_code'] . "/" . $data['wvnmi_screen_name'] . "/" . $data['mode'];

        $responses = wp_remote_retrieve_body(wp_remote_post($request_url, $request_args));

        return $responses;
    }

    /**
     * @param $data
     * @return string
     */
    private function _execute_privacysign_screen_submission($data)
    {
        global $wp;

        $headers = $this->_set_request_header(['Accept' => "application/json, text/javascript, */*; q=0.01", 'Authorization' => 'Basic ' . $this->plugin_api_auth_key]);

        $redirect_url = $_SERVER['HTTP_REFERER'];
        $data['Clients']['referring_url'] = json_encode($redirect_url);
        $data['Clients']['gdpr_ip'] = isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : null;

        $request_args = $this->_get_request_args([
                'method' => 'POST',
                'headers' => $headers,
                'body' => $data['Clients']
            ]
        );

        if (isset($data['profile_key']) && $data['profile_key'] != '') {
            if (isset($data['rfc']) && $data['rfc'] != '') {
                $request_url = $this->base_request_url . $data['form_code'] . "/" . $data['wvnmi_screen_name'] . "/" . $data['profile_key'] . "/" . $data['rfc'];
            }else{
                $request_url = $this->base_request_url . $data['form_code'] . "/" . $data['wvnmi_screen_name'] . "/" . $data['profile_key'];
            }
        } else {
            if (isset($data['return_vendor'])) {
                $request_url = $this->base_request_url . $data['form_code'] . "/return/" . (int)$data['return_vendor'];
            }else{
                $request_url = $this->base_request_url . $data['form_code'] . "/" . $data['wvnmi_screen_name'];
            }
        }

        $responses = wp_remote_retrieve_body(wp_remote_post($request_url, $request_args));

        return $responses;
    }

    /**
     * @param $data
     * @return string
     */
    private function _execute_profile_screen_submission($data)
    {
        global $wp;

        $headers = $this->_set_request_header(['Accept' => "application/json, text/javascript, */*; q=0.01", 'Authorization' => 'Basic ' . $this->plugin_api_auth_key]);

        if(is_array($data['Clients']['client_applic_type'])) {
            if ($this->_count_array($data['Clients']['client_applic_type']) > 0) {
                $data['Clients']['client_applic_type'] = json_encode($data['Clients']['client_applic_type']);
            }
        }

        if(is_array($data['Clients']['client_applic_type'])) {
            if ($this->_count_array($data['Clients']['client_merc']) > 0) {
                $data['Clients']['client_merc'] = json_encode($data['Clients']['client_merc']);
            }
        }

        $redirect_url = $_SERVER['HTTP_REFERER'];
        $data['Clients']['referring_url'] = json_encode($redirect_url);

        $request_args = $this->_get_request_args([
                'method' => 'POST',
                'headers' => $headers,
                'body' => $data['Clients']
            ]
        );

        if (isset($data['profile_key']) && !empty($data['profile_key'])) {
            $request_url = $this->base_request_url . $data['form_code'] . "/" . $data['wvnmi_screen_name'] . "/" . $data['profile_key'];

            if (isset($data['rfc']) && !empty($data['rfc'])) {
                $request_url .= "/" . $data['rfc'];
            }

        } elseif (isset($data['rfc']) && isset($data['rpk'])) {
            $request_url = $this->base_request_url . $data['form_code'] . "/" . $data['wvnmi_screen_name'] . "/" . $data['rpk'] . "/" . $data['rfc'];

        } else {
            if (isset($data['return_vendor'])) {
                $request_url = $this->base_request_url . $data['form_code'] . "/return/" . (int)$data['return_vendor'];
            }else{
                $request_url = $this->base_request_url . $data['form_code'] . "/" . $data['wvnmi_screen_name'];
            }
        }

        $responses = wp_remote_retrieve_body(wp_remote_post($request_url, $request_args));

        return $responses;
    }

    /**
     * @param $data
     * @return string
     */
    private function _execute_session_screen_submission($data)
    {
        global $wp;

        $headers = $this->_set_request_header(['Accept' => "application/json, text/javascript, */*; q=0.01", 'Authorization' => 'Basic ' . $this->plugin_api_auth_key]);

        if(is_array($data['Sessions']['client_applic_type'])) {
            if ($this->_count_array($data['Sessions']['client_applic_type']) > 0) {
                $data['Sessions']['client_applic_type'] = json_encode($data['Sessions']['client_applic_type']);
            }
        }

        if(is_array($data['Sessions']['client_applic_type'])) {
            if ($this->_count_array($data['Sessions']['client_merc']) > 0) {
                $data['Sessions']['client_merc'] = json_encode($data['Sessions']['client_merc']);
            }
        }

        $redirect_url = $_SERVER['HTTP_REFERER'];
        $data['Sessions']['referring_url'] = json_encode($redirect_url);

        $request_args = $this->_get_request_args([
                'method' => 'POST',
                'headers' => $headers,
                'body' => $data['Sessions']
            ]
        );

        // print_r($request_args); die;

        if (isset($data['profile_key']) && !empty($data['profile_key'])) {
            $request_url = $this->base_request_url . $data['form_code'] . "/" . $data['wvnmi_screen_name'] . "/" . $data['profile_key'];

            if (isset($data['rfc']) && !empty($data['rfc'])) {
                $request_url .= "/" . $data['rfc'];
            }

        } elseif (isset($data['rfc']) && isset($data['rpk'])) {
            $request_url = $this->base_request_url . $data['form_code'] . "/" . $data['wvnmi_screen_name'] . "/" . $data['rpk'] . "/" . $data['rfc'];

        } else {
            if (isset($data['return_vendor'])) {
                $request_url = $this->base_request_url . $data['form_code'] . "/return/" . (int)$data['return_vendor'];
            }else{
                $request_url = $this->base_request_url . $data['form_code'] . "/" . $data['wvnmi_screen_name'];
            }
        }

        $responses = wp_remote_retrieve_body(wp_remote_post($request_url, $request_args));

        return $responses;
    }

    /**
     * @param $data
     */
    private function _execute_payment_screen_submission($data) {

        $headers = $this->_set_request_header(['Accept' => "application/json, text/javascript, */*; q=0.01", 'Authorization' => 'Basic ' . $this->plugin_api_auth_key]);

        $request_args = $this->_get_request_args([
                'method'  => 'POST',
                'headers' =>  $headers,
                'body'    => $data
            ]
        );

        $request_url = $this->base_request_url . $data['form_code'] . "/" . $data['wvnmi_screen_name'] . "/" . $data['profile_key'] . "/" . $data['payment_processor'];

        $responses = wp_remote_retrieve_body(wp_remote_request($request_url, $request_args));

        return $responses;
    }

    /**
     * @param $data
     * @return string
     */
    private function _execute_map_book_booth_submission($data)
    {
        $headers = $this->_set_request_header(['Accept' => "application/json, text/javascript, */*; q=0.01", 'Authorization' => 'Basic ' . $this->plugin_api_auth_key]);

        $data['Clients']['amenity_types'] = isset($data['Clients']['amenity_types']) ? $data['Clients']['amenity_types'] : 0;

        if(isset($data['amenity_extra'])){
            $body = ['AmenitiesExtra' => ['amenity_extra' => $data['amenity_extra']]];
        }else{
            $body = ['Amenities' => ['amenity_types' => $data['Clients']['amenity_types']], 'amenity_qty' => $data['amenity_qty']];
        }

        $request_args = $this->_get_request_args([
                'method'  => 'POST',
                'headers' =>  $headers,
                'body'    => $body
            ]
        );

        if(isset($data['Clients']['Value']['applic_profile_key']) && $data['Clients']['Value']['applic_profile_key'] != '') {
            $request_url = $this->base_request_url . $data['Clients']['Value']['form_code'] . '/' . $data['wvnmi_screen_name'] . "/" . $data['Clients']['Value']['applic_profile_key'];
        }else{
            $request_url = $this->base_request_url . $data['Clients']['Value']['form_code'] . "/" . $data['wvnmi_screen_name'];
        }

        $responses = wp_remote_retrieve_body(wp_remote_request($request_url, $request_args));

        if(isset($data['amenity_extra'])) {

        }

        return $responses;
    }

    /**
     * @param $data
     * @return string
     */
    private function _execute_amenities_screen_submission($data)
    {
        $headers = $this->_set_request_header(['Accept' => "application/json, text/javascript, */*; q=0.01", 'Authorization' => 'Basic ' . $this->plugin_api_auth_key]);

        // bug fix to correct issue when de-selecting All amenities
        // $data['Clients']['amenity_types'] may not be set
        $data['Clients']['amenity_types'] = isset($data['Clients']['amenity_types']) ? $data['Clients']['amenity_types'] : 0;

        if(isset($data['amenity_extra']) && isset($data['amenity_extra_custom'])){
            $body = ['AmenitiesExtra' =>
                        [
                            'amenity_extra' => $data['amenity_extra'],
                            'amenity_extra_custom' => $data['amenity_extra_custom']
                        ]
                    ];
        }elseif(isset($data['amenity_extra'])){
            $body = ['AmenitiesExtra' =>
                        [
                            'amenity_extra' => $data['amenity_extra']
                        ]
                    ];
        }else{
            $body = ['Amenities' => [
                    'amenity_types' => $data['Clients']['amenity_types']
                    ],
                    'amenity_qty' => $data['amenity_qty'],
                    'amenity_game_qty' => $data['amenity_game_qty'],
                    'comment' => $data['Clients']['comment']
                    ];
        }

        $request_args = $this->_get_request_args([
                'method'  => 'POST',
                'headers' =>  $headers,
                'body'    => $body
            ]
        );

        if(isset($data['profile_key'])) {
            $request_url = $this->base_request_url . $data['Clients']['Value']['form_code'] . '/' . $data['wvnmi_screen_name'] . "/" . $data['profile_key'];

        }elseif(isset($_SESSION['temp_pk'])) {
            $request_url = $this->base_request_url . $data['Clients']['Value']['form_code'] . '/' . $data['wvnmi_screen_name'] . "/" . $_SESSION['temp_pk'] . ".temp_pk";

        }else{
            $request_url = $this->base_request_url . $data['Clients']['Value']['form_code'] . "/" . $data['wvnmi_screen_name'];
        }

        $responses = wp_remote_retrieve_body(wp_remote_request($request_url, $request_args));

        if(isset($data['amenity_extra'])) {
            // print_r($responses); die;
        }

        return $responses;
    }

    /**
     * @param $data
     * @return array
     */
    private function _execute_uploads_screen_submission_does_NOT_work_using_native_WP_functions($data)
    {
        $postData = [];
        if(isset($_FILES['DynamicModel']['name']) && $this->_count_array($_FILES['DynamicModel']['name']) > 0) {

            foreach ($_FILES['DynamicModel']['name'] as $key => $file) {

                if($file != '') {
                    //$postData[$key] = '@' . $_FILES['DynamicModel']['tmp_name'][$key] . ';filename=' . $_FILES['DynamicModel']['name'][$key] . ';type=' . $_FILES['DynamicModel']['type'][$key];
                    $files_a[$key]['tmp_name'] = $_FILES['DynamicModel']['tmp_name'][$key];
                    $files_a[$key]['type'] = $_FILES['DynamicModel']['type'][$key];
                    $files_a[$key]['name'] = basename($_FILES['DynamicModel']['name'][$key]);
                    $files_a[$key]['lic_id'] = $key;
                }
            }
        }

        $postData[] = ["upload_files" => ""];

        $postData['meta'] = sanitize_text_field($_POST['DynamicModel']['meta']);

        if(isset($data['DynamicModel']['Value']['applic_profile_key']) && $data['DynamicModel']['Value']['applic_profile_key'] != '') {
            $request_url = $this->base_request_url . $data['form_code'] . '/' . $data['wvnmi_screen_name'] . "/" . $data['DynamicModel']['Value']['applic_profile_key'];
        }else{
            $request_url = $this->base_request_url . $data['form_code'] . "/" . $data['wvnmi_screen_name'];
        }

        foreach($files_a AS $file_a){

            // wp_remote_request way
            $file = @fopen( $file_a['tmp_name'], 'r' );
            $file_size = filesize( $file_a['tmp_name'] );

            $image_type = $file_a['type'];
            $photo_sized = $file_a['tmp_name'];

            $name = $file_a['name'];

            $args = array();
            $args['headers']['Content-Type'] = $image_type;
            $args['headers']['Content-Length'] = filesize( $photo_sized );
            $args['headers']['Content-Disposition'] = "filename=" . basename( $photo_sized );
            $contents = file_get_contents( $photo_sized );
            $args['headers']['Content-MD5'] = md5( $contents );
            // $args['body'] = $contents;
            $args['stream'] = $photo_sized;
            $args['filename'] = $name;
            $args['headers']['Authorization'] = 'Basic ' . $this->plugin_api_auth_key;

            $response = wp_remote_post( $request_url, $args );
        }

        // set the response
        $responses = [];
        if(isset($data['DynamicModel']['Value']['applic_profile_key']) && $data['DynamicModel']['Value']['applic_profile_key']) {
            $responses['profile_key'] = $data['DynamicModel']['Value']['applic_profile_key'];
            $responses['upload_status'] = json_decode($response, true);
        }

        return $responses;
    }
    /**
     * @param $data
     * @return array
     */
    private function _execute_uploads_screen_submission($data)
    {
        // NOTE:
        // uses curl because there's no good solution to post a file to API using native wp_remote_post()
        // hopefully WP will add better support for this in the future

        $postData = [];
        if(isset($_FILES['DynamicModel']['name']) && $this->_count_array($_FILES['DynamicModel']['name']) > 0) {

            foreach ($_FILES['DynamicModel']['name'] as $key => $file) {

                if($file != '') {

                    $tmp_name_key = sanitize_text_field($_FILES['DynamicModel']['tmp_name'][$key]);
                    $name_key = sanitize_text_field($_FILES['DynamicModel']['name'][$key]);
                    $type_key = sanitize_text_field($_FILES['DynamicModel']['type'][$key]);

                    if($this->_check_php_version()) {
                        $postData[$key] = new CURLFile($tmp_name_key, $type_key, basename($name_key));
                    }else{
                        $responses[$key] = '@' . $tmp_name_key . ';filename=' . $name_key . ';type=' . $type_key;
                    }
                }
            }
        }

        $postData[] = ["upload_files" => ""];

        $postData['meta'] = sanitize_text_field($_POST['DynamicModel']['meta']);

        if(isset($data['DynamicModel']['Value']['applic_profile_key']) && $data['DynamicModel']['Value']['applic_profile_key'] != '') {
            $request_url = esc_url(sanitize_url($this->base_request_url . $data['form_code'] . '/' . $data['wvnmi_screen_name'] . "/" . $data['DynamicModel']['Value']['applic_profile_key']));
        }else{
            $request_url = esc_url(sanitize_url($this->base_request_url . $data['form_code'] . "/" . $data['wvnmi_screen_name']));
        }

        // initialize the curl request
        // needed for file uploads
        if (function_exists('curl_init')) {

            $curl_request = curl_init();

            curl_setopt($curl_request, CURLOPT_URL, $request_url);
            // modify curl request to send file
            curl_setopt($curl_request, CURLOPT_POST, true);

            // add file into curl request
            curl_setopt($curl_request, CURLOPT_POSTFIELDS, $this->_build_post_fields($postData));

            // initialize curl headers
            $curl_headers = $this->_set_request_header([
                'Content-Type' => "multipart/form-data",
                'Accept' => "application/json, text/javascript, */*; q=0.01",
                'Authorization' => 'Basic ' . $this->plugin_api_auth_key
            ]);

            // set curl http headers
            curl_setopt($curl_request, CURLOPT_HTTPHEADER, $curl_headers);

            // modify curl to return response
            curl_setopt($curl_request, CURLOPT_RETURNTRANSFER, true);

            $curl_responses = curl_exec($curl_request);

            curl_close($curl_request);

            // set the response
            $responses = [];
            if(isset($data['DynamicModel']['Value']['applic_profile_key']) && $data['DynamicModel']['Value']['applic_profile_key']) {
                $responses['profile_key'] = $data['DynamicModel']['Value']['applic_profile_key'];
                $responses['upload_status'] = json_decode($curl_responses, true);
            }

            return $responses;

        }else{
            $responses['profile_key'] = $data['DynamicModel']['Value']['applic_profile_key'];
            $responses['upload_status'] = false;

            return $responses;
        }
    }

    /**
     * Converts multidimensional arrays to single dim array for CURLOPT_POSTFIELDS
     * @param $data
     * @param string $existingKeys
     * @param array $returnArray
     * @return array
     */
    private function _build_post_fields( $data,$existingKeys='',&$returnArray=[]){
        if(($data instanceof CURLFile) or !(is_array($data) or is_object($data))){
            $returnArray[$existingKeys]=$data;

            return $returnArray;

        }else{
            foreach ($data as $key => $item) {
                $this->_build_post_fields($item,$existingKeys?$existingKeys."[$key]":$key,$returnArray);
            }
            return $returnArray;
        }
    }

    /**
     * @param array $args
     * @return array
     */
    private function _get_request_args($args = [])
    {
        return $this->_set_request_args($args);
    }

    /**
     * @param array $headers
     * @return array
     */
    private function _set_request_header($headers = [])
    {
        $current_headers = $this->default_headers;

        if(!empty($current_headers)) {
            foreach($headers as $key => $val) {

                $current_headers[$key] = $val;
            }
        }
        return $this->_generate_request_headers($current_headers);
    }

    /**
     * @param array $headers
     * @return array
     */
    private function _generate_request_headers($headers = [])
    {
        $request_headers = [];

        if(!empty($headers)) {
            foreach($headers as $key => $val) {
                $request_headers[] = $key . ":" . $val;
            }
        }
        return $request_headers;
    }

    /**
     * @param array $args
     * @return array
     */
    private function _set_request_args($args = [])
    {
        $current_args = $this->default_args;

        if(!empty($args)) {

            foreach($args as $key => $val) {
                if(array_key_exists($key, $current_args)) {
                    $current_args[$key] = $val;
                }
            }
        }
        return $current_args;
    }

    /**
     * @return string
     */
    private function _get_current_screen($rec_type = 1, $ticketing_nav_order = 1)
    {
        if(isset( $_GET['css'])){
            return "css";

        }elseif(isset( $_GET['profile'])){
            return "profile";

        }elseif(isset( $_GET['session'])){
            return "session";

        }elseif(isset( $_GET['uploads'])){
            return "uploads";

        }elseif(isset( $_GET['amenities'])) {

            if(isset( $_GET['map']) && $_GET['map'] != '') {
                return "map";
            }else{
                return "amenities";
            }

        }elseif(isset( $_GET['badges'])){
            return "badges";

        }elseif(isset( $_GET['terms'])) {

            if(isset( $_GET['signature']) && $_GET['signature'] != '') {
                return "signature";
            }else{
                return "terms";
            }

        }elseif(isset( $_GET['payment'])){
            return "payment";

        }elseif(isset( $_GET['mapview'])){
            return "mapview";

        }elseif(isset( $_GET['login'])){
            return "login";

        }elseif(isset( $_GET['logout'])){
            return "logout";

        }elseif(isset( $_GET['register'])){
            return "register";

        }elseif(isset( $_GET['passreset'])){
            return "passreset";

        }elseif(isset( $_GET['privacysign'])){
            return "privacysign";

        }elseif(isset( $_GET['clearsession'])){
            return "clearsession";

        }else{
            if($rec_type == 1){
                return "login";

            }elseif($rec_type == 3){

                 /*
                 * 1 = select, profile
                 * 2 = profile, select
                 * */
                if($ticketing_nav_order == 1){
                    return "amenities";
                }else{
                    return "profile";
                }
            }else{
                return "profile";
            }
        }
    }

    /**
     * @param $formData
     * @return string
     */
    private function _payment_screen($formData)
    {
        $form = "";

        $form = $this->_set_application_title($this->event_attributes, $form);

        $form = $this->_set_application_steps("payment", $form, $formData);

        $form = $this->_create_payment_screen_fields($formData, $form);

        return $this->_wrap_with_parents($form);
    }

    /**
     * @param $formData
     * @return string
     */
    private function _signature_screen($formData)
    {
        $form = "";

        // process terms checkbox submission
        if(isset( $_GET['signature']) && $_GET['signature'] == 3) {

            $event_attributes = json_decode($this->event_attributes, true);
            $data['form_code'] = $event_attributes['event_a']['form_code'];
            $data['profile_key'] = "{$event_attributes['applicant_a']['profile_key']}.{$_SESSION['api_token']}"; // => GZNFFuJDmmiFpM2NTldI
            $data['wvnmi_screen_name'] = 'terms_confirm';

            $this->_execute_form_submission($data, $this->_get_form_root_path(wp_get_referer()));
        }

        $form = $this->_create_signature_screen_fields($formData, $form);

        return $form;
    }

    /**
     * @param $formData
     * @return string
     */
    private function _terms_screen($formData)
    {
        $form = "";

        $form = $this->_set_application_title($this->event_attributes, $form);

        $form = $this->_set_application_steps("terms", $form, $formData);

        $form = $this->_create_terms_screen_fields($formData, $form);

        return $this->_wrap_with_parents($form);
    }

    /**
     * @param $formData
     * @return string
     */
    private function _map_screen($request_url_info)
    {
        $form = "";

        $form = $this->_create_map_screen_fields($request_url_info);

        return $form;
    }


    /**
     * @param $formData
     * @return string
     */
    private function _mapview_screen($request_url_info)
    {
        $form = "";

        $form = $this->_create_mapview_screen_fields($request_url_info);

        return $form;
    }

    /**
     * @param $formData
     * @return string
     */
    private function _uploads_screen($formData)
    {
        $form = "";

        $form = $this->_set_application_title($this->event_attributes, $form);

        $form = $this->_set_application_steps('uploads', $form, $formData);

        $form = $this->_create_uploads_screen_fields($formData, $form);

        return $this->_wrap_with_parents($form);
    }

    /**
     * @param $formData
     * @return string
     */
    private function _error_screen($formData)
    {
        $form = "";

        $form = $this->_set_application_title($this->event_attributes, $form);

        // $form = $this->_set_application_steps('profile', $form, $formData);

        $form = $this->_create_error_screen($formData, $form);

        return $this->_wrap_with_parents($form);
    }

    /**
     * @param $formData
     * @return string
     */
    private function _login_screen($formData, $audit = 0)
    {
        $form = "";

        $form = $this->_set_application_title($this->event_attributes, $form);

        $form = $this->_set_application_steps('login', $form, $formData);

        $form = $this->_create_login_screen_fields($formData, $form, $audit);

        return $this->_wrap_with_parents($form);
    }

    /**
     * @param $formData
     * @return string
     */
    private function _passreset_screen($formData)
    {
        $form = "";

        $form = $this->_set_application_title($this->event_attributes, $form);

        $form = $this->_set_application_steps('passreset', $form, $formData);

        $form = $this->_create_passreset_screen_fields($formData, $form);

        return $this->_wrap_with_parents($form);
    }

    /**
     * @param $formData
     * @return string
     */
    private function _register_screen($formData)
    {
        $form = "";

        $form = $this->_set_application_title($this->event_attributes, $form);

        $form = $this->_set_application_steps('register', $form, $formData);

        $form = $this->_create_register_screen_fields($formData, $form);

        return $this->_wrap_with_parents($form);
    }

    /**
     * @param $formData
     * @return string
     */
    private function _privacysign_screen($formData)
    {
        $form = "";

        $form = $this->_set_application_title($this->event_attributes, $form);

        $form = $this->_set_application_steps('profile', $form, $formData);

        $form = $this->_create_privacysign_screen_fields($formData, $form);

        return $this->_wrap_with_parents($form);
    }

    /**
     * @param $formData
     * @return string
     */
    private function _profile_screen($formData)
    {
        $form = "";

        // print_r($this->event_attributes); die;
        $event_a = $formData['event_a'];

        $form = $this->_set_application_title($this->event_attributes, $form);

        $form = $this->_set_application_steps('profile', $form, $formData);

        $form = $this->_create_profile_screen_fields($formData, $form);

        return $this->_wrap_with_parents($form);
    }

    /**
     * @param $formData
     * @return string
     */
    private function _session_screen($formData)
    {
        $form = "";

        // print_r($this->event_attributes); die;
        $event_a = $formData['event_a'];

        $form = $this->_set_application_title($this->event_attributes, $form);

        $form = $this->_set_application_steps('session', $form, $formData);

        $form = $this->_create_session_screen_fields($formData, $form);

        return $this->_wrap_with_parents($form);
    }

    /**
     * @param $formData
     * @return string
     */
    private function _amenities_screen($formData)
    {
        $form = "";
        $raw_output = false;

        // print_r($this->event_attributes); die;

        $form = $this->_set_application_title($this->event_attributes, $form, $raw_output);

        $form_attributes_a = json_decode($this->event_attributes, true);

        // $form = $this->_set_application_steps("amenities", $form, $formData, $raw_output);

        if(isset( $_GET['extra']) && $_GET['extra'] != null){
            $form = $this->_set_application_steps("badges", $form, $formData, $raw_output);
            $form = $this->_create_extra_screen_fields($formData, $form, $form_attributes_a);
        }else{
            $form = $this->_set_application_steps("amenities", $form, $formData, $raw_output);
            $form = $this->_create_amenities_screen_fields($formData, $form);
        }

        return $this->_wrap_with_parents($form, $raw_output);
    }

    /**
     * @param $formData
     * @param $field_type (checkbox/radio)
     * @return string
     */
    private function _generate_checkboxes_client_types($input_data, $field_type = 'checkbox') {

        $client_types_description_a = $input_data['client_types_description_a'];

        $applicant_a = [];
        if(isset($input_data['client_type']))
            $applicant_a = json_decode($input_data['client_type'], true);

        $selectors = '';
        if(isset($input_data['client_type']) && !empty($applicant_a)) {

            $c = 0;
            foreach($input_data['client_types_a'] as $tKey => $tVal) {
                $c++;
                $div = "<div class=\"col-lg-8 {$field_type}\">";

                if($field_type == 'checkbox') {
                    $required = $c == 1 && $input_data['required'] == 1 ? 'data-parsley-mincheck="1" data-parsley-errors-container="#error-box-' . $input_data['model_field'] . '" required' : '';
                }else{
                    $required = $c == 1 && $input_data['required'] == 1 ? 'data-parsley-errors-container="#error-box-' . $input_data['model_field'] . '" required' : '';
                }

                if(in_array($tKey, $applicant_a)) {
                    $div .= "<input ".$required." id=\"client_type_" . $tKey . "\" class=\"client_type\" type=\"{$field_type}\" checked=\"checked\" name=\"Clients[client_applic_type][]\" value=\"" . $tKey . "\">";
                }else{
                    $div .= "<input ".$required." id=\"client_type_" . $tKey . "\" class=\"client_type\" type=\"{$field_type}\" name=\"Clients[client_applic_type][]\" value=\"" . $tKey . "\">";
                }

                $div .= "<label for=\"client_type_" . $tKey. "\">{$tVal}</label>";
                if(!empty($client_types_description_a[$tKey])){
                    $div .= "<div class='well well-infobox client_desc'>{$client_types_description_a[$tKey]}</div>";
                }
                $div .= "</div>";

                $selectors .= $div;
            }
        }else{
            $c = 0;
            foreach($input_data['client_types_a'] as $tKey => $tVal) {
                $c++;
                $div = "<div class=\"col-lg-8 {$field_type}\">";

                $required = $c == 1 && $input_data['required'] == 1 ? 'data-parsley-errors-container="#error-box-'.$input_data['model_field'].'" required' : '';

                $div .= "<input ".$required." id=\"client_type_" . $tKey . "\" class=\"client_type\" type=\"{$field_type}\" name=\"Clients[client_applic_type][]\" value=\"" . $tKey. "\">";

                $div .= "<label for=\"client_type_" . $tKey. "\">{$tVal}</label>";
                if(!empty($client_types_description_a[$tKey])){
                    $div .= "<div class='well well-infobox client_desc'>{$client_types_description_a[$tKey]}</div>";
                }
                $div .= "</div>";

                $selectors .= $div;
            }
        }
        return $selectors;
    }

    /**
     * @param $key
     * @param $data
     * @param bool $partial
     * @return string
     */
    private function _uploaded_file_status($key, $data, $partial = false)
    {
        ob_start();
        if(isset($data['lic_id_status_a'][$key])):
            ?>
            <?php if(!$partial): ?>
            <span style="font-size: 17px;" class="green-alert">
                <i class="fa fa-check" aria-hidden="true"></i>
            </span>
            Uploaded <strong><?php echo sanitize_text_field($data['lic_id_file_names_a'][$key]); ?></strong>
        <?php endif; ?>
            <?php if($data['lic_id_status_a'][$key] == 1): ?>
            <span class="tooltip-success label label-success" data-original-title="" style="white-space: nowrap; text-decoration: none; cursor: default;">Approved</span>
        <?php elseif($data['lic_id_status_a'][$key] == 2): ?>
            <span class="tooltip-danger label label-danger" data-original-title="" style="white-space: nowrap; text-decoration: none; cursor: default;">On Hold, please review</span>
        <?php else: ?>
            <span class="tooltip-warning label label-warning" data-original-title="" style="white-space: nowrap; text-decoration: none; cursor: default;">Pending Review</span>
        <?php
        endif;
        endif;

        return ob_get_clean();
    }

    /**
     * @param array $area
     * @return string
     */
    private function _generate_viewmap_area($area = [])
    {
        ob_start();
        ?>
        <area id="id_<?php echo esc_attr($area['href']); ?>" key="id_<?php echo esc_attr($area['href']); ?>" full="#<?php echo esc_attr($area['href']); ?>" title="<?php echo esc_attr($area['title']); ?>" shape="<?php echo esc_attr($area['type']); ?>" coords="<?php echo esc_attr($area['coords']); ?>" href="#<?php echo esc_attr($area['href']); ?>" alt="<?php echo esc_attr($area['alt']); ?>">
        <?php
        return ob_get_clean();
    }

    /**
     * @param array $area
     * @return string
     */
    private function _generate_map_area($area = [])
    {
        ob_start();
        ?>
        <area key="<?php echo esc_attr($area['href']); ?>" full="#<?php echo esc_attr($area['href']); ?>" title="<?php echo esc_attr($area['title']); ?>" shape="<?php echo esc_attr($area['type']); ?>" coords="<?php echo sanitize_text_field($area['coords']); ?>" href="#<?php echo esc_attr($area['href']); ?>" alt="<?php echo esc_attr($area['alt']); ?>">
        <?php
        return ob_get_clean();
    }

    /**
     * @param $formData
     * @param $form
     * @return string
     */
    private function _create_payment_screen_fields($formData, $form)
    {
        global $wp;
        $current_url = home_url(add_query_arg([], $wp->request));
        $mt = str_replace('.', '', microtime(true));

        $event_attributes = json_decode($this->event_attributes, true);

        $applicant_payment = $formData;

        // inject formcode into $formData
        $formData['event_a']['form_code'] = $event_attributes['event_a']['form_code'];
        $formData['login_redirect'] = 'payment';

        $event_attributes['event_a']['notice1_body_merged'] = $applicant_payment['notice1_body_merged'];

        $approval_status = $event_attributes['applicant_a']['approval_status'];

        $app_incomplete = false;
        if($this->_count_array($event_attributes['error_details_a']) > 0):
            if (in_array('map', $event_attributes['error_details_a'])):
                $app_incomplete = true;
            endif;

            if(in_array('uploads', $event_attributes['error_details_a'])):
                $app_incomplete = true;
            endif;

            if(in_array('terms', $event_attributes['error_details_a'])):
                $app_incomplete = true;
            endif;
        endif;

        $paypal_notice = '';
        if(isset( $_GET['return'] ) && $_GET['return'] != null){
            $paypal_notice = '<div class="well well-sm" style="margin-bottom:10px; margin-top:10px;"><i style="float:left; margin-right:10px;" class="fa fa-2x fa-exclamation-circle blue" aria-hidden="true"></i>
                Payments may take a few seconds to register as paid, so refresh this page if your payment still displays as due.
            </div>';
        }

        ob_start();

        // fallback for older plugins
        // to-do: make fallback function to instantiate default vals from api to support older plugins
        $applicant_payment['fee_override'] = array_key_exists('fee_override',$applicant_payment) ? $applicant_payment['fee_override'] : 0;

        if(isset($applicant_payment['dataProvider_fees']['allModels'])){
            if($this->_count_array($applicant_payment['dataProvider_fees']['allModels']) > 0){
                $cart_items_exists = true;
            }
        }else{
            $cart_items_exists = false;
        }

        if(!$cart_items_exists &&
            $applicant_payment['fee_total'] == 0 &&
            $applicant_payment['fee_total_paid'] == 0 &&
            $applicant_payment['fee_override'] == 0 &&
            $applicant_payment['fee_total_once_approved'] == 0):

            if($this->_count_array($event_attributes['error_details_a']) > 0):

                if (in_array('map', $event_attributes['error_details_a'])): ?>
                    <a class="btn btn-error"
                       href="<?php echo esc_url(sanitize_url($this->_get_skip_url(['amenities' => '', 'pk' => sanitize_text_field($_GET['pk'])]))); ?>"
                       style="text-decoration: none;">
                        <h3>Select a booth location</h3>
                    </a>
                <?php endif; ?>

                <?php if (in_array('uploads', $event_attributes['error_details_a'])): ?>
                    <a class="btn btn-error"
                       href="<?php echo esc_url(sanitize_url($this->_get_skip_url(['uploads' => '', 'pk' => sanitize_text_field($_GET['pk'])]))); ?>"
                       style="text-decoration: none;">
                        <h3>Please upload required docs</h3>
                    </a>
                <?php endif; ?>

                <?php if (in_array('terms', $event_attributes['error_details_a'])): ?>
                    <a class="btn btn-error"
                       href="<?php echo esc_url(sanitize_url($this->_get_skip_url(['terms' => '', 'pk' => sanitize_text_field($_GET['pk'])]))); ?>"
                       style="text-decoration: none;">
                        <h3><?php echo $this->_button_label_swap('signature_req'); ?></h3>
                    </a>
                <?php endif; ?>

            <?php else: ?>

                <div style="margin-top:20px; width:100%; text-align:center;">
                    <p>
                        <h2>
                            <span class="green-alert">
                                <i class="fa fa-check" aria-hidden="true"></i> <?php echo $event_attributes['event_a']['application_label']; ?> Complete.
                            </span>
                        </h2>
                    </p>
                </div>

                <div style="width:100%; text-align:center;">
                    <?php echo $this->_get_approval_status($approval_status, $event_attributes['event_a']); ?>
                    <?php echo $this->_display_payment_info($event_attributes['event_a']); ?>
                </div>

            <?php endif; ?>

        <?php else: ?>

            <div class="col-lg-offset-2">
                <?php if(!empty($event_attributes['event_a']['payment_note'])): ?>
                    <div class="block_text well" style="margin-left: 0px; margin-top:4px;"><?php echo $event_attributes['event_a']['payment_note'] ?></div>
                <?php endif; ?>
            </div>

            <?php if($event_attributes['event_a']['pay_policy'] != 4): ?>

                <!--// begin cart -->
                <div class="grid-view">
                    <table class="cart-line-item-table table mce-table-striped table-bordered">
                        <thead style="white-space: nowrap;">
                        <tr>
                            <th class="cart-table-header cart-col-1">Item Description</th>
                            <th class="cart-table-header cart-col-2">Status</th>
                            <th class="cart-table-header cart-col-3a">Qty</th>
                            <th class="cart-table-header cart-col-3b">Qty Due</th>
                            <th class="cart-table-header cart-col-4">Price</th>
                            <th class="cart-table-header cart-col-5">Sub-Total</th>
                            <th class="cart-table-header cart-col-6">Qty Paid*</th>
                        </tr>
                        </thead>
                        <tbody>
                        <?php if(isset($applicant_payment['dataProvider_fees']['allModels'])): ?>
                            <?php if($this->_count_array($applicant_payment['dataProvider_fees']['allModels']) > 0): ?>
                                <?php foreach($applicant_payment['dataProvider_fees']['allModels'] as $key => $product): ?>
                                    <tr data-key="<?php echo esc_attr($product['id']); ?>">
                                        <?php if($product['item_desc']): ?>
                                            <td>
                                                <?php echo sanitize_text_field($product['item_desc']); ?>
                                            </td>
                                        <?php elseif($this->_count_array($applicant_payment['event_invoice_a']) > 0): ?>
                                            <td>
                                                <?php if($applicant_payment['event_invoice_a']['cart_display'] == 1): ?>
                                                    <div class="cart-invoice-bottom">
                                                        <a class="btn-nav btn-blue" target = "_blank" href="<?php echo esc_url(sanitize_url("https://app.wavenami.com/invoice/" . $event_attributes['applicant_a']['profile_key'])); ?>">View <?php echo sanitize_text_field($event_attributes['event_a']['invoice_label']); ?></a>
                                                    </div>
                                                <?php endif; ?>
                                            </td>
                                        <?php else: ?>
                                            <td>
                                            </td>
                                        <?php endif; ?>
                                        <td style="white-space: nowrap; text-align: center;" class="cart-col-2"><?php echo sanitize_text_field($product['status']); ?></td>
                                        <td style="white-space: nowrap; text-align: center;" class="cart-col-3a"><?php echo sanitize_text_field($applicant_payment['applicant_amen_qty_ordered_a'][$product['applic_amen_id']]); ?></td>
                                        <td style="white-space: nowrap; text-align: center;" class="cart-col-3b"><?php echo sanitize_text_field($product['qty']); ?></td>
                                        <td style="white-space: nowrap;" class="cart-col-4"><?php echo sanitize_text_field($product['fee']); ?></td>
                                        <td style="white-space: nowrap;" class="cart-col-5"><?php echo sanitize_text_field($product['fee_sub_total']); ?></td>
                                        <td style="white-space: nowrap;" class="cart-col-6"><?php echo sanitize_text_field($product['qty_paid']); ?></td>
                                    </tr>
                                <?php endforeach; ?>
                            <?php endif;?>
                        <?php endif; ?>
                        </tbody>
                    </table>
                </div>

                <div class="cart-total-label"><h5>*this is the quantity you have <span style="text-decoration: underline;">already</span> paid for.</h5></div>
                <!--// end cart -->

            <?php endif; ?>

            <!--// begin cart -->
            <?php if($event_attributes['event_a']['split_payment'] == 1): ?>
                <?php if(!$app_incomplete): ?>
                    <?php if(isset($applicant_payment['fee_total']) && $this->_count_array($applicant_payment['date_amount_selector_a']) > 0): ?>

                        <div class="grid-view split-payment-block">
                            <table class="cart-split-payments table mce-table-striped table-bordered">
                                <thead>
                                <tr>
                                    <th colspan="4" class="split-payment-header">
                                        <?php echo $event_attributes['event_a']['split_pay_header'] != null ? $event_attributes['event_a']['split_pay_header'] : "Payment Schedule"; ?>
                                    </th>
                                </tr>
                                <?php if($event_attributes['event_a']['split_pay_notes'] != null): ?>
                                    <tr>
                                        <th colspan="4" class="split-payment-notes">
                                            <?php echo $event_attributes['event_a']['split_pay_notes']; ?>
                                        </th>
                                    </tr>
                                <?php endif; ?>
                                <tr>
                                    <th class="cart-table-header"></th>
                                    <th class="cart-table-header">Percentage</th>
                                    <th class="cart-table-header">Due By</th>
                                    <th class="cart-table-header">Amount</th>
                                </tr>
                                </thead>
                                <tbody>
                                <?php if($this->_count_array($applicant_payment['date_amount_selector_a']) > 0): ?>
                                    <?php $c = 0; ?>
                                    <?php foreach($applicant_payment['date_amount_selector_a'] as $date => $split_data_a): ?>
                                        <?php
                                        $c++;
                                        $date_label = str_replace(".","/",$date);
                                        $odp = str_replace(".","_",$date);
                                        $select_botton = "<a href='" . esc_url(sanitize_url($current_url . "/?payment&pk=" . sanitize_text_field($_GET['pk']) . "&odp=" . $odp. "&v=" . $mt)) . "' class='btn-nav btn-blue'>Select</a>";
                                        $selected_class = "";
                                        if(sanitize_text_field($_GET['odp']) == $odp){
                                            $selected_class = "split-payment-selected";
                                        }elseif($c == 1 && $applicant_payment['fee_total'] == $split_data_a['total']){
                                            $selected_class = "split-payment-selected";
                                        }
                                        ?>
                                        <tr data-key="" class="<?php echo $selected_class; ?>">
                                            <td style="text-align: center;"><?php echo $select_botton; ?></td>
                                            <td><?php echo $split_data_a['ratio']; ?>%</td>
                                            <td><?php echo $date_label; ?></td>
                                            <td><?php echo $formData['currency_symbol'] ?><?php echo $split_data_a['total']; ?></td>
                                        </tr>
                                    <?php endforeach; ?>
                                <?php endif;?>
                                </tbody>
                            </table>
                        </div>

                    <?php endif;?>
                <?php endif; ?>
            <?php endif; ?>

            <?php echo $paypal_notice; ?>

            <?php
            if($this->_count_array($event_attributes['error_details_a']) > 0):

                if (in_array('amenities', $event_attributes['error_details_a'])):
                    $app_incomplete = true;
                    ?>
                    <a class="btn btn-error"
                       href="<?php echo esc_url(sanitize_url($this->_get_skip_url(['amenities' => '', 'pk' => sanitize_text_field($_GET['pk'])]))); ?>"
                       style="text-decoration: none; margin-top:10px; margin-bottom:20px;">
                        <h3><?php echo $this->_button_label_swap('amenities_req'); ?></h3>
                    </a>
                <?php endif; ?>

                <?php if(in_array('uploads', $event_attributes['error_details_a'])):
                    $app_incomplete = true;
                    ?>
                    <a class="btn btn-error"
                       href="<?php echo esc_url(sanitize_url($this->_get_skip_url(['uploads' => '', 'pk' => sanitize_text_field($_GET['pk'])]))); ?>"
                       style="text-decoration: none; margin-top:10px; margin-bottom:20px;">
                        <h3><?php echo $this->_button_label_swap('docs_req'); ?></h3>
                    </a>
                <?php endif; ?>

                <?php if(in_array('terms', $event_attributes['error_details_a'])):
                    $app_incomplete = true;
                    ?>
                    <a class="btn btn-error"
                       href="<?php echo esc_url(sanitize_url($this->_get_skip_url(['terms' => '', 'pk' => sanitize_text_field($_GET['pk'])]))); ?>"
                       style="text-decoration: none; margin-top:10px; margin-bottom:20px;">
                        <h3><?php echo $this->_button_label_swap('signature_req'); ?></h3>
                    </a>
                <?php endif; ?>

                <?php if($app_incomplete): ?>
                    <input type="hidden" style="display: none" value="" id="ccnum">
                <?php endif; ?>

            <?php endif; ?>

            <?php if($applicant_payment['fee_total'] == 0 && $applicant_payment['fee_total_paid'] > 0 && !$app_incomplete): ?>

                <div style="margin-top:20px; width:100%; text-align:center;">
                    <h2><span class="green-alert"><i class="fa fa-check" aria-hidden="true"></i> <?php echo $event_attributes['event_a']['application_label']; ?> Complete.</span></h2>
                </div>

                <div style="width:100%; text-align:center;">
                    <?php echo $this->_get_approval_status($approval_status, $event_attributes['event_a']); ?>
                    <?php echo $this->_display_payment_info($event_attributes['event_a']); ?>
                </div>

                <input type="hidden" style="display: none" value="" id="ccnum">

            <?php elseif(!$app_incomplete): ?>

                <?php if(isset($applicant_payment['fee_total'])):

                    if ($applicant_payment['fee_total'] > 0):

                         /*
                         * pay_policy
                         * 1 - block until approved
                         * 2 - may pay before approval
                         * 3 - must pay before approval
                         * 4 - no payment associated with form
                         * */

                        if ($event_attributes['event_a']['pay_policy'] != 4 && isset($applicant_payment['pay_options'])):

                            /*
                             * Display deposit override if allowed                             *
                             * */

                            $deposit_override_button = '';

                            if($applicant_payment['is_variable_deposit_payment'] == 0 && $applicant_payment['is_applic_fee'] == 1 && $applicant_payment['allow_deposit_override'] == 1 && !isset( $_GET['odp'])){
                                $deposit_override_button = ' <a class="btn-nav btn-blue" href="' . esc_url(sanitize_url($current_url.'/?payment&odp=deposit_override&pk='.sanitize_text_field($_GET['pk']).'&v='.$mt)) . '"\>or Pay Full Balance</a>';
                            }

                            //////////////////////////////
                            // payments due and info block
                            ?>

                            <div style="margin-top: 10px;">
                                <?php echo $this->_get_approval_status($approval_status, $event_attributes['event_a']); ?>

                                <div style="margin-bottom:5px; margin-top:5px;">
                                <?php echo "<h4>Grand Total: <strong>".$formData['currency_symbol'].number_format($applicant_payment['fee_global_total_sum_raw'],2)."</strong></h4>"; ?>
                                </div>

                                <div style="margin-bottom:5px; margin-top:5px;">
                                <?php echo "<h4>Payment Due: <strong>".$formData['currency_symbol'].number_format($applicant_payment['fee_total'],2)."</strong>{$deposit_override_button}</h4>"; ?>
                                </div>

                                <?php if($event_attributes['event_a']['pay_policy'] != 0): ?>
                                <div style="margin-bottom:5px; margin-top:5px;">
                                        <h4>Payment Deadline:

                                            <?php if(!empty($event_attributes['event_a']['pay_policy_custom'])): ?>
                                                <strong><?php echo $event_attributes['event_a']['pay_policy_custom']; ?></strong>

                                            <?php elseif($event_attributes['event_a']['pay_policy'] == 3): ?>
                                                <span class='red-alert'>With <?php echo $event_attributes['event_a']['application_label']; ?></span>

                                            <?php else: ?>
                                                <strong>
                                                    <?php
                                                    $date = $applicant_payment['payment_due_date'] == '0' ? 'not set' : date_format(date_create($applicant_payment['payment_due_date']), 'm/d/Y');
                                                    ?>
                                                    <?php echo $date; ?>
                                                </strong>
                                            <?php endif; ?>
                                        </h4>
                                </div>
                                <?php endif; ?>

                                <?php
                                $display_discount = false;
                                if($event_attributes['event_a']['discount_scope'] == 1) {
                                    $display_discount = true;
                                    $discount_scope = "{$event_attributes['event_a']['application_label']} Fee/Deposit";
                                    $discount_percentage = (int)$event_attributes['event_a']['discount_rate'];

                                }elseif($event_attributes['event_a']['discount_scope'] == 2) {
                                    $display_discount = true;
                                    $discount_scope = "{$event_attributes['event_a']['application_label']} Fee/Remaining Balance";
                                    $discount_percentage = (int)$event_attributes['event_a']['discount_rate'];

                                }elseif($event_attributes['event_a']['discount_scope'] == 3) {
                                    $display_discount = true;
                                    $discount_scope = "All Fees";
                                    $discount_percentage = (int)$event_attributes['event_a']['discount_rate'];
                                }

                                $discount_exp = $event_attributes['event_a']['discount_scope'] != 0 ? date_format(date_create($event_attributes['event_a']['discount_exp']), 'm/d/Y') . ' 11:59pm EST' : false;
                                ?>

                                <?php if($applicant_payment['show_discount_code_block']): ?>
                                    <div id="discount_code" style="clear:both">

                                        <?php if($applicant_payment['event_discount_id']): ?>
                                            <h4>Discount Code:
                                            <strong><?php echo $applicant_payment['discount_code']; ?></strong>
                                            (<?php echo $applicant_payment['discount_label']; ?>)
                                            <a style="font-size: 14px;" class="btn-nav btn-blue" target = "_self" href="<?php echo esc_url(sanitize_url($current_url . "/?payment&clear=dcode&pk=" . sanitize_text_field($_GET['pk']) . "&v=" . $mt)); ?>">clear</a>
                                            </h4>
                                        <?php else: ?>
                                            <h4>Do you have a Discount Code?</h4>
                                            <form class="" name="discount_code" action="<?php echo admin_url('admin-ajax.php'); ?>" id="clients-form" method="post" enctype="multipart/form-data">
                                                <input type="hidden" name="_csrf" value="">
                                                <input type="hidden" name="wvnmi_screen_name" value="payment">
                                                <?php wp_nonce_field('wvnmi_form_submission', 'wvnmi_verify_submission'); ?>
                                                <input type="hidden" name="action" value="wvnmi_form_submission">
                                                <input type="hidden" class="form-control" name="cart_code" value="<?php echo $applicant_payment['cart_code']; ?>">
                                                <input type="hidden" class="form-control" name="form_code" value="<?php echo $event_attributes['event_a']['form_code']; ?>">
                                                <input type="hidden" class="form-control" name="payment_processor" value="bypass">
                                                <input type="hidden" id="payment-client_profile_key" class="form-control" name="client_profile_key" value="<?php echo $event_attributes['client_a']['profile_key']; ?>">
                                                <input type="hidden" id="payment-applic_profile_key" class="form-control" name="profile_key" value="<?php echo esc_attr($_GET['pk']) ?>">
                                                <input class="form-control-inline" value="<?php echo isset( $_GET['dcode']) ? esc_attr($_GET['dcode']) : '' ?>" type="text" name="discount_code" style="width:150px">
                                                <button type="submit" id="submit-code" class="btn btn-discount-bottom">Apply Code</button>
                                            </form>
                                        <?php endif; ?>
                                    </div>
                                <?php endif; ?>

                                <?php if($applicant_payment['show_agent_code_block']): ?>
                                    <div id="agent_code" style="clear:both">

                                        <?php if($applicant_payment['event_agent_id'] > 0): ?>
                                            <h4><?php echo $applicant_payment['agent_code_label']; ?>:
                                            <strong><?php echo $applicant_payment['event_agent_code']; ?></strong>
                                            (<?php echo $applicant_payment['agent_full_name']; ?>)
                                            <a style="font-size: 14px;" class="btn-nav btn-blue" target = "_self" href="<?php echo esc_url(sanitize_url($current_url . "/?payment&clear=acode&pk=" . sanitize_text_field($_GET['pk']) . "&v=" . $mt)); ?>">clear</a>
                                            </h4>
                                        <?php else: ?>
                                            <h4>Do you have a <?php echo $applicant_payment['agent_code_label']; ?>?</h4>
                                            <form class="" name="agent_code" action="<?php echo admin_url('admin-ajax.php'); ?>" id="clients-form" method="post" enctype="multipart/form-data">
                                                <input type="hidden" name="_csrf" value="">
                                                <input type="hidden" name="wvnmi_screen_name" value="payment">
                                                <?php wp_nonce_field('wvnmi_form_submission', 'wvnmi_verify_submission'); ?>
                                                <input type="hidden" name="action" value="wvnmi_form_submission">
                                                <input type="hidden" class="form-control" name="cart_code" value="<?php echo $applicant_payment['cart_code']; ?>">
                                                <input type="hidden" class="form-control" name="form_code" value="<?php echo $event_attributes['event_a']['form_code']; ?>">
                                                <input type="hidden" class="form-control" name="payment_processor" value="bypass">
                                                <input type="hidden" id="payment-client_profile_key" class="form-control" name="client_profile_key" value="<?php echo $event_attributes['client_a']['profile_key']; ?>">
                                                <input type="hidden" id="payment-applic_profile_key" class="form-control" name="profile_key" value="<?php echo esc_attr($_GET['pk']) ?>">
                                                <input class="form-control-inline" value="" type="text" name="agent_code" style="width:150px">
                                                <button type="submit" id="submit-code" class="btn btn-discount-bottom">Apply Code</button>
                                            </form>
                                        <?php endif; ?>
                                    </div>
                                <?php endif; ?>

                                <?php if($display_discount): ?>
                                    <h4>Cart Discount: <span class='green-alert'><?php echo $discount_percentage; ?>% (<?php echo $discount_scope; ?>)</span></h4>
                                    <h4>If You Pay By: <span class='red-alert'><?php echo $discount_exp; ?></span></h4>
                                <?php endif; ?>

                                <div style="padding-top:10px;">
                                    <?php if(in_array('pp_b', $applicant_payment['pay_options'])): ?>
                                        <img style="width:275px height:48px;"
                                             src="<?php echo WAVENAMI_WORDPRESS_CLIENT_URL; ?>/front-end/assets/img/paypal-img1-footer-275.png"
                                             alt="paypal">
                                    <?php endif; ?>
                                </div>

                                <?php if ($applicant_payment['pay_by_check'] == 1): ?>

                                    <div class="cart_cc_box_header cart_row_header">
                                        <h3>Pay By Check</h3>

                                        <div style="text-align: right; flex: auto; margin-right: 10px;">
                                            <?php
                                            $wp_full_url = home_url(add_query_arg($_GET,$wp->request));
                                            if(stristr($wp_full_url,"&pbc=")){
                                                list($wp_full_url,) = explode("&pbc=",$wp_full_url,2);
                                            }
                                            $wp_full_url .= '&pbc=reset';
                                            ?>
                                            <a class="btn-nav btn-blue" target = "" href="<?php echo esc_url(sanitize_url($wp_full_url)); ?>">Pay by Credit Card</a>
                                        </div>
                                    </div>

                                    <div class="cart_box cart_row">
                                        <div class="col-100">
                                        <pre><h4><?php echo $event_attributes['event_a']['pay_check_details']; ?></h4></pre>
                                        </div>
                                    </div>

                                <?php elseif ($event_attributes['event_a']['sso_checkout'] == 1 &&
                                    $event_attributes['event_a']['rec_type'] == 3 &&
                                    $formData['login_field_data_a']): ?>

                                    <?php echo $this->_create_login_screen_fields($formData, '', 1, 'payment'); ?>

                                <?php
                                ////////////////////////////////////////////
                                // BEGIN - generate paypal button and encrypted form
                                elseif (in_array('pp_b', $applicant_payment['pay_options'])):

                                    if(!isset($_SESSION['api_token'])){
                                        echo "Missing session::api_token, please logout and login again";
                                    }

                                    $paypal_data = json_decode($this->_get_paypal_data($event_attributes,$applicant_payment['override_date_period']), true);

                                    if($paypal_data['encrypted_form_vals']): ?>

                                        <form action="https://www.paypal.com/cgi-bin/webscr" method="post">
                                            <input type="hidden" name="cmd" value="_s-xclick">
                                            <input type="hidden" name="encrypted"
                                                   value="<?php echo sanitize_text_field($paypal_data['encrypted_form_vals']); ?>">
                                            <div class="form-group">
                                                <button type="submit" class="btn btn-success"><i class="fa fa-lock" style="font-size:20px"></i> Pay using Paypal</button>
                                                <div id="submit-spinner" class="pull-left"></div>
                                            </div>
                                            <input type="hidden" style="display: none" value="" id="ccnum">
                                        </form>

                                        <?php //else: ?>
                                        <!--div class="well well-sm" style="margin-bottom:10px; margin-top:10px;"><i style="float:left; margin-right:10px; color:red;" class="fa fa-2x fa-exclamation-circle" aria-hidden="true"></i>
                                            Paypal not configured correctly.
                                        </div-->
                                    <?php endif; ?>

                                <?php elseif (in_array('stripe', $applicant_payment['pay_options'])): ?>

                                    <div class="cart_cc_box_header cart_row_header">
                                        <h3>Payment Details</h3>

                                        <div style="text-align: right; flex: auto; margin-right: 10px;">
                                            <?php if(!empty(trim($event_attributes['event_a']['pay_check_details']))): ?>
                                                <?php
                                                $wp_full_url = home_url(add_query_arg($_GET,$wp->request));
                                                if(stristr($wp_full_url,"&pbc=")){
                                                    list($wp_full_url,) = explode("&pbc=",$wp_full_url,2);
                                                }
                                                $wp_full_url .= '&pbc='.$applicant_payment['cart_code'];
                                                ?>
                                                <a class="btn-nav btn-blue" target = "" href="<?php echo esc_url(sanitize_url($wp_full_url)); ?>">Pay by Check</a>
                                            <?php endif; ?>

                                            <?php if((int)$applicant_payment['max_deposit'] > 0): ?>
                                                <a class='btn-nav btn-blue' id='var_deposit_button'>Split Payment</a>

                                                    <?php if((int)$applicant_payment['is_variable_deposit_payment'] == 1): ?>
                                                        <div id="var_deposit_form_block" style="margin-top:10px;" disabled="disabled">
                                                        <form class="" id="var_deposit_cancel" name="var_deposit_cancel" action="<?php echo admin_url('admin-ajax.php'); ?>" id="clients-form" method="post" enctype="multipart/form-data">
                                                            <input type="hidden" name="_csrf" value="">
                                                            <input type="hidden" name="wvnmi_screen_name" value="payment">
                                                            <?php wp_nonce_field('wvnmi_form_submission', 'wvnmi_verify_submission'); ?>
                                                            <input type="hidden" name="action" value="wvnmi_form_submission">
                                                            <input type="hidden" class="form-control" name="cart_code" value="<?php echo $applicant_payment['cart_code']; ?>">
                                                            <input type="hidden" class="form-control" name="form_code" value="<?php echo $event_attributes['event_a']['form_code']; ?>">
                                                            <input type="hidden" class="form-control" name="payment_processor" value="bypass">
                                                            <input type="hidden" id="payment-client_profile_key" class="form-control" name="client_profile_key" value="<?php echo $event_attributes['client_a']['profile_key']; ?>">
                                                            <input type="hidden" id="payment-applic_profile_key" class="form-control" name="profile_key" value="<?php echo esc_attr($_GET['pk']) ?>">
                                                            <input type="hidden" id="var_deposit_cancel" name="var_deposit_cancel" value="1">
                                                            <input disabled="disabled" type="text"  id="var_deposit_amount" class="form-control-inline" value="<?php echo sanitize_text_field($formData['currency_symbol'].number_format($applicant_payment['max_deposit'],2)) ?>" name="var_deposit_amount" style="width:100px">
                                                            <button type="submit" id="var_deposit_submit" class="btn btn-deposit-cancel">Cancel Deposit</button>
                                                        </form>
                                                        <h5>Click Cancel Deposit to pay the full amount due.</h5>
                                                    <?php else: ?>
                                                        <div id="var_deposit_form_block" style="margin-top:10px; display:none">
                                                        <form class="" id="var_deposit_form" name="var_deposit_form" action="<?php echo admin_url('admin-ajax.php'); ?>" id="clients-form" method="post" enctype="multipart/form-data">
                                                            <input type="hidden" name="_csrf" value="">
                                                            <input type="hidden" name="wvnmi_screen_name" value="payment">
                                                            <?php wp_nonce_field('wvnmi_form_submission', 'wvnmi_verify_submission'); ?>
                                                            <input type="hidden" name="action" value="wvnmi_form_submission">
                                                            <input type="hidden" class="form-control" name="cart_code" value="<?php echo $applicant_payment['cart_code']; ?>">
                                                            <input type="hidden" class="form-control" name="form_code" value="<?php echo $event_attributes['event_a']['form_code']; ?>">
                                                            <input type="hidden" class="form-control" name="payment_processor" value="bypass">
                                                            <input type="hidden" id="payment-client_profile_key" class="form-control" name="client_profile_key" value="<?php echo $event_attributes['client_a']['profile_key']; ?>">
                                                            <input type="hidden" id="payment-applic_profile_key" class="form-control" name="profile_key" value="<?php echo esc_attr($_GET['pk']) ?>">
                                                            <input type="hidden" id="var_deposit_maximum" name="maximum" value="<?php echo sanitize_text_field($applicant_payment['max_deposit']) ?>">
                                                            <input type="text"  id="var_deposit_amount" class="form-control-inline" value="<?php echo sanitize_text_field($applicant_payment['max_deposit']) ?>" name="var_deposit_amount" style="width:100px">
                                                            <button type="submit" id="var_deposit_submit" class="btn btn-discount-bottom">Set Amount</button>
                                                        </form>
                                                        <h5>Enter a different amount and click <strong>Set Amount</strong>.<br>Any applicable fees will be added.</h5>
                                                    <?php endif; ?>
                                                    </div>

                                                <script type="text/javascript">
                                                    $(document).ready(function () {
                                                        // initialize jQuery stuff after page load
                                                        jQuery(function(){
                                                            $('#var_deposit_form').submit (function() {
                                                                var deposit_max = parseInt($('#var_deposit_maximum').val());
                                                                var deposit_amount = parseInt($('#var_deposit_amount').val());
                                                                if(deposit_amount < deposit_max){
                                                                    return true;
                                                                }else{
                                                                    alert('Amount must be LESS than: ' + deposit_max);
                                                                    return false;
                                                                }
                                                            });
                                                        });
                                                    });
                                                </script>
                                            <?php endif; ?>
                                        </div>
                                    </div>

                                    <?php if($applicant_payment['cc_error_message']): ?>
                                        <div class="cart_cc_box_error cart_row">
                                            Last Payment Notice<br>
                                            <?php echo $applicant_payment['cc_error_message']; ?>
                                        </div>
                                    <?php endif; ?>

                                    <div class="cart_box cart_row">
                                        <div class="col-100">

                                            <?php if(empty($applicant_payment['strip_profile_a']['stripe_cust_id'])): ?>

                                            <script type="text/javascript">Stripe.setPublishableKey("<?php echo $applicant_payment['platform_public_key']; ?>");</script>

                                            <form data-parsley-errors-messages-disabled="" id="stripe-payment-form" class="form-horizontal" name="step-5"
                                                  action="<?php echo admin_url('admin-ajax.php'); ?>" method="post"
                                                  enctype="multipart/form-data">

                                                <?php endif; ?>

                                                <input type="hidden" name="_csrf" value="">
                                                <input type="hidden" name="wvnmi_screen_name" value="payment">
                                                <?php wp_nonce_field('wvnmi_form_submission', 'wvnmi_verify_submission'); ?>
                                                <input type="hidden" name="action" value="wvnmi_form_submission">

                                                <div class="cart_row">
                                                    <div class="col-50">
                                                        <div style="margin-top:35px;"><h4>Billing Address</h4></div>

                                                        <div class="cart_row">
                                                            <div class="col-inner-50">
                                                                <label class="control-label-cart" for="fname">First Name</label>
                                                                <input value="<?php echo $applicant_payment['client_a']['first_name']; ?>" required="" type="text" id="fname" name="billingFirstName" placeholder="" class="form-control">
                                                            </div>
                                                            <div class="col-inner-50">
                                                                <label class="control-label-cart" for="lname">Last Name</label>
                                                                <input value="<?php echo $applicant_payment['client_a']['last_name']; ?>" required="" type="text" id="lname" name="billingLastName" placeholder="" class="form-control">
                                                            </div>
                                                        </div>

                                                        <label class="control-label-cart" for="adr">Street Address</label>
                                                        <input required="" type="text" id="adr" name="billingAddress" placeholder="" class="form-control">

                                                        <label class="control-label-cart" for="city">City</label>
                                                        <input required="" type="text" id="city" name="billingCity" placeholder="" class="form-control">

                                                        <label class="control-label-cart" for="state">State/Province</label>
                                                        <input required="" type="text" id="state" name="billingState" placeholder="" class="form-control">

                                                        <div class="cart_row" style="padding-left:0px; padding-right:15px">
                                                            <div class="col-50">
                                                                <label class="control-label-cart" for="zip">Zip/Postal Code</label>
                                                                <input required="" style="width:120px" type="text" id="zip" name="billingZip" placeholder="" class="form-control">
                                                            </div>

                                                            <div class="col-50">
                                                                <label class="control-label-cart" for="country">Country</label>
                                                                <select name="billingCountry" id="country-alpha-2" required="" class="form-control" style="width:160px">
                                                                    <option value="">Select</option>
                                                                </select>
                                                            </div>
                                                        </div>
                                                    </div>

                                                    <div class="col-50">
                                                        <div class="icon-container">
                                                            <img class="" style="width:224px"
                                                                 src="<?= WAVENAMI_WORDPRESS_CLIENT_URL; ?>/front-end/assets/img/stripe1.png"
                                                                 alt="Payments through Stripe">
                                                        </div>

                                                        <h4>Payment Method</h4>

                                                        <?php if(!empty($applicant_payment['strip_profile_a']['stripe_cust_id'])): ?>
                                                            <div class="cart_row">
                                                                <div class="col-75" style="margin-bottom:20px;">
                                                                    <h6>Your previously saved credit card profile is listed below. To
                                                                        change to another payment method, click the <strong>Use Another Card</strong> button.</h6>
                                                                    <label class="control-label-cart" for="">Saved Credit Card
                                                                        <a style="font-size: 12px;" class="btn-nav btn-blue" target = "_self" href="<?php echo esc_url(sanitize_url( $current_url . "/?payment&clear_cc=1&pk=" . sanitize_text_field($_GET['pk']) . "&v=" . $mt)); ?>">Use Another Card</a>
                                                                    </label>
                                                                    <input id="last4" value="xxxx-xxxx-xxxx-<?php echo $applicant_payment['strip_profile_a']['stripe_cc_last4']; ?>" disabled="disabled" type="text" class="form-control">

                                                                    <label class="control-label-cart" for="">Exp</label>
                                                                    <input id="exp" style="width:75px;" value="<?php echo $applicant_payment['strip_profile_a']['stripe_cc_exp']; ?>" disabled="disabled" type="text" class="form-control">
                                                                </div>
                                                            </div>
                                                            <div class="cart_row">
                                                                <div class="checkout-buttons" style="">
                                                                    <div class="" style="margin-bottom:0px; display:block;">
                                                                        <h3>Pay: <?php echo "<strong>".$formData['currency_symbol'].number_format($applicant_payment['fee_total'],2)."</strong>"; ?></h3>
                                                                    </div>
                                                                    <button style="color: #2c2c2c;" type="submit" id="submit-stripe" class="btn btn-success">
                                                                        <i style="margin-right:4px; color:gold" class="fa fa-lg fa-lock" aria-hidden="true"></i> <?php echo $this->_button_label_swap('submit_payment'); ?>
                                                                    </button>
                                                                </div>
                                                            </div>
                                                        <?php else: ?>

                                                            <label class="control-label-cart" for="cname">Name on Card</label>
                                                            <input value="<?php echo $applicant_payment['client_a']['first_name']; ?> <?php echo $applicant_payment['client_a']['last_name']; ?>" required="" type="text" id="cname" name="billingCompany" placeholder="" class="form-control">

                                                            <label style="display: inline-block;" class="control-label-cart" for="ccnum">Credit Card Number</label>

                                                            <input
                                                                style="display: inline-block;"
                                                                type="tel"
                                                                id="ccnum"
                                                                data-exception="ccnum"
                                                                name="cardNumber"
                                                                class="card-number form-control masked"
                                                                placeholder="15 or 16 digits"
                                                                pattern="[3-6][0-9 ]{15,18}"
                                                                title="15 or 16-digit number" >

                                                            <!-- span style="display: inline;" id="cclabel"></span -->

                                                            <div class="cart_row" style="margin-left: 10px;">
                                                                <div class="col-33">
                                                                    <label class="control-label-cart" for="expmonth">Exp Month</label>
                                                                    <select style="width: 110px;" type="text" id="expmonth" class="card-expiry-month form-control">
                                                                        <option value="01">Jan (01)</option>
                                                                        <option value="02">Feb (02)</option>
                                                                        <option value="03">Mar (03)</option>
                                                                        <option value="04">Apr (04)</option>
                                                                        <option value="05">May (05)</option>
                                                                        <option value="06">June (06)</option>
                                                                        <option value="07">July (07)</option>
                                                                        <option value="08">Aug (08)</option>
                                                                        <option value="09">Sept (09)</option>
                                                                        <option value="10">Oct (10)</option>
                                                                        <option value="11">Nov (11)</option>
                                                                        <option value="12">Dec (12)</option>
                                                                    </select>
                                                                </div>

                                                                <div class="col-33">
                                                                    <label class="control-label-cart" for="expyear">Exp Year</label>
                                                                    <select style="width: 85px;" type="text" id="expyear" class="card-expiry-year form-control">
                                                                        <option value="22">2022</option>
                                                                        <option value="23">2023</option>
                                                                        <option value="24">2024</option>
                                                                        <option value="25">2025</option>
                                                                        <option value="26">2026</option>
                                                                        <option value="27">2027</option>
                                                                        <option value="28">2028</option>
                                                                        <option value="29">2029</option>
                                                                        <option value="30">2030</option>
                                                                        <option value="31">2031</option>
                                                                        <option value="32">2032</option>
                                                                    </select>
                                                                </div>
                                                                <div class="col-33">
                                                                    <label class="control-label-cart" for="cvc">CCV</label>
                                                                    <input style="width:50px" size="4" required="" type="text" id="cvc" placeholder="" class="card-cvc form-control">
                                                                </div>
                                                            </div>

                                                            <div class="cart_row">
                                                                <div class="checkout-buttons" style="">
                                                                    <div class="" style="margin-bottom:0px; display:block;">
                                                                        <h3>Pay: <?php echo "<strong>".$formData['currency_symbol'].number_format($applicant_payment['fee_total'],2)."</strong>"; ?></h3>
                                                                    </div>

                                                                    <?php if($applicant_payment['strip_profile_a']['profile_saved_enabled'] == 1): ?>

                                                                        <div class="" style="margin-bottom:10px; display:block;">
                                                                            <input id="save_my_stripe_profile" class="client_type" type="checkbox" name="save_my_stripe_profile" value="1">
                                                                            <label style="font-size: 14px;" for="save_my_stripe_profile">Save payment method for later</label>
                                                                        </div>

                                                                    <?php endif; ?>

                                                                    <button style="color: #2c2c2c;" type="submit" id="submit-stripe" class="btn btn-success">
                                                                        <i style="margin-right:4px; color:gold" class="fa fa-lg fa-lock" aria-hidden="true"></i> <?php echo $this->_button_label_swap('submit_payment'); ?>
                                                                    </button>
                                                                </div>
                                                            </div>

                                                            <div class="cart_row">
                                                                <div id="payment-errors" class="" style="margin-top:10px;"></div>
                                                            </div>
                                                        <?php endif; ?>
                                                    </div>
                                                </div>

                                                <div class="cart_left">

                                                    <?php if(!empty($applicant_payment['strip_profile_a']['stripe_cust_id'])): ?>
                                                        <input type="hidden" class="form-control" id="use_stripe_profile" name="use_stripe_profile" value="1">
                                                    <?php else: ?>
                                                        <input type="hidden" class="form-control" id="use_stripe_profile" name="use_stripe_profile" value="0">
                                                    <?php endif; ?>

                                                    <?php if(isset($_GET['odp'])): ?>
                                                        <?php if($_GET['odp'] == 'deposit_override'): ?>
                                                            <input type="hidden" class="form-control" id="deposit_override_pay_full" name="deposit_override_pay_full" value="1">
                                                        <?php endif; ?>
                                                    <?php endif; ?>

                                                    <input type="hidden" id="cart_code" class="form-control" name="cart_code" value="<?php echo $applicant_payment['cart_code']; ?>">

                                                    <input type="hidden" id="payment-client_profile_key" class="form-control" name="client_profile_key" value="<?php echo $event_attributes['client_a']['profile_key']; ?>">

                                                    <input type="hidden" id="payment-applic_profile_key" class="form-control" name="profile_key" value="<?php echo esc_attr($_GET['pk']); ?>">

                                                    <input type="hidden" id="payment-apply_step5" class="form-control" name="apply_step5" value="1">

                                                    <input type="hidden" id="payment-processor" class="form-control" name="payment_processor" value="stripe">

                                                    <input type="hidden" id="payment-event-code" class="form-control" name="form_code" value="<?php echo $event_attributes['event_a']['form_code']; ?>">

                                                    <input type="hidden" id="payment-event-code" class="form-control" name="amount" value="<?php echo $applicant_payment['fee_total']; ?>">
                                                </div>
                                            </form>
                                        </div>
                                    </div>

                                <?php // BASYS SUPPORT ?>
                                <?php elseif (in_array('basys', $applicant_payment['pay_options'])): ?>

                                    <div class="cart_cc_box_header cart_row_header">
                                        <h3>Payment Details</h3>

                                        <div style="text-align: right; flex: auto; margin-right: 10px;">
                                            <?php if(!empty(trim($event_attributes['event_a']['pay_check_details']))): ?>
                                                <?php
                                                $wp_full_url = home_url(add_query_arg($_GET,$wp->request));
                                                if(stristr($wp_full_url,"&pbc=")){
                                                    list($wp_full_url,) = explode("&pbc=",$wp_full_url,2);
                                                }
                                                $wp_full_url .= '&pbc='.$applicant_payment['cart_code'];
                                                ?>
                                                <a class="btn-nav btn-blue" target = "" href="<?php echo esc_url(sanitize_url($wp_full_url)); ?>">Pay by Check</a>
                                            <?php endif; ?>

                                            <?php if((int)$applicant_payment['max_deposit'] > 0): ?>
                                                <a class='btn-nav btn-blue' id='var_deposit_button'>Split Payment</a>

                                                    <?php if((int)$applicant_payment['is_variable_deposit_payment'] == 1): ?>
                                                        <div id="var_deposit_form_block" style="margin-top:10px;" disabled="disabled">
                                                        <form class="" id="var_deposit_cancel" name="var_deposit_cancel" action="<?php echo admin_url('admin-ajax.php'); ?>" id="clients-form" method="post" enctype="multipart/form-data">
                                                            <input type="hidden" name="_csrf" value="">
                                                            <input type="hidden" name="wvnmi_screen_name" value="payment">
                                                            <?php wp_nonce_field('wvnmi_form_submission', 'wvnmi_verify_submission'); ?>
                                                            <input type="hidden" name="action" value="wvnmi_form_submission">
                                                            <input type="hidden" class="form-control" name="cart_code" value="<?php echo $applicant_payment['cart_code']; ?>">
                                                            <input type="hidden" class="form-control" name="form_code" value="<?php echo $event_attributes['event_a']['form_code']; ?>">
                                                            <input type="hidden" class="form-control" name="payment_processor" value="bypass">
                                                            <input type="hidden" id="payment-client_profile_key" class="form-control" name="client_profile_key" value="<?php echo $event_attributes['client_a']['profile_key']; ?>">
                                                            <input type="hidden" id="payment-applic_profile_key" class="form-control" name="profile_key" value="<?php echo esc_attr($_GET['pk']) ?>">
                                                            <input type="hidden" id="var_deposit_cancel" name="var_deposit_cancel" value="1">
                                                            <input disabled="disabled" type="text"  id="var_deposit_amount" class="form-control-inline" value="<?php echo sanitize_text_field($formData['currency_symbol'].number_format($applicant_payment['max_deposit'],2)) ?>" name="var_deposit_amount" style="width:100px">
                                                            <button type="submit" id="var_deposit_submit" class="btn btn-deposit-cancel">Cancel Deposit</button>
                                                        </form>
                                                        <h5>Click Cancel Deposit to pay the full amount due.</h5>
                                                    <?php else: ?>
                                                        <div id="var_deposit_form_block" style="margin-top:10px; display:none">
                                                        <form class="" id="var_deposit_form" name="var_deposit_form" action="<?php echo admin_url('admin-ajax.php'); ?>" id="clients-form" method="post" enctype="multipart/form-data">
                                                            <input type="hidden" name="_csrf" value="">
                                                            <input type="hidden" name="wvnmi_screen_name" value="payment">
                                                            <?php wp_nonce_field('wvnmi_form_submission', 'wvnmi_verify_submission'); ?>
                                                            <input type="hidden" name="action" value="wvnmi_form_submission">
                                                            <input type="hidden" class="form-control" name="cart_code" value="<?php echo $applicant_payment['cart_code']; ?>">
                                                            <input type="hidden" class="form-control" name="form_code" value="<?php echo $event_attributes['event_a']['form_code']; ?>">
                                                            <input type="hidden" class="form-control" name="payment_processor" value="bypass">
                                                            <input type="hidden" id="payment-client_profile_key" class="form-control" name="client_profile_key" value="<?php echo $event_attributes['client_a']['profile_key']; ?>">
                                                            <input type="hidden" id="payment-applic_profile_key" class="form-control" name="profile_key" value="<?php echo esc_attr($_GET['pk']) ?>">
                                                            <input type="hidden" id="var_deposit_maximum" name="maximum" value="<?php echo sanitize_text_field($applicant_payment['max_deposit']) ?>">
                                                            <input type="text"  id="var_deposit_amount" class="form-control-inline" value="<?php echo sanitize_text_field($applicant_payment['max_deposit']) ?>" name="var_deposit_amount" style="width:100px">
                                                            <button type="submit" id="var_deposit_submit" class="btn btn-discount-bottom">Set Amount</button>
                                                        </form>
                                                        <h5>Enter a different amount and click <strong>Set Amount</strong>.<br>Any applicable fees will be added.</h5>
                                                    <?php endif; ?>
                                                    </div>

                                                <script type="text/javascript">
                                                    $(document).ready(function () {
                                                        // initialize jQuery stuff after page load
                                                        jQuery(function(){
                                                            $('#var_deposit_form').submit (function() {
                                                                var deposit_max = parseInt($('#var_deposit_maximum').val());
                                                                var deposit_amount = parseInt($('#var_deposit_amount').val());
                                                                if(deposit_amount < deposit_max){
                                                                    return true;
                                                                }else{
                                                                    alert('Amount must be LESS than: ' + deposit_max);
                                                                    return false;
                                                                }
                                                            });
                                                        });
                                                    });
                                                </script>
                                            <?php endif; ?>
                                        </div>
                                    </div>

                                    <?php if($applicant_payment['cc_error_message']): ?>
                                        <div class="cart_cc_box_error cart_row">
                                            Last Payment Notice<br>
                                            <?php echo $applicant_payment['cc_error_message']; ?>
                                        </div>
                                    <?php endif; ?>

                                    <div class="cart_box cart_row">
                                        <div class="col-100">

                                            <form data-parsley-errors-messages-disabled="" id="basys-payment-form" class="form-horizontal" name="step-5"
                                                  action="<?php echo admin_url('admin-ajax.php'); ?>" method="post"
                                                  enctype="multipart/form-data">

                                                <input type="hidden" name="_csrf" value="">
                                                <input type="hidden" name="wvnmi_screen_name" value="payment">
                                                <?php wp_nonce_field('wvnmi_form_submission', 'wvnmi_verify_submission'); ?>
                                                <input type="hidden" name="action" value="wvnmi_form_submission">

                                                <div class="cart_row">
                                                    <div class="col-50">
                                                        <div style="margin-top:35px;"><h4>Billing Address</h4></div>

                                                        <div class="cart_row">
                                                            <div class="col-inner-50">
                                                                <label class="control-label-cart" for="fname">First Name</label>
                                                                <input value="<?php echo $applicant_payment['client_a']['first_name']; ?>" required="" type="text" id="fname" name="billingFirstName" placeholder="" class="form-control auto-save">
                                                            </div>
                                                            <div class="col-inner-50">
                                                                <label class="control-label-cart" for="lname">Last Name</label>
                                                                <input value="<?php echo $applicant_payment['client_a']['last_name']; ?>" required="" type="text" id="lname" name="billingLastName" placeholder="" class="form-control auto-save">
                                                            </div>
                                                        </div>

                                                        <label class="control-label-cart" for="adr">Street Address</label>
                                                        <input required="" type="text" id="adr" name="billingAddress" placeholder="" class="form-control auto-save">

                                                        <label class="control-label-cart" for="city">City</label>
                                                        <input required="" type="text" id="city" name="billingCity" placeholder="" class="form-control auto-save">

                                                        <label class="control-label-cart" for="state">State/Province</label>
                                                        <input required="" type="text" id="state" name="billingState" placeholder="" class="form-control auto-save">

                                                        <div class="cart_row" style="padding-left:0px; padding-right:15px">
                                                            <div class="col-50">
                                                                <label class="control-label-cart" for="zip">Zip/Postal Code</label>
                                                                <input required="" style="width:120px" type="text" id="zip" name="billingZip" placeholder="" class="form-control auto-save">
                                                            </div>

                                                            <div class="col-50">
                                                                <label class="control-label-cart" for="country">Country</label>
                                                                <select name="billingCountry" id="country-alpha-2" required="" class="form-control auto-save" style="width:160px">
                                                                    <option value="">Select</option>
                                                                    <option value="US">United States</option>
                                                                </select>
                                                            </div>
                                                        </div>
                                                    </div>

                                                    <div class="col-50">
                                                        <div class="icon-container">
                                                            <img class="" style="width:224px"
                                                                 src="https://basyspro.com/wp-content/uploads/2020/10/iQ-Pro-Login.jpg"
                                                                 alt="BaSYS Processing">
                                                        </div>

                                                        <h4>Payment Method</h4>

                                                        <?php if(!empty($applicant_payment['strip_profile_a']['basys_cust_id'])): ?>
                                                            <div class="cart_row">
                                                                <div class="col-75" style="margin-bottom:20px;">
                                                                    <h6>Your previously saved credit card profile is listed below. To
                                                                        change to another payment method, click the <strong>Use Another Card</strong> button.</h6>
                                                                    <label class="control-label-cart" for="">Saved Credit Card
                                                                        <a style="font-size: 12px;" class="btn-nav btn-blue" target = "_self" href="<?php echo esc_url(sanitize_url( $current_url . "/?payment&clear_cc=1&pk=" . sanitize_text_field($_GET['pk']) . "&v=" . $mt)); ?>">Use Another Card</a>
                                                                    </label>
                                                                    <input id="last4" value="xxxx-xxxx-xxxx-<?php echo $applicant_payment['strip_profile_a']['basys_cc_last4']; ?>" disabled="disabled" type="text" class="form-control">

                                                                    <label class="control-label-cart" for="">Exp</label>
                                                                    <input id="exp" style="width:75px;" value="<?php echo $applicant_payment['strip_profile_a']['basys_cc_exp']; ?>" disabled="disabled" type="text" class="form-control">
                                                                </div>
                                                            </div>
                                                            <div class="cart_row">
                                                                <div class="checkout-buttons" style="">
                                                                    <div class="" style="margin-bottom:0px; display:block;">
                                                                        <h3>Pay: <?php echo "<strong>".$formData['currency_symbol'].number_format($applicant_payment['fee_total'],2)."</strong>"; ?></h3>
                                                                    </div>
                                                                    <button style="color: #2c2c2c;" type="submit" id="submit-basys" class="btn btn-success">
                                                                        <i style="margin-right:4px; color:gold" class="fa fa-lg fa-lock" aria-hidden="true"></i> <?php echo $this->_button_label_swap('submit_payment'); ?>
                                                                    </button>
                                                                </div>
                                                            </div>
                                                        <?php else: ?>

                                                            <label class="control-label-cart" for="cname">Name on Card</label>
                                                            <input value="<?php echo $applicant_payment['client_a']['first_name']; ?> <?php echo $applicant_payment['client_a']['last_name']; ?>" required="" type="text" id="cname" name="billingCompany" placeholder="" class="form-control">

                                                            <label style="display: inline-block;" class="control-label-cart" for="ccnum">Credit Card Number</label>

                                                            <input
                                                                style="display: inline-block;"
                                                                type="tel"
                                                                id="ccnum"
                                                                data-exception="ccnum"
                                                                name="cardNumber"
                                                                class="card-number form-control masked"
                                                                placeholder="15 or 16 digits"
                                                                pattern="[3-6][0-9 ]{15,18}"
                                                                title="15 or 16-digit number" >

                                                            <!-- span style="display: inline;" id="cclabel"></span -->

                                                            <div class="cart_row" style="margin-left: 10px;">
                                                                <div class="col-33">
                                                                    <label class="control-label-cart" for="expmonth">Exp Month</label>
                                                                    <select style="width: 110px;" type="text" name="expmonth" id="expmonth" class="card-expiry-month form-control">
                                                                        <option value="01">Jan (01)</option>
                                                                        <option value="02">Feb (02)</option>
                                                                        <option value="03">Mar (03)</option>
                                                                        <option value="04">Apr (04)</option>
                                                                        <option value="05">May (05)</option>
                                                                        <option value="06">June (06)</option>
                                                                        <option value="07">July (07)</option>
                                                                        <option value="08">Aug (08)</option>
                                                                        <option value="09">Sept (09)</option>
                                                                        <option value="10">Oct (10)</option>
                                                                        <option value="11">Nov (11)</option>
                                                                        <option value="12">Dec (12)</option>
                                                                    </select>
                                                                </div>

                                                                <div class="col-33">
                                                                    <label class="control-label-cart" for="expyear">Exp Year</label>
                                                                    <select style="width: 85px;" type="text" name="expyear" id="expyear" class="card-expiry-year form-control">
                                                                        <option value="22">2022</option>
                                                                        <option value="23">2023</option>
                                                                        <option value="24">2024</option>
                                                                        <option value="25">2025</option>
                                                                        <option value="26">2026</option>
                                                                        <option value="27">2027</option>
                                                                        <option value="28">2028</option>
                                                                        <option value="29">2029</option>
                                                                        <option value="30">2030</option>
                                                                        <option value="31">2031</option>
                                                                        <option value="32">2032</option>
                                                                    </select>
                                                                </div>

                                                                <div class="col-33">
                                                                    <label class="control-label-cart" for="cvc">CCV</label>
                                                                    <input style="width:50px" size="4" required="" type="text" name="cvc" id="cvc" placeholder="" class="card-cvc form-control">
                                                                </div>
                                                            </div>

                                                            <div class="cart_row">
                                                                <div class="checkout-buttons" style="">
                                                                    <div class="" style="margin-bottom:0px; display:block;">
                                                                        <h3>Pay: <?php echo "<strong>".$formData['currency_symbol'].number_format($applicant_payment['fee_total'],2)."</strong>"; ?></h3>
                                                                    </div>

                                                                    <?php if($applicant_payment['strip_profile_a']['profile_saved_enabled'] == 1): ?>

                                                                        <div class="" style="margin-bottom:10px; display:block;">
                                                                            <input id="save_my_basys_profile" class="client_type" type="checkbox" name="save_my_basys_profile" value="1">
                                                                            <label style="font-size: 14px;" for="save_my_basys_profile">Save payment method for later</label>
                                                                        </div>

                                                                    <?php endif; ?>

                                                                    <button style="color: #2c2c2c;" type="submit" id="submit-basys" class="btn btn-success">
                                                                        <i style="margin-right:4px; color:gold" class="fa fa-lg fa-lock" aria-hidden="true"></i> <?php echo $this->_button_label_swap('submit_payment'); ?>
                                                                    </button>
                                                                </div>
                                                            </div>

                                                            <div class="cart_row">
                                                                <div id="payment-errors" class="" style="margin-top:10px;"></div>
                                                            </div>
                                                        <?php endif; ?>
                                                    </div>
                                                </div>

                                                <div class="cart_left">

                                                    <?php if(!empty($applicant_payment['strip_profile_a']['basys_cust_id'])): ?>
                                                        <input type="hidden" class="form-control" id="use_basys_profile" name="use_basys_profile" value="1">
                                                    <?php else: ?>
                                                        <input type="hidden" class="form-control" id="use_basys_profile" name="use_basys_profile" value="0">
                                                    <?php endif; ?>

                                                    <?php if(isset($_GET['odp'])): ?>
                                                        <?php if($_GET['odp'] == 'deposit_override'): ?>
                                                            <input type="hidden" class="form-control" id="deposit_override_pay_full" name="deposit_override_pay_full" value="1">
                                                        <?php endif; ?>
                                                    <?php endif; ?>

                                                    <input type="hidden" id="cart_code" class="form-control" name="cart_code" value="<?php echo $applicant_payment['cart_code']; ?>">

                                                    <input type="hidden" id="payment-client_profile_key" class="form-control" name="client_profile_key" value="<?php echo $event_attributes['client_a']['profile_key']; ?>">

                                                    <input type="hidden" id="payment-applic_profile_key" class="form-control" name="profile_key" value="<?php echo esc_attr($_GET['pk']); ?>">

                                                    <input type="hidden" id="payment-apply_step5" class="form-control" name="apply_step5" value="1">

                                                    <input type="hidden" id="payment-processor" class="form-control" name="payment_processor" value="basys">

                                                    <input type="hidden" id="payment-event-code" class="form-control" name="form_code" value="<?php echo $event_attributes['event_a']['form_code']; ?>">

                                                    <input type="hidden" id="payment-event-code" class="form-control" name="amount" value="<?php echo $applicant_payment['fee_total']; ?>">
                                                </div>
                                            </form>
                                        </div>
                                    </div>

                                <?php endif;
                                // END - generate paypal button and encrypted form
                                //////////////////////////////////
                                ?>

                                <?php echo $this->_display_payment_info($event_attributes['event_a']); ?>
                            </div><!-- mark1 -->
                        <?php
                        endif;
                    else:
                        ?>
                        <div style="margin-top: 10px;">
                            <?php echo $this->_get_approval_status($approval_status, $event_attributes['event_a']); ?>

                            <?php if(!empty($event_attributes['event_a']['pay_policy_custom'])): ?>
                                <div style="margin-bottom:5px; margin-top:5px;">
                                    <h4><?php echo $event_attributes['event_a']['pay_policy_custom']; ?></h4>
                                </div>
                            <?php else: ?>
                                <?php echo $this->_get_notice_by_pay_policy($event_attributes['event_a']['pay_policy']); ?>
                            <?php endif; ?>

                            <?php echo $this->_display_payment_info($event_attributes['event_a']); ?>
                        </div>
                    <?php
                    endif;
                endif;
            endif;
        endif;

        return ($form . $this->_generate_payment_screen_field(ob_get_clean(), $this->event_attributes));
    }

    /**
     * @param $formData
     * @param $form
     * @return string
     */
    private function _create_signature_screen_fields($formData, $form)
    {
        $attributes = json_decode($this->event_attributes, true);
        $return_url = $this->_get_skip_url(['amenities' => '', 'pk' => sanitize_text_field($_GET['pk'])]);

        ob_start();

        ?>
        <div id="signature-pad" class="m-signature-pad">
            <div class="m-signature-pad--body">
                <canvas width="658" height="298" style="touch-action: none;">
            </div>
            <div class="m-signature-pad--footer">
                <div class="description">Use mouse or finger to sign above</div>
                <div class="left">
                    <button type="button" class="btn btn-success" data-action="clear"><?php echo $this->_button_label_swap('clear'); ?></button>
                </div>
                <div class="right">
                    <button type="button" class="btn btn-success" data-action="save-svg"> <?php echo $this->_button_label_swap('signature_save'); ?></button>
                </div>
            </div>
        </div>
        <script type="text/javascript">
            var wrapper = document.getElementById("signature-pad"),
                clearButton = wrapper.querySelector("[data-action=clear]"),
                savePNGButton = wrapper.querySelector("[data-action=save-png]"),
                saveSVGButton = wrapper.querySelector("[data-action=save-svg]"),
                canvas = wrapper.querySelector("canvas"),
                signaturePad;

            // Adjust canvas coordinate space taking into account pixel ratio,
            // to make it look crisp on mobile devices.
            // This also causes canvas to be cleared.
            function resizeCanvas() {
                // When zoomed out to less than 100%, for some very strange reason,
                // some browsers report devicePixelRatio as less than 1
                // and only part of the canvas is cleared then.
                var ratio =  Math.max(window.devicePixelRatio || 1, 1);
                canvas.width = canvas.offsetWidth * ratio;
                canvas.height = canvas.offsetHeight * ratio;
                canvas.getContext("2d").scale(ratio, ratio);
            }

            window.onresize = resizeCanvas;
            resizeCanvas();

            signaturePad = new SignaturePad(canvas);

            clearButton.addEventListener("click", function (event) {
                signaturePad.clear();
            });

            saveSVGButton.addEventListener("click", function (event) {
                if (signaturePad.isEmpty()) {
                    alert("Please provide signature first.");
                } else {
                    // window.open(signaturePad.toDataURL('image/svg+xml'));
                    var sig = {};
                    sig.svg_xml = signaturePad.toDataURL('image/svg+xml');
                    sig.svg = signaturePad.toDataURL('image/svg');
                    // console.log(sig);
                    jQuery.ajax({
                        url: "<?php echo admin_url('admin-ajax.php'); ?>",
                        type: "POST",
                        cache: false,
                        dataType: "json",
                        data: {svg_xml: sig.svg_xml, svg: sig.svg, wvnmi_screen_name: "signature", action: "wvnmi_signature_submission", wvnmi_verify_submission: "<?php echo wp_create_nonce("wvnmi_signature_submission");  ?>", form_code: "<?php echo sanitize_text_field($attributes['event_a']['form_code']); ?>", profile_key: "<?php echo sanitize_text_field($_GET['pk']) ?>", terms_scope: "<?php echo sanitize_text_field($_GET['signature']); ?>"},
                        success: function(data){
                            if(data.status === "success"){
                                //alert('success');
                                location.href = "<?php echo sanitize_text_field($this->_get_skip_url(['terms' => '', 'pk' => sanitize_text_field($_GET['pk'])])); ?>";
                            }else{
                                //alert('fail');
                                return false;
                            }
                        }
                    });
                }
            });

        </script>
        <?php
        return ob_get_clean();
    }

    /**
     * @param $formData
     * @param $form
     * @return string
     */
    private function _create_terms_screen_fields($formData, $form)
    {
        $terms_signed = $contract_signed = $no_signatures_required = $display_continue = $hide_continue = $mini_block = false;

        $event_attributes = json_decode($this->event_attributes, true);

        $status_approved = $event_attributes['applicant_a']['approval_status'] == 1 ? true : false;

        // print_r($formData); die;

        // checkbox signed
        // $formData['terms_scope'] => 3


        /*
         * $event_a['c_cfg2']
         * event_forms::c_cfg2
         * 1. e-sign before approval
         *      -require signature before initial payments
         * 2. e-sign after approval
         *      -do not require until approval status = 1
         */

        $contract_sign_period = $event_attributes['event_a']['c_cfg2'] == 1 ? 'pre-approval' : 'post-approval';

        if($event_attributes['event_a']['terms_id'] == null && $event_attributes['event_a']['contract'] == 0){
            $no_signatures_required = true;
        }else{
            $applicant_signature = json_decode($this->_get_data("signature", $event_attributes), true);
        }

        // print_r($applicant_signature); die;

        if(isset($applicant_signature['signature'])) {
            foreach($applicant_signature['signature'] AS $signature){
                if($signature['terms_scope'] == 1){
                    $terms_signed = true;
                    $terms_sign_date = $signature['sign_date'];
                    $terms_sign_svg = $signature['svg'];
                    $terms_ip_address = $signature['ip_address'];
                }
                if($signature['terms_scope'] == 2){
                    $contract_signed = true;
                    $contract_sign_date = $signature['sign_date'];
                    $contract_sign_svg = $signature['svg'];
                    $contract_ip_address = $signature['ip_address'];
                }
                // checkbox signed
                if($signature['terms_scope'] == 3){
                    $terms_signed = true;
                    $terms_sign_date = $signature['sign_date'];
                    $terms_ip_address = $signature['ip_address'];
                }
            }
        }

        $no_contract_signature_required = false;
        if($event_attributes['event_a']['contract'] == 1 &&
            $contract_sign_period == 'post-approval' &&
            $status_approved == false) {
            $no_contract_signature_required = true;
        }

        // USE https://summernote.org/deep-dive/ FOR CONTRACT WINDOW

        ob_start();
        ?>

        <?php if($formData['audit'] == 1): ?>
            <!-- DISPLAY audit message -->
            <div class="well well-sm" style="margin-bottom:10px; margin-top:0px;">
                <h4>Audit Mode: Some profile fields are read-only and can only be modified by the primary.
                </h4>
            </div>
        <?php endif; ?>

        <?php //// TERMS SIGNATURE ///// ?>

        <?php if($formData['terms_scope'] == 1) : ?>

            <?php if($terms_signed) : ?>

                <div class="col-lg-offset-2">
                    <h4><?php echo sanitize_text_field($formData['terms']['title']); ?></h4>
                </div>

                <div id="summernote">
                    <?php echo $formData['terms']['body']; ?>
                </div>

                <div style="width: 100%; margin-bottom:20px; margin-top:10px;">
                    <div class="sig_block_inner">
                        <img src="<?php echo sanitize_text_field($terms_sign_svg); ?>" alt="" style="width: 80%;" height="auto">
                        <hr>
                        <div style="margin-top: -8px;">Signature</div>
                    </div>
                    <div class="sig_block_inner">
                        <h5><?php echo sanitize_text_field($terms_sign_date); ?></h5>
                        <hr>
                        <div style="margin-top: -8px;">Date</div>
                    </div>
                </div>
                <?php $display_continue = true; ?>
                <?php $mini_block = true; ?>

            <?php else: ?>

                <div class="col-lg-offset-2">
                    <h4><?php echo sanitize_text_field($formData['terms']['title']); ?></h4>
                </div>

                <div id="summernote">
                    <?php echo $formData['terms']['body']; ?>
                </div>

                <?php if($formData['audit'] == 0): ?>
                    <div style="width:80%; margin:20px auto; text-align:center;">
                        <form class="terms-checkbox">
                            <input id="terms-checkbox" type="checkbox"/><label class="fa" for="terms-checkbox"></label>
                            <?php echo sanitize_text_field($formData['terms']['note']); ?>
                        </form>
                    </div>

                    <?php if($event_attributes['event_a']['terms_proc'] == 1): ?>
                        <div class="center" style="margin-top:10px;">
                            <button type="submit" id="terms-agree-button" class="btn">
                                <i class="fa fa-pencil" aria-hidden="true"></i> <?php echo $this->_button_label_swap('sign_here'); ?>
                            </button>
                        </div>
                    <?php else: ?>
                        <div class="center" style="margin-top:10px;">
                            <button type="submit" id="terms-agree-submit" class="btn">
                               Continue <i style="margin-left:0px;" class="fa fa-chevron-right" aria-hidden="true"></i>
                            </button>
                        </div>
                    <?php endif; ?>
                <?php else: ?>
                    <?php $display_continue = true; ?>
                <?php endif; ?>

                <script type="text/javascript">
                    $(document).ready(function () {
                        // initialize jQuery stuff after page load
                        $(function(){
                            $('#terms-agree-button').click(function () {
                                document.location.href = "<?php echo sanitize_text_field($this->_get_skip_url(['terms' => '', 'signature' => $formData['terms_scope'], 'pk' => sanitize_text_field($_GET['pk'])])); ?>";
                            });
                            $('#terms-agree-submit').click(function () {
                                document.location.href = "<?php echo sanitize_text_field($this->_get_skip_url(['terms' => '', 'signature' => 3, 'pk' => sanitize_text_field($_GET['pk'])])); ?>";
                            });
                            $("#terms-checkbox").on("click", function() {
                                var chk = $("#terms-checkbox").is(":checked");
                                $('#terms-agree-button').prop("disabled", !chk).toggleClass("btn-success",chk);  // possibly add .button('refresh'); for JQM
                                $('#terms-agree-submit').prop("disabled", !chk).toggleClass("btn-success",chk);  // possibly add .button('refresh'); for JQM
                            });
                        });
                        $('#terms-agree-button').prop("disabled", "disabled");
                        $('#terms-agree-submit').prop("disabled", "disabled");
                    });
                </script>

                <?php $hide_continue = true; ?>
            <?php endif; ?>

        <?php endif; ?>

        <?php //// CONTRACTS ///// ?>

        <?php if($formData['terms_scope'] == 2) : ?>

            <?php if($contract_signed) : ?>

                <div class="col-lg-offset-2">
                    <h4><?php echo sanitize_text_field($formData['contract']['title']); ?></h4>
                </div>

                <div id="summernote">
                    <?php echo sanitize_text_field($formData['contract']['body']); ?>
                </div>

                <div style="width: 100%; margin-bottom:20px; margin-top:10px;">
                    <div class="sig_block_inner">
                        <img src="<?php echo sanitize_text_field($contract_sign_svg); ?>" alt="" style="width: 80%;" height="auto">
                        <hr>
                        Signature
                    </div>
                    <div class="sig_block_inner">
                        <h4><?php echo sanitize_text_field($contract_sign_date); ?></h4>
                        <hr>
                        Date
                    </div>
                </div>
                <?php $display_continue = true; ?>
                <?php $mini_block = true; ?>

            <?php else: ?>

                <div class="col-lg-offset-2">
                    <h4><?php echo sanitize_text_field($formData['contract']['title']); ?></h4>
                </div>

                <div id="summernote">
                    <?php echo sanitize_text_field($formData['contract']['body']); ?>
                </div>

                <?php if($formData['audit'] == 0): ?>
                    <div style="width:80%; margin:20px auto; text-align:center;">
                        <form class="terms-checkbox">
                            <input id="terms-checkbox" type="checkbox"/><label class="fa" for="terms-checkbox"></label>
                            <?php echo sanitize_text_field($formData['contract']['note']); ?>
                        </form>
                    </div>

                    <div class="center" style="margin-top:10px;">
                        <button type="submit" id="terms-agree-button" class="btn">
                            <i class="fa fa-pencil" aria-hidden="true"></i> <?php echo $this->_button_label_swap('sign_here'); ?>
                        </button>
                    </div>

                <?php else: ?>
                    <?php $display_continue = true; ?>
                <?php endif; ?>

                <script type="text/javascript">
                    $(document).ready(function () {
                        // initialize jQuery stuff after page load
                        $(function(){
                            $('#terms-agree-button').click(function () {
                                document.location.href = "<?php echo sanitize_text_field($this->_get_skip_url(['terms' => '', 'signature' => $formData['terms_scope'], 'pk' => sanitize_text_field($_GET['pk'])])); ?>";
                            });
                            $("#terms-checkbox").on("click", function() {
                                var chk = $("#terms-checkbox").is(":checked");
                                $('#terms-agree-button').prop("disabled", !chk).toggleClass("btn-success",chk);  // possibly add .button('refresh'); for JQM
                            });
                        });
                        $('#terms-agree-button').prop("disabled", "disabled");
                    });
                </script>
            <?php endif; ?>

        <?php endif; ?>


        <?php //// TERMS CHECKBOX ///// ?>

        <?php if($formData['terms_scope'] == 3) : ?>

            <?php if($terms_signed) : ?>

                <div class="col-lg-offset-2">
                    <h4><?php echo sanitize_text_field($formData['terms']['title']); ?></h4>
                </div>

                <div id="summernote">
                    <?php echo $formData['terms']['body']; ?>
                </div>

                <div style="width: 100%; margin-bottom:20px; margin-top:10px;">
                    <div class="sig_block_inner">
                        <h4><?php echo sanitize_text_field($terms_sign_date); ?></h4>
                        <hr>
                        <div style="margin-top: -8px;">Signed on Date</div>
                    </div>
                    <div class="sig_block_inner">
                        <h4><?php echo sanitize_text_field($terms_ip_address); ?></h4>
                        <hr>
                        <div style="margin-top: -8px;">IP Address</div>
                    </div>
                </div>
                <?php $display_continue = true; ?>
                <?php $mini_block = true; ?>

            <?php else: ?>

                <div class="col-lg-offset-2">
                    <h4><?php echo sanitize_text_field($formData['terms']['title']); ?></h4>
                </div>

                <div id="summernote">
                    <?php echo $formData['terms']['body']; ?>
                </div>

                <?php if($formData['audit'] == 0): ?>
                    <div style="width:80%; margin:20px auto; text-align:center;">
                        <form class="terms-checkbox">
                            <input id="terms-checkbox" type="checkbox"/><label class="fa" for="terms-checkbox"></label>
                            <?php echo sanitize_text_field($formData['terms']['note']); ?>
                        </form>
                    </div>

                    <?php if($event_attributes['event_a']['terms_proc'] == 1): ?>
                        <div class="center" style="margin-top:10px;">
                            <button type="submit" id="terms-agree-button" class="btn">
                                <i class="fa fa-pencil" aria-hidden="true"></i> <?php echo $this->_button_label_swap('sign_here'); ?>
                            </button>
                        </div>
                    <?php else: ?>
                        <div class="center" style="margin-top:10px;">
                            <button type="submit" id="terms-agree-submit" class="btn">
                               Continue <i style="margin-left:0px;" class="fa fa-chevron-right" aria-hidden="true"></i>
                            </button>
                        </div>
                    <?php endif; ?>
                <?php else: ?>
                    <?php $display_continue = true; ?>
                <?php endif; ?>

                <script type="text/javascript">
                    $(document).ready(function () {
                        // initialize jQuery stuff after page load
                        $(function(){
                            $('#terms-agree-button').click(function () {
                                document.location.href = "<?php echo sanitize_text_field($this->_get_skip_url(['terms' => '', 'signature' => $formData['terms_scope'], 'pk' => sanitize_text_field($_GET['pk'])])); ?>";
                            });
                            $('#terms-agree-submit').click(function () {
                                document.location.href = "<?php echo sanitize_text_field($this->_get_skip_url(['terms' => '', 'signature' => 3, 'pk' => sanitize_text_field($_GET['pk'])])); ?>";
                            });
                            $("#terms-checkbox").on("click", function() {
                                var chk = $("#terms-checkbox").is(":checked");
                                $('#terms-agree-button').prop("disabled", !chk).toggleClass("btn-success",chk);  // possibly add .button('refresh'); for JQM
                                $('#terms-agree-submit').prop("disabled", !chk).toggleClass("btn-success",chk);  // possibly add .button('refresh'); for JQM
                            });
                        });
                        $('#terms-agree-button').prop("disabled", "disabled");
                        $('#terms-agree-submit').prop("disabled", "disabled");
                    });
                </script>

                <?php $hide_continue = true; ?>
            <?php endif; ?>

        <?php endif; ?>

        <?php if($no_signatures_required): ?>

            <h4>No Signature Required.</h4>
            <?php $display_continue = true; ?>

        <?php elseif($no_contract_signature_required): ?>
            <div class="center" style="margin-top:10px;">
                <h5>Note: Final contract signature required AFTER application approval.</h5>
            </div>

            <?php $display_continue = $hide_continue ? false : true; ?>

        <?php endif; ?>

            <?php if($display_continue): ?>

            <div class="form-group">
                <div class="col-lg-offset-2 col-lg-11">
                    <button type="submit" id="skipTerms" class="btn btn-success-bottom pull-left">Continue <i style="margin-left:0px;" class="fa fa-chevron-right" aria-hidden="true"></i></button>
                </div>
            </div>
            <script type="text/javascript">
                $(document).ready(function () {
                    // initialize jQuery stuff after page load
                    $(function(){
                        $('#skipTerms').click(function () {
                            document.location.href = "<?php echo sanitize_text_field($this->_get_skip_url(['payment' => '', 'pk' => sanitize_text_field($_GET['pk'])])); ?>";
                        });
                    });
                });
            </script>

        <?php endif; ?>

            <?php if($mini_block): ?>
            <script type="text/javascript">
                var $ = jQuery.noConflict();
                $(document).ready(function ($) {
                    $('#summernote').summernote({
                        toolbar: false,
                        height: 300
                    });
                });
            </script>
        <?php else: ?>
            <script type="text/javascript">
                var $ = jQuery.noConflict();
                $(document).ready(function ($) {
                    $('#summernote').summernote({
                        toolbar: false,
                        height: 500
                    });
                });
            </script>
        <?php endif; ?>

        <?php
        return ($form . $this->_generate_terms_screen_field(ob_get_clean(), $this->event_attributes));
    }

    /**
     * @param $formData
     * @param $form
     * @return string
     */
    private function _create_map_screen_fields($request_url_info)
    {
        $attributes = is_array($this->event_attributes) ? $this->event_attributes : json_decode( $this->event_attributes, true);
        global $wp;

        if(isset($_SESSION['temp_pk'])) {
            $pk = $_SESSION['temp_pk'] . ".temp_pk";
            $request_url_info['pk'] = $_SESSION['temp_pk'] . ".temp_pk";

        }else{
            $pk = sanitize_text_field($_GET['pk']);
        }

        // used in js window.location.href
        $return_url = $this->_get_skip_url(['amenities' => '', 'pk' => $pk]);
        $return_map_url = home_url()."/{$wp->request}/?amenities&map=".$_GET['map']."&pk=".$pk."&v=".str_replace('.', '', microtime(true));

        $finish_button_label = $this->_button_label_swap('close_map');
        ob_start();
        ?>

        <div id="container" class="container">
            <div id="map"></div>
            <div class="topcorner"><a href="<?php echo esc_url(sanitize_url($return_url)); ?>" class="btn btn-success"><?php echo $finish_button_label; ?></a></div>
            <div id="note">
                Click on a booth area to select or de-select. <a id="close_note2"><i class="fa fa-close" style="font-size:20px; color:red"></i></a>
                <?php
                if(1 == 2){
                    if($_SESSION['temp_pk']){
                        echo "session::temp_pk: ";
                        echo $_SESSION['temp_pk'];
                        echo "<br>";
                    }
                    if($_SESSION['pk']){
                        echo "session::pk: ";
                        echo $_SESSION['pk'];
                        echo "<br>";
                    }
                }
                ?>
            </div>
            <div class="sk-fading-circle">
                <div class="sk-circle1 sk-circle"></div>
                <div class="sk-circle2 sk-circle"></div>
                <div class="sk-circle3 sk-circle"></div>
                <div class="sk-circle4 sk-circle"></div>
                <div class="sk-circle5 sk-circle"></div>
                <div class="sk-circle6 sk-circle"></div>
                <div class="sk-circle7 sk-circle"></div>
                <div class="sk-circle8 sk-circle"></div>
                <div class="sk-circle9 sk-circle"></div>
                <div class="sk-circle10 sk-circle"></div>
                <div class="sk-circle11 sk-circle"></div>
                <div class="sk-circle12 sk-circle"></div>
            </div>
        </div>

        <script type="text/javascript">
            var ajax_url ="<?php echo admin_url('admin-ajax.php'); ?>";
            var api_url_info = <?php echo json_encode($request_url_info); ?>;
        </script>

        <script type="text/javascript">
            var map, pFeatures = {}, selectFeature = null, markers = [];
            var marker_icon = L.AwesomeMarkers.icon({
                  icon: 'star',
                  prefix: 'fa',
                  markerColor:'green'
            });
            (function($) {

                $(document).ready(function($){
                    initMap();
                });

                async function initMap(){

                    var api_data = await get_api_data();

                    var image = await getImage(api_data.map_img_url);
                    var image_width = image.width, image_height = image.height, image_url = api_data.map_img_url;

                    map = L.map('map', {
                        minZoom: 1,
                        maxZoom: 10,
                        zoomDelta: 0.5,
                        zoomSnap: 0,
                        center: [parseInt(image_height/2), parseInt(image_width/2)],
                        zoom: 2,
                        crs: L.CRS.Simple,
                        attributionControl:false
                    });
                    map.zoomControl.setPosition('topleft');
                    var image_zoom = map.getMinZoom() + 2;
                    var northWest = map.unproject([0, 0], image_zoom);
                    var southEast = map.unproject([image_width, image_height], image_zoom);
                    var bounds = new L.LatLngBounds(northWest, southEast);

                    L.imageOverlay(image_url, bounds).addTo(map);
                    //map.setMaxBounds(bounds);
                    map.fitBounds(bounds);

                    // draw polygons
                    for(var i=0; i<api_data['imagemap_areas_a'].length;i++){
                        var area = api_data['imagemap_areas_a'][i];
                        var coords = area.coords.split(',');
                        var id = `id_${area.href}`;
                        var area_status = api_data['area_status_js'][id];

                        // BUG 11/28 - this fails if there's an appostrophie in the label or title
                        var popup_content = area_status['toolTip'];

                        // decode php::rawurlencode() content that corrupts bubble content
                        popup_content = decodeURIComponent(popup_content);

                        //var fillOpacity = area_status["selected"] == "true" ? area_status["fillOpacity"] : 0;
                        var fillOpacity = area_status["selected"] == "true" ? 0.5 : 0;
                        var options = {
                            stroke: false,
                            fill: area_status["fill"],
                            fillColor: '#' + area_status["fillColor"],
                            fillOpacity: fillOpacity
                        };

                        switch (area.type) {
                            case 'rect':
                                var x1 = parseInt(coords[0]), y1 = parseInt(coords[1]);
                                var x2 = parseInt(coords[2]), y2 = parseInt(coords[3]);
                                var bounds = [map.unproject([x1,y1],image_zoom), map.unproject([x2,y2],image_zoom)];
                                var polygon = L.rectangle(bounds, options).addTo(map);
                                polygon.id = area.href;
                                polygon.selected = area_status["selected"] == "true" ? true : false;
                                polygon.bindPopup(popup_content,{maxWidth:500, closeButton:false});
                                pFeatures[id] = polygon;
                                addEvent(polygon);
                                break;
                            case 'circle':
                                var xc = parseInt(coords[0]), yc = parseInt(coords[1]), r = parseInt(coords[2]);
                                var latlngs=[];
                                for(angle=0;angle<360;angle+=0.5){
                                    var x = xc + r*Math.cos(angle*Math.PI/180);
                                    var y = yc - r*Math.sin(angle*Math.PI/180);
                                    latlngs.push(map.unproject([x,y],image_zoom));
                                }
                                var polygon = L.polygon(latlngs, options).addTo(map);
                                polygon.id = area.href;
                                polygon.selected = area_status["selected"] == "true" ? true : false;
                                polygon.bindPopup(popup_content,{maxWidth:500, closeButton:false});
                                pFeatures[id] = polygon;
                                addEvent(polygon);
                                break;

                            case 'poly':
                                var latlngs=[];
                                for(var j=0;j<coords.length;j++){
                                    if(j % 2==0){
                                        var x = parseInt(coords[j]);
                                    }else{
                                        var y = parseInt(coords[j]);
                                        latlngs.push(map.unproject([x,y],image_zoom));
                                    }
                                }
                                var polygon = L.polygon(latlngs, options).addTo(map);
                                polygon.id = area.href;
                                polygon.selected = area_status["selected"] == "true" ? true : false;
                                polygon.bindPopup(popup_content,{maxWidth:500, closeButton:false});
                                pFeatures[id] = polygon;
                                addEvent(polygon);
                                break;
                        }

                        if(area_status["ownerFlag"] == "true"){
                            // polygon.getCenter();
                            markers[area.href] = L.marker(
                               [ polygon.getBounds().getNorth(), polygon.getCenter().lng ],
                               { icon: marker_icon }).addTo(map);
                        }
                    }
                    $(".sk-fading-circle").hide();
                }

                function get_api_data(){
                    return new Promise(resolve => {
                        var post_data = {
                            'action': 'get_map_areas',
                            'base_request_url': api_url_info["base_request_url"],
                            'id_hash': api_url_info["id_hash"],
                            'form_key': api_url_info["form_key"],
                            'pk': api_url_info["pk"],
                            'map': api_url_info["map"]
                        };
                        // console.dir(ajax_url);
                        // console.dir(post_data);
                        $.post(ajax_url, post_data, function(data){
                            /*console.dir(data);*/
                            var json = JSON.parse(data);
                            resolve(json);
                        });
                    });

            }

            function addEvent(area){

                area.on('mouseover',function(e){

                    if(selectFeature){
                        if(selectFeature.selected == true){
                            selectFeature.setStyle({ fillOpacity: 0.5 });
                        }else{
                            selectFeature.setStyle({ fillOpacity: 0 });
                        }
                    }
                    selectFeature = this;
                    if(selectFeature.selected == true){
                        this.setStyle({ fillOpacity: 0.7 });
                    }else{
                        this.setStyle({ fillOpacity: 0.5 });
                    }
                    this.openPopup([ this.getBounds().getNorth(), this.getCenter().lng ]);
                });

                area.on('mouseout',function(e){
                    this.closePopup();
                    selectFeature = this;
                    if(selectFeature.selected == true){
                        this.setStyle({ fillOpacity: 0.7 });
                    }else{
                        this.setStyle({ fillOpacity: 0 });
                    }
                });

                area.on('click',function(e){

                    this.openPopup([ this.getBounds().getNorth(), this.getCenter().lng ]);

                    var map_area_name = e.target.id;

                    var post_data={
                        action: "wvnmi_map_submission",
                        data: map_area_name,
                        wvnmi_screen_name: "map",
                        map: api_url_info["map"],
                        wvnmi_verify_submission: api_url_info["wvnmi_map_submission"],
                        form_code: api_url_info["form_key"],
                        profile_key: api_url_info["pk"],
                        audit: 1
                    };

                    jQuery.ajax({
                        url: ajax_url,
                        type: "POST",
                        cache: false,
                        data: post_data,
                        success: function(data){

                            <?php
                            $button = 'booth_select_button';
                            $button_custom_labels = $attributes['event_a']['button_labels'];
                            $select_button_label = !empty($button_custom_labels[$button]) ? $button_custom_labels[$button] : false;

                            $cancel_button_label = $this->_button_label_swap('cancel');

                            $close_button_label = $this->_button_label_swap('close');
                            $select_another_button_label = $this->_button_label_swap('select_another');
                            ?>

                            // alert(status.toSource(data));
                            var status = jQuery.parseJSON(data);
                            var booth_select_custom = "<?php echo $select_button_label; ?>";
                            var select_button = booth_select_custom != false ? booth_select_custom : "Select " + status['label'];
                            var cancel_button_label = "<?php echo $cancel_button_label; ?>";

                            var close_button_label = "<?php echo $close_button_label; ?>";
                            var select_another_button_label = "<?php echo $select_another_button_label; ?>";

                            if(status['code'] == 'info_select') {

                                var temp = status['detail'].split(" ");
                                swal({
                                    html: true,
                                    animation: false,
                                    title: temp[1],
                                    text:  status['info'] + ", " + status['price'] + "<br><br>Click <span style='font-weight: bold'>" + select_button + "</span> to select",
                                    // type: "info",
                                    showCancelButton: true,
                                    closeOnConfirm: false,
                                    showLoaderOnConfirm: true,
                                    confirmButtonText: select_button,
                                    cancelButtonText: cancel_button_label,
                                    reverseButtons: true
                                    // confirmButtonColor: "rgb(53, 138, 60)",
                                    // cancelButtonColor: "#DD6B55"
                                }, function () {
                                    setTimeout(function () {
                                        var post_data = {
                                            action: "wvnmi_map_submission",
                                            data: map_area_name,
                                            wvnmi_screen_name: "map",
                                            map: api_url_info["map"],
                                            wvnmi_verify_submission: api_url_info["wvnmi_map_submission"],
                                            form_code: api_url_info["form_key"],
                                            profile_key: api_url_info["pk"],
                                            audit: 0
                                        };
                                        jQuery.ajax({
                                            url: ajax_url,
                                            type: "POST",
                                            cache: false,
                                            data: post_data,
                                            success: function (data) {
                                                var status = jQuery.parseJSON(data);
                                                if (status['code'] == 'added') {

                                                    area.selected = true;
                                                    area.setStyle({
                                                        fillColor: '#fff099',
                                                        fillOpacity: 0.7
                                                    });
                                                    if(markers[map_area_name]){
                                                        map.addLayer(markers[map_area_name]);
                                                    }else{
                                                        markers[map_area_name] = L.marker(
                                                        [ area.getBounds().getNorth(), area.getCenter().lng ],
                                                        { icon: marker_icon }).addTo(map);
                                                    }
                                                    var temp = status['detail'].split(" ");
                                                    swal({
                                                            title: temp[1] + " Added",
                                                            text: status['label'] + " " + temp[1] + ", " + status['price'],
                                                            type: "success",
                                                            showCancelButton: true,
                                                            confirmButtonColor: "#DD6B55",
                                                            confirmButtonText: close_button_label,
                                                            cancelButtonText: select_another_button_label,
                                                            closeOnConfirm: true,
                                                            closeOnCancel: true
                                                        },
                                                        function (isConfirm) {
                                                            if (isConfirm) {
                                                                window.location.href = "<?php echo sanitize_text_field($return_url); ?>";
                                                            } else {
                                                                // alert('#status_id_' + map_area_name + ' span');
                                                                // $('#status_id_' + map_area_name + ' span').text('Selected');
                                                                window.location.href = "<?php echo sanitize_text_field($return_map_url); ?>";
                                                            }
                                                        });
                                                } else {
                                                    swal(status['label'] + " NOT booked");
                                                }
                                            }
                                        })
                                    }, 1);
                                });

                            }else if(status['code'] == 'info_deselect'){

                                var temp = status['detail'].split(" ");
                                swal({
                                    html: true,
                                    title: temp[1],
                                    text:  status['info'] + ", " + status['price'] + "<br>Status: <span style='font-weight: bold'>SELECTED</span><br><br>Click <span style='font-weight: bold'>Remove " + status['label'] + "</span> to remove this location",
                                    // type: "warning",
                                    showCancelButton: true,
                                    closeOnConfirm: false,
                                    showLoaderOnConfirm: true,
                                    confirmButtonText: "Remove " + status['label'],
                                    cancelButtonText: "Cancel"
                                    // confirmButtonColor: "rgb(53, 138, 60)",
                                    // cancelButtonColor: "#DD6B55"
                                }, function () {
                                    setTimeout(function () {
                                        var post_data={
                                            action: "wvnmi_map_submission",
                                            data: map_area_name,
                                            wvnmi_screen_name: "map",
                                            map: api_url_info["map"],
                                            wvnmi_verify_submission: api_url_info["wvnmi_map_submission"],
                                            form_code: api_url_info["form_key"],
                                            profile_key: api_url_info["pk"],
                                            audit: 0
                                        };
                                        jQuery.ajax({
                                            url: ajax_url,
                                            type: "POST",
                                            cache: false,
                                            data: post_data,
                                            success: function (data) {
                                                var status = jQuery.parseJSON(data);
                                                if(status['code'] == 'removed'){
                                                    area.selected = false;
                                                    area.setStyle({
                                                        fillColor: '#00ff00',
                                                        fillOpacity: 0
                                                    });
                                                    if(markers[map_area_name]){
                                                        map.removeLayer(markers[map_area_name]);
                                                    }
                                                    var temp = status['detail'].split(" ");
                                                    swal({
                                                            title: temp[1] + " Removed",
                                                            type: "error",
                                                            showCancelButton: true,
                                                            confirmButtonColor: "#DD6B55",
                                                            confirmButtonText: "Close",
                                                            cancelButtonText: "Select another",
                                                            closeOnConfirm: true,
                                                            closeOnCancel: true
                                                        },
                                                        function(isConfirm){
                                                            if (isConfirm) {
                                                                window.location.href = "<?php echo sanitize_text_field($return_url); ?>";
                                                            } else {
                                                                // alert('#status_id_' + map_area_name + ' span');
                                                                // $('#status_id_' + map_area_name + ' span').text('Available');
                                                                window.location.href = "<?php echo sanitize_text_field($return_map_url); ?>";
                                                            }
                                                        });
                                                }
                                            }
                                        })
                                        // swal("Ajax request finished!");
                                    }, 1);
                                });

                            }else if(status['code'] == 'added'){
                                area.selected = true;
                                area.setStyle({
                                    fillColor: '#fff099',
                                    fillOpacity: 0.7
                                });
                                if(markers[map_area_name]){
                                    map.addLayer(markers[map_area_name]);
                                }else{
                                    markers[map_area_name] = L.marker(
                                        [ area.getBounds().getNorth(), area.getCenter().lng ],
                                        { icon: marker_icon }).addTo(map);
                                }
                                var temp = status['detail'].split(" ");
                                swal({
                                        title: temp[1] + " Added",
                                        text: status['label'] + " " + temp[1] + ", " + status['price'],
                                        type: "success",
                                        showCancelButton: true,
                                        confirmButtonColor: "#DD6B55",
                                        confirmButtonText: "Yes, close.",
                                        cancelButtonText: "No, select another.",
                                        closeOnConfirm: true,
                                        closeOnCancel: true
                                    },
                                    function(isConfirm){
                                        if (isConfirm) {
                                            window.location.href = "<?php echo sanitize_text_field($return_url); ?>";
                                        } else {
                                            return false;
                                        }
                                    });

                            }else if(status['code'] == 'removed'){
                                area.selected = false;
                                area.setStyle({
                                    fillColor: '#00ff00',
                                    fillOpacity: 0
                                });
                                if(markers[map_area_name]){
                                    map.removeLayer(markers[map_area_name]);
                                }
                                var temp = status['detail'].split(" ");
                                swal({
                                        title: temp[1] + " Removed",
                                        type: "info",
                                        showCancelButton: true,
                                        confirmButtonColor: "#DD6B55",
                                        confirmButtonText: "Yes, close.",
                                        cancelButtonText: "No, select another booth.",
                                        closeOnConfirm: true,
                                        closeOnCancel: true
                                    },
                                    function(isConfirm){
                                        if (isConfirm) {
                                            window.location.href = "<?php echo sanitize_text_field($return_url); ?>";
                                        } else {
                                            return false;
                                        }
                                    });
                            }else if(status['code'] == 'paid'){
                                // do nothing
                            }else if(status['code'] == 'unavailable'){
                                // do nothing
                            }else{
                                swal({
                                    title: "Error: " + status['code'],
                                    text: "Detail: " + status['detail'],
                                    type: "error",
                                    showCancelButton: true,
                                    confirmButtonColor: "#DD6B55",
                                    confirmButtonText: "Yes, close.",
                                    cancelButtonText: "No, not done yet.",
                                    closeOnConfirm: true,
                                    closeOnCancel: true
                                },
                                function(isConfirm){
                                    if (isConfirm) {
                                        window.location.href = "<?php echo sanitize_text_field($return_url); ?>";
                                    } else {
                                        return false;
                                    }
                                });
                            }
                        }
                    });
                });
            }

            function getImage(image_url){
                return new Promise(resolve => {
                    var img = new Image();
                    img.src = image_url;
                    img.onload = function() {
                        resolve({
                            width: this.width,
                            height: this.height
                        });
                    }
                });
            }
            })( jQuery );

        </script>

        <script>
            close = document.getElementById("note");
            close.addEventListener('click', function() {
                note = document.getElementById("note");
                note.style.display = 'none';
            }, false);
        </script>

        <?php
        return ob_get_clean();
    }

    /**
     * @param $formData
     * @param $form
     * @return string
     */
    private function _create_mapview_screen_fields($request_url_info)
    {
        global $wp;

        $current_url = home_url(add_query_arg([], $wp->request));

        $event_attributes = $this->event_attributes;
        $show_booth_price = $event_attributes['event_a']['show_booth_price'];
        $show_booth_favorites = $event_attributes['event_a']['show_booth_favorites'];
        $event_maps_name_host_a = $event_attributes['event_a']['event_maps_name_host_a'];
        $current_map_id = $event_attributes['event_a']['map_id'];

        if(!isset( $_GET['book'])) {
            if(isset($_SESSION['r1_book_code'])){
                unset($_SESSION['r1_book_code']);
            }
        }

        ob_start();
        ?>

        <header class="MapFlex-header row">
            <div class='pull-left map-title-header'></div>

            <div class="MapFlex-map-hosts">
                <?php if(count($event_attributes['event_maps_name_host_a']) > 0): ?>
                <!-- span class="fa fa-lg fa-map-marker" style="color:green"></span -->
                <select class="map-host-selector" id="map-host-selector" name="" onchange="javascript:location.href = this.value;">
                    <?php foreach($event_attributes['event_maps_name_host_a'] AS $map_id => $map_details_a): ?>
                    <?php $selected = $map_id == $current_map_id ? ' selected' : ''; ?>
                    <option value="<?php echo $map_details_a[key($map_details_a)]; ?>"<?php echo $selected; ?>><?php echo key($map_details_a) ?></option>
                    <?php endforeach; ?>
                </select>
                <?php endif; ?>
            </div>

            <div class="MapFlex-keywords">
                <select class="keyword-select selectpicker" name="keyword" title="Search by Keyword" data-live-search="true" data-size="10" data-width="200px">
                </select>
                <button class='btn-keyword-reset btn btn-success'>Reset</button>
            </div>
        </header>

        <div class="MapFlex-body row" id="boothlist-container">
            <div class="MapFlex-nav col-sm-3">
                <div class="search-div">
                    <div class="input-group">
                        <input type="text" class="search" id="input-search-filter" placeholder="Search Area #">
                        <span class="input-group-btn">
                            <button type="button" id="btn-boothlist-reset" data-sort = "client_name" data-toggle="tooltip" data-placement="bottom" title="Reset">
                                <span class="glyphicon glyphicon-refresh" style="color:#eee"></span>
                            </button>
                        </span>
                    </div>
                    <?php if($show_booth_favorites == 1): ?>
                        <span class="badge" id="search-count"></span>
                        <span class="badge" id="my-favorites">Show Favorites</span>
                    <?php endif; ?>
                </div>
                <div class="sort-div">

                    <?php if($show_booth_favorites == 1): ?>
                        <span class = "all-star fa fa-lg fa-star-o" style="color:green"></span>
                    <?php endif; ?>

                    <a class="sort" id="sort_client_name" data-sort="client_name">EXHIBITOR NAME</a>
                    <a class="sort" id="sort_applic_id" data-sort="applic_id">AREA #</a>
                </div>
                <div id="owner" class="owner">
                    <ul id="boothlist" class="boothlist list-group list" style="display:none">

                    </ul>
                </div>
            </div>
            <div class="MapFlex-content col-sm-9">
                <div class="loader"></div>
                <button id="MapFlex-nav-toggle"><span class="glyphicon glyphicon-menu-left"></span></button>
                <div id="map"></div>
                <script type="text/javascript">
                    var ajax_url = "<?php echo admin_url('admin-ajax.php'); ?>";
                    var api_url_info = <?php echo json_encode($request_url_info); ?>;
                </script>
            </div>
        </div>

        <div id="boothModal" class="modal fade">
            <div class="modal-dialog" style="margin-right:0">
                <div class="modal-content">
                    <div class="modal-header">
                        <button type="button" class="close" data-dismiss="modal" aria-hidden="true">&times;</button>
                        <h4 class="modal-title">Area Details</h4>
                        <h5 class="modal-title-description" id="modal_title_description"></h5>
                    </div>
                    <div class="modal-body">
                        <div class="booth-details-loader">
                            <div></div><div></div><div></div><div></div><div></div><div></div>
                            <div></div><div></div><div></div><div></div><div></div><div></div>
                        </div>
                        <form class="form-horizontal">
                            <div class="form-group">
                                <label class="control-label col-md-3">Number</label>
                                <label class="control-label col-md-9" id="m_booth_no"></label>
                            </div>
                            <div class="form-group">
                                <label class="control-label col-md-3">Details</label>
                                <label class="control-label col-md-9" id="m_booth_details"></label>
                            </div>

                            <?php if($show_booth_price == 1): ?>
                            <div class="form-group">
                                <label class="control-label col-md-3">Price</label>
                                <label class="control-label col-md-9" id="m_booth_price"></label>
                            </div>
                            <?php endif; ?>

                            <div class="form-group">
                                <label class="control-label col-md-3">Status</label>
                                <label class="control-label col-md-9" id="m_booth_status"></label>
                            </div>
                        </form>
                    </div>
                </div>
            </div>
        </div>

        <div id="vendorModal" class="modal fade">
            <div class="modal-dialog" style="margin-right:0">
                <div class="modal-content">
                    <div class="modal-header">
                        <button type="button" class="close" data-dismiss="modal" aria-hidden="true">&times;</button>
                        <img class="vendor-logo" id="vendor-modal-logo" src="">
                    </div>
                    <div class="modal-body">
                        <div class="booth-details-loader">
                            <div></div><div></div><div></div><div></div><div></div><div></div>
                            <div></div><div></div><div></div><div></div><div></div><div></div>
                        </div>
                        <form class="form-horizontal" id="vendor-form-horizontal">
                        </form>
                    </div>
                </div>
            </div>
        </div>

        <div id="bookModal" class="modal fade">
            <div class="modal-dialog">
                <div class="modal-content">
                    <div class="modal-header">
                        <button type="button" class="close" data-dismiss="modal" aria-hidden="true">&times;</button>
                        <h3 class="modal-title" id="modal-title"><span style="text-transform: capitalize;" class="book_booth_label"></span> Selected</h3>
                    </div>
                    <div class="modal-body">
                        <div class="booth-details-loader">
                            <div></div><div></div><div></div><div></div><div></div><div></div>
                            <div></div><div></div><div></div><div></div><div></div><div></div>
                        </div>
                        <form class="form-horizontal" id="booth-form-horizontal">
                            <div class="form-group">
                                <label class="control-label col-md-5"><span style="text-transform: capitalize;" class="book_booth_label"></span> Number</label>
                                <label class="control-label col-md-7" id="book_booth_no"></label>
                            </div>
                            <div class="form-group">
                                <label class="control-label col-md-5"><span style="text-transform: capitalize;" class="book_booth_label"></span> Details</label>
                                <label class="control-label col-md-7" id="book_booth_details"></label>
                            </div>
                            <div class="form-group">
                                <label class="control-label col-md-5"><span style="text-transform: capitalize;" class="book_booth_label"></span> Price</label>
                                <label class="control-label col-md-7" id="book_booth_price"></label>
                            </div>
                        </form>
                        <div class="well well-sm" style="margin-bottom:4px; margin-top:4px;">
                            <strong>Directions:</strong> To continue, please click on the application button (below). After your complete the
                            first page of the application, the <span style="text-transform: lowercase;" class="book_booth_label"></span> you selected will automatically
                            be reserved for you. You can also select more <span style="text-transform: lowercase;" class="book_booth_label"></span>s
                            from the application.
                        </div>
                        <div class="form-horizontal" id="booth-form-selectors">
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <script type="text/javascript">
            var map, pFeatures = {}, selectFeature = null;
            var boothList;

            (function($) {
                $(document).ready(function($){
                    var options = {
                        valueNames: [
                            { data: ['id'] },
                            'client_name',
                            'applic_id',
                            {name:'star', attr:'data-flag'}
                        ],
                        item: [
                            '<li class="list-group-item clearfix">',
                            <?php if($show_booth_favorites == 1): ?>
                            '<span class = "star fa fa-lg fa-star-o" style="color:green"></span>',
                            <?php endif; ?>
                            '<a class = "client_name"></a>',
                            '<span class = "applic_id"></span>',
                            '</li>'
                        ].join('')
                    };
                    // console.dir(options);
                    boothList = new List('boothlist-container', options);

                    initMap();

                    boothList.on('updated',function(){
                        // var search_count = boothList.size(); // total size
                        var search_count = boothList.visibleItems.length;
                        $("#search-count").text(search_count + ' Exhibitors');
                        // alert("boothList.on");
                    });

                    $("li.list-group-item").on("mouseover", function() {
                        // alert("hi");
                        var index = $(this).index();
                        // console.log(index);

                        //var list_item = document.getElementsByClassName("list-group-item")[index];
                        //var id = list_item.getAttributeNode("data-id").value;
                        var id = boothList.visibleItems[index].values().id;
                        // console.log(id);

                        if(pFeatures[id]){
                            if(selectFeature){
                                selectFeature.setStyle({
                                    stroke: false,
                                    fillOpacity: 0.3
                                });
                            }
                            selectFeature = pFeatures[id];
                            pFeatures[id].setStyle({
                                stroke: true,
                                fillOpacity: 0.5
                            });
                            if(map.getZoom()>map.getMinZoom() + 2){
                                var center = pFeatures[id].getBounds().getCenter();
                                map.panTo(center);
                                //map.flyTo(center);
                            }
                            pFeatures[id].openPopup([ pFeatures[id].getBounds().getNorth(), pFeatures[id].getCenter().lng ]);
                        }
                    });

                    $("#boothlist").on("mouseover","a.client_name", function(){
                        var index = $(this).parent().index();

                        // console.log(index);
                        //var list_item = document.getElementsByClassName("list-group-item")[index];
                        //var id = list_item.getAttributeNode("data-id").value;
                        var id = boothList.visibleItems[index].values().id;
                        if(pFeatures[id]){
                            if(selectFeature){
                                selectFeature.setStyle({
                                    stroke: false,
                                    fillOpacity: 0.3
                                });
                            }
                            selectFeature = pFeatures[id];
                            pFeatures[id].setStyle({
                                stroke: true,
                                fillOpacity: 0.5
                            });
                            if(map.getZoom()>map.getMinZoom() + 2){
                                var center = pFeatures[id].getBounds().getCenter();
                                map.panTo(center);
                                //map.flyTo(center);
                            }
                            pFeatures[id].openPopup([ pFeatures[id].getBounds().getNorth(), pFeatures[id].getCenter().lng ]);
                        }
                    });

                    $("#boothlist").on("click","a.client_name", function(){
                        if(selectFeature){
                            display_booth_details(selectFeature);
                        }
                    });


                    $("#boothlist").on("click","span.star", function(){
                        var index = $(this).parent().index();
                        if($(this).hasClass("fa-star-o")){
                            $(this).removeClass("fa-star-o");
                            $(this).addClass("fa-star");
                            boothList.visibleItems[index].values({star:1});
                        }else{
                            $(this).removeClass("fa-star");
                            $(this).addClass("fa-star-o");
                            boothList.visibleItems[index].values({star:0});
                        }
                    });

                    $("span.all-star").click(function(){
                        if($(this).hasClass("fa-star-o")){
                            $(this).removeClass("fa-star-o");
                            $(this).addClass("fa-star");
                            $(".list-group-item").find("span.star").removeClass("fa-star-o");
                            $(".list-group-item").find("span.star").addClass("fa-star");
                            for(var i=0;i<boothList.visibleItems.length;i++){
                                boothList.visibleItems[i].values({star:1});
                            }
                        }else{
                            $(this).removeClass("fa-star");
                            $(this).addClass("fa-star-o");
                            $(".list-group-item").find("span.star").removeClass("fa-star");
                            $(".list-group-item").find("span.star").addClass("fa-star-o");
                            for(var i=0;i<boothList.visibleItems.length;i++){
                                boothList.visibleItems[i].values({star:0});
                            }
                        }
                    });

                    $("#my-favorites").click(function(){
                        for (var key in pFeatures) {
                            if(map.hasLayer(pFeatures[key])){
                                map.removeLayer(pFeatures[key]);
                            }
                        }
                        boothList.filter(function(item){
                            if(item.values().star == 1){
                                return true;
                            }else{
                                return false;
                            }
                        });
                        for(var i=0;i<boothList.visibleItems.length;i++){
                            var id = boothList.visibleItems[i].values().id;
                            if(!map.hasLayer(pFeatures[id])){
                                map.addLayer(pFeatures[id]);
                            }
                        }
                    });

                    $("#btn-boothlist-reset").click(function(){
                        $("#input-search-filter").val('');
                        for (var key in pFeatures) {
                            if(!map.hasLayer(pFeatures[key])){
                                map.addLayer(pFeatures[key]);
                            }
                        }
                        boothList.filter();
                        boothList.search();
                    });

                    $(".keyword-select").change(function(){
                        $(".loader").show();
                        for (var key in pFeatures) {
                            map.removeLayer(pFeatures[key]);
                        }
                        var post_data = {
                            'action': 'get_map_areas_by_kid',
                            'base_request_url': api_url_info["base_request_url"],
                            'event_code': api_url_info["event_code"],
                            'amenity_id': api_url_info["amenity_id"],
                            'kid': $(this).val()
                        };
                        $.post(ajax_url, post_data, function(data){
                            var json = JSON.parse(data);
                            var map_areas = json["imagemap_areas_a"];
                            var ids = [];
                            for(var i=0;i<map_areas.length;i++){
                                var id = `id_${map_areas[i]["href"]}`;
                                map.addLayer(pFeatures[id]);
                                ids.push(`[${json["applic_id_map_id_a"][map_areas[i]["href"]]}]`);
                            }
                            boothList.filter(function(item){
                                //console.log(item.values());
                                for(var i=0;i<ids.length;i++){
                                    if(item.values().applic_id == ids[i]){
                                        return true;
                                    }
                                }
                                return false;
                            });
                            $(".loader").hide();
                        });
                    });

                    $(".btn-keyword-reset").click(function(){
                        for (var key in pFeatures) {
                            if(!map.hasLayer(pFeatures[key])){
                                map.addLayer(pFeatures[key]);
                            }
                        }
                        boothList.filter();
                        boothList.search();
                    });

                    $("#MapFlex-nav-toggle").click(function(){
                        $(".MapFlex-nav").toggleClass("toggled");
                        if($(this).find('span').hasClass("glyphicon-menu-left")){
                            $(this).find('span').removeClass("glyphicon-menu-left");
                            $(this).find('span').addClass("glyphicon-menu-right");
                            $(".MapFlex-nav").removeClass("col-sm-3");
                            $(".MapFlex-content").removeClass("col-xs-9");
                            $(".MapFlex-content").addClass("col-xs-12");
                            $(".MapFlex-content").removeClass("col-sm-9");
                            $(".MapFlex-content").addClass("col-sm-12");
                            $(".MapFlex-content").removeClass("col-md-9");
                            $(".MapFlex-content").addClass("col-md-12");
                            $(".MapFlex-content").removeClass("col-lg-9");
                            $(".MapFlex-content").addClass("col-lg-12");
                            if($(window).width()<768){
                                $(".MapFlex-content").css("height","100%");
                            }
                        }else{
                            $(this).find('span').removeClass("glyphicon-menu-right");
                            $(this).find('span').addClass("glyphicon-menu-left");
                            $(".MapFlex-nav").addClass("col-sm-3");
                            $(".MapFlex-content").removeClass("col-xs-12");
                            $(".MapFlex-content").addClass("col-xs-9");
                            $(".MapFlex-content").removeClass("col-sm-12");
                            $(".MapFlex-content").addClass("col-sm-9");
                            $(".MapFlex-content").removeClass("col-md-12");
                            $(".MapFlex-content").addClass("col-md-9");
                            $(".MapFlex-content").removeClass("col-lg-12");
                            $(".MapFlex-content").addClass("col-lg-9");
                            if($(window).width()<768){
                                $(".MapFlex-content").css("height","50%");
                            }
                        }
                        map.invalidateSize();
                    });
                });
            })( jQuery );

            async function initMap(){

                var api_data = await get_api_data();

                // add title
                var home_url = '<a href="/">Home</a>';
                if(api_data['event_a']['home_url']){
                    home_url = '<a href="' + api_data['event_a']['home_url'] + '">Home</a>';
                }

                if(api_data['event_a']['title']) {
                    $(".map-title-header").html(home_url + ' > ' + api_data['event_a']['title'] + ' > ' + api_data['maps_a']['name']);
                }

                // console.dir(api_data["map_area_owner_a"]);

                // add list
                for(var applic_id in api_data["map_area_owner_a"]){
                    var client_name = api_data["map_area_owner_a"][applic_id];
                    boothList.add({
                        id: 'id_' + applic_id,
                        client_name: client_name,
                        applic_id: '<span class="btn-grid btn-info">' + api_data['applic_id_map_id_a'][applic_id] + '</span>',
                        star: 0
                    });
                }

                // add select list
                if(api_data['maps_a']['show_keywords'] == 1){
                    $(".MapFlex-keywords").show();
                    for(var kid  in api_data['applic_keywords_a'] ){
                        var keyword = api_data['applic_keywords_a'][kid];
                        $('.selectpicker').append('<option value="'+kid+'">'+keyword+'</option>');
                    }
                    $(".selectpicker").selectpicker("refresh");
                }else{
                    $(".MapFlex-keywords").hide();
                }

                var image = await getImage(api_data.map_img_url);
                var image_width = image.width, image_height = image.height, image_url = api_data.map_img_url;

                map = L.map('map', {
                    minZoom: 0,
                    maxZoom: 10,
                    zoomDelta: 0.25,
                    zoomSnap: 0,
                    center: [parseInt(image_height/2), parseInt(image_width/2)],
                    zoom: 2,
                    crs: L.CRS.Simple,
                    attributionControl:false
                });

                // https://kempe.net/blog/2014/06/14/leaflet-pan-zoom-image.html
                map.zoomControl.setPosition('topleft');
                var image_zoom = map.getMinZoom() + 2; //0 = less, 2 = more
                var northWest = map.unproject([0, 0], image_zoom);
                var southEast = map.unproject([image_width, image_height], image_zoom);

                var bounds = new L.LatLngBounds(northWest, southEast);
                console.dir(bounds);

                L.imageOverlay(image_url, bounds).addTo(map);
                //map.setMaxBounds(bounds);
                map.fitBounds(bounds);

                // set initial zoom level
                var zoomlevel = map.getZoom();
                var init_zoom = (parseFloat(zoomlevel)+parseFloat(api_data['event_a']['init_map_zoom'])).toFixed(5);
                map.setZoom(init_zoom);

                // draw polygons
                for(var i=0; i<api_data['imagemap_areas_a'].length;i++){
                    var area = api_data['imagemap_areas_a'][i];
                    var coords = area.coords.split(',');
                    var id = `id_${area.href}`;
                    // alert(id);
                    var area_status = api_data['area_status_js'][id];
                    // alert(area_status['render_select']['fillColor']);
                    var popup_content = `${area_status['toolTip']}<div class="booth_details">click for details</div>`; //<br><a class="booth_details">Click for Details</a>`;
                    var fillColor = area_status['render_select']['fillColor'];

                    // decode php::rawurlencode() content that corrupts bubble content
                    popup_content = decodeURIComponent(popup_content);
                    var options = {
                        stroke: false,
                        // color: '#' + fillColor,
                        // color: '#f00',
                        // weight: 0,
                        fill: true,
                        fillColor: '#' + fillColor,
                        // fillColor: '#f00',
                        fillOpacity: 0.2
                    };

                    switch (area.type) {
                        case 'rect':
                            var x1 = parseInt(coords[0]), y1 = parseInt(coords[1]);
                            var x2 = parseInt(coords[2]), y2 = parseInt(coords[3]);
                            var bounds = [map.unproject([x1,y1],image_zoom), map.unproject([x2,y2],image_zoom)];
                            var polygon = L.rectangle(bounds, options).addTo(map);
                            polygon.id = id;
                            polygon.bindPopup(popup_content,{maxWidth:500, closeButton:false});
                            pFeatures[id] = polygon;
                            addEvent(polygon);
                            break;

                        case 'circle':
                            var xc = parseInt(coords[0]), yc = parseInt(coords[1]), r = parseInt(coords[2]);
                            var latlngs=[];
                            for(angle=0;angle<360;angle+=0.5){
                                var x = xc + r*Math.cos(angle*Math.PI/180);
                                var y = yc - r*Math.sin(angle*Math.PI/180);
                                latlngs.push(map.unproject([x,y],image_zoom));
                            }
                            var polygon = L.polygon(latlngs, options).addTo(map);
                            polygon.id = id;
                            polygon.bindPopup(popup_content,{closeButton:false});
                            pFeatures[id] = polygon;
                            addEvent(polygon);
                            break;

                        case 'poly':
                            var latlngs=[];
                            for(var j=0;j<coords.length;j++){
                                if(j % 2==0){
                                    var x = parseInt(coords[j]);
                                }else{
                                    var y = parseInt(coords[j]);
                                    latlngs.push(map.unproject([x,y],image_zoom));
                                }
                            }
                            var polygon = L.polygon(latlngs, options).addTo(map);
                            polygon.id = id;
                            polygon.bindPopup(popup_content,{closeButton:false});
                            pFeatures[id] = polygon;
                            addEvent(polygon);
                            break;
                    }
                }

                $('#sort_client_name')[0].click();
                $("#boothlist").show();
                $(".loader").hide();
            }

            function get_api_data(){
                return new Promise(resolve => {
                    var post_data = {
                        'action': 'get_map_view_areas',
                        'base_request_url': api_url_info["base_request_url"],
                        'event_code': api_url_info["event_code"],
                        'amenity_id': api_url_info["amenity_id"]
                    };
                    /* console.log(post_data); */
                    $.post(ajax_url, post_data, function(data){
                        /* console.log(data); */
                        var json = JSON.parse(data);
                        resolve(json);
                    });
                });
            }

            function addEvent(area){
                area.on('mouseover',function(e){
                    if(selectFeature){
                        selectFeature.setStyle({
                            stroke: false,
                            fillOpacity: 0.3
                        });
                    }
                    selectFeature = this;
                    this.setStyle({
                        stroke: true,
                        fillOpacity: 0.5
                    });
                    this.openPopup([ this.getBounds().getNorth(), this.getCenter().lng ]);
                });

                area.on('mouseout',function(e){
                    this.closePopup();
                });

                area.on('click',function(e){
                    this.openPopup([ this.getBounds().getNorth(), this.getCenter().lng ]);
                    display_booth_details(area);
                });
            }

            function display_booth_details(area){

                if(area.id.indexOf(".") == -1) {
                    // alert(area.id);
                    var href_id = area.id;
                    var post_data = {
                        'action': 'get_booth_details',
                        'base_request_url': api_url_info["base_request_url"],
                        'event_code': api_url_info["event_code"],
                        'amenity_id': api_url_info["amenity_id"],
                        'href_id': href_id,
                        'is_aid': 1
                    };

                    $("#vendor-form-horizontal").empty();
                    $("#vendor-modal-title").empty();
                    $("#vendor-modal-logo").attr("src", '');

                    $("#vendorModal").modal('show');
                    $(".booth-details-loader").show();

                    $.post(ajax_url, post_data, function (data) {

                        var json = JSON.parse(data);
                        $(".booth-details-loader").hide();
                        try {
                            var labels = json['event_a']['booth_detail_labels'];
                            var v_data = json["vendor_details_js"];
                            var b_fields = json['event_a']['booth_details'];

                            // $("#vendor-modal-title").text(v_data['vendor_name']);

                            if(v_data['vendor_logo']){
                                $("#vendor-modal-logo").attr("src", v_data['vendor_logo']);
                            }

                            $.each(b_fields, function(index, value) {
                                // console.log(value);

                                var field_id = (value.indexOf('field_') == -1) ? value : value.split('field_')[1];
                                // console.log(labels[field_id]);
                                field_label = decodeURIComponent(labels[field_id]);
                                field_data = decodeURIComponent(v_data[field_id]);
                                field_data = field_data == 'undefined' ? '' : field_data;

                                field_data_rev = field_data.split("").reverse().join("");

                                // var img_test = field_data_rev.split(".")[0];
                                // img_test = img_test.split("").reverse().join("");

                                if(field_label == 'undefined'){

                                //}else if(img_test === 'jpg' || img_test === 'png' || img_test === 'gif' || img_test === 'jpeg'){
                                //    $('#vendor-form-horizontal').append("<div class='form-group'><img class='company-detail-logo control-label col-md-12' src=" + field_data + "></div>");
                                }else{
                                    $('#vendor-form-horizontal').append("<div class='form-group'><label class='control-label col-md-3'>" + field_label + "</label><label class='control-data col-md-9'>" + field_data + "</label></div>");
                                }
                            });

                        } catch (error) {
                            $("#vendor-form-horizontal").empty();
                        }
                    });
                }else{
                    var href_id = area.id.split('.')[0];
                    var post_data = {
                        'action': 'get_booth_details',
                        'base_request_url': api_url_info["base_request_url"],
                        'event_code': api_url_info["event_code"],
                        'amenity_id': api_url_info["amenity_id"],
                        'href_id': href_id
                    };
                    $("#boothModal").modal('show');
                    $(".booth-details-loader").show();
                    $("#m_booth_no").text("");
                    $("#m_booth_price").text("");
                    $("#m_booth_details").text("");
                    $("#m_booth_status").text("");

                    $.post(ajax_url, post_data, function (data) {
                        var json = JSON.parse(data);
                        $(".booth-details-loader").hide();
                        try {
                            var area_key_prefix = area.id.split(".",2)[0];
                            var area_key_suffix = area.id.substr(area.id.indexOf('.')+1);
                            var area_key = area_key_prefix + '.' + btoa(area_key_suffix);
                            var m_info = json["area_detail_js"][area_key];

                            // console.log(m_info);
                            var book_code = json['event_a']['book_code'];
                            var book_url = json['event_a']['book_code'] != false ? '<a href="?book=' + book_code + '" class="btn btn-success" style="text-decoration: none; margin: 0px;">Book this ' + m_info["label"] + '</a>' : '';
                            // split area_key and base64 encode suffix to match b64 key from API
                            // ie. id_100.MTAxIHRoaXMgaXMgLiAzNDIzNA==
                            // console.log(area_key);
                            // console.log(area_key_suffix);
                            $("#m_booth_no").text(m_info["booth_no"]);
                            $("#m_booth_price").text(m_info["booth_fee"]);
                            $("#m_booth_details").text(m_info["booth_detail"]);
                            $("#m_booth_status").html(m_info["booth_status"] + ' ' + book_url);

                        } catch (error) {

                            $("#m_booth_no").text("");
                            $("#m_booth_price").text("");
                            $("#m_booth_details").text("");
                            $("#m_booth_status").text("");
                        }
                    });
                }
            }

            function getImage(image_url){
                return new Promise(resolve => {
                    var img = new Image();
                    img.src = image_url;
                    img.onload = function() {
                        resolve({
                            width: this.width,
                            height: this.height
                        });
                    }
                });
            }

        </script>

        <?php if(isset( $_GET['book'])): ?>

        <?php
        $map_area_id = 0;
        if(isset($_GET['book'])) {
            $map_area_id = $booth_label = '';
            list(, $map_area_id, $booth_label) = explode("-", base64_decode(sanitize_text_field($_GET['book'])),3);
        }
        ?>

        <script type="text/javascript">
            $("#bookModal").modal('show');

            var post_data = {
                'action': 'get_booth_details',
                'base_request_url': api_url_info["base_request_url"],
                'event_code': api_url_info["event_code"],
                'amenity_id': api_url_info["amenity_id"],
                'href_id': <?php echo $map_area_id; ?>
            };

            // console.log(post_data);

            $("#book_booth_no").text("");
            $("#book_booth_price").text("");
            $("#book_booth_details").text("");
            $(".book_booth_label").text("");

            $.post(ajax_url, post_data, function (data) {
                var json = JSON.parse(data);

                try {

                    var area_key = "id_<?php echo $map_area_id; ?>.<?php echo $booth_label; ?>";
                    var book_info = json["area_detail_js"][area_key];

                    $("#book_booth_no").text(book_info["booth_no"]);
                    $("#book_booth_price").text(book_info["booth_fee"]);
                    $("#book_booth_details").text(book_info["booth_detail"]);
                    $(".book_booth_label").text(book_info["booth_label"]);

                    var form_url = json['form_host_urls_a'][json['event_a']['book_forms']];
                    var form_label = json['form_host_labels_a'][json['event_a']['book_forms']];

                    $('#booth-form-selectors').append("<div class='form-group'><label class='control-label col-md-12'><a href='" + form_url + "' class='btn btn-success' style='text-decoration: none; margin: 0px;' target='_parent'>" + form_label + "</a></label></div>");

                } catch (error) {
                    $("#book_booth_no").text("");
                    $("#book_booth_price").text("");
                    $("#book_booth_details").text("");
                    $(".book_booth_label").text("");
                }
            });
        </script>

    <?php endif; ?>

        <?php
        return ob_get_clean();
    }

    /**
     * @param $formData
     * @param $form
     * @return string
     */
    private function _create_amenities_screen_fields($formData, $form)
    {
        global $wp;

        $event_attributes = json_decode($this->event_attributes, true);

        $current_url = home_url(add_query_arg([], $wp->request));
        $mt = str_replace('.', '', microtime(true));
        $skip_profile = false;

        ob_start();

        $is_new = true;
        $skip_profile = false;
        if(isset( $_GET['rfc']) && $_GET['rfc'] != ''){
            $is_new = $_GET['rfc'] == 'new' ? true : false;
        }elseif(isset( $_GET['pk']) && $_GET['pk'] != ''){
            $is_new = false;
        }
        ?>

        <?php if($event_attributes['event_a']['rsvp_form_host_id'] > 0): ?>
            <?php if($is_new && isset($_SESSION['temp_pk']) && !isset($_GET['ok']) && !$logout_flag): ?>
                <?php
                $formData['amenities_selector_a'] = [];
                ?>
                <div class="form-group-top-error field-clients-value-apply_step1">
                    <div class="col-lg-8">
                        <div class="red-alert"><h4>NOTICE: Company tracking code not found.</h4></div>
                        <h5>The URL should end with: /?ok={company-code}.</h5>
                    </div>
                </div>
            <?php endif; ?>
        <?php endif; ?>

        <?php
        // mod here to change dialogue if no amenities
        if($this->_count_array($formData['amenities_selector_a']) > 0){
            ?>

            <div class="col-lg-offset-2">
                <?php if(!empty($formData['amenity_note'])): ?>
                    <div class="block_text well" style="margin-left:0px; margin-top:4px;"><?php echo $formData['amenity_note']; ?></div>
                <?php else: ?>
                    <h4>Select the amenities you require.</h4>
                <?php endif; ?>
            </div>

        <?php }else{ ?>

            <div class="col-lg-offset-2">
                <br><h4>No amenities to select for this event.</h4>
            </div>

        <?php } ?>

        <div id="amenities_container">

            <?php
            $map_select_bool = '';
            $map_policy = $event_attributes['event_a']['map_policy'];

            $map_reservation_shared_a = $formData['map_reservation_shared_a'];
            $map_reservation_share_with_name_a = $formData['map_reservation_share_with_name_a'];
            $map_reservation_fee_override_a = $formData['map_reservation_fee_override_a'];
            $order_lock = $formData['order_lock'];

            if(isset($_SESSION['temp_pk'])) {
                $pk = $_SESSION['temp_pk'] . ".temp_pk";

            }else{
                $pk = sanitize_text_field($_GET['pk']);
            }

            if($this->_count_array($formData['amenities_selector_a']) > 0) {

                foreach ($formData['amenity_types_custom_order_a'] as $key => $val) { ?>

                    <?php if (array_key_exists($val, $formData['amenity_types_map_selectors_a'])) {
                        $required_flag = isset($formData['amenities_required_a'][$val]) ? "<span class='red-alert'>*</span>" : "";
                        ?>

                        <div class="form-group field-event required">
                            <label class="col-lg-2 control-label well-label"
                                   for="amenity-types"><?php echo sanitize_text_field($formData['amenity_types_a'][$val].$required_flag); ?>
                            </label>

                            <div class="col-lg-2 control-desc"
                                 for="amenity-types"><?php echo sanitize_text_field($formData['amenity_types_desc_a'][$val]); ?></div>

                            <?php
                            if(isset($formData['amenities_required_a'][$val]) && $this->_count_array($formData['amenity_map_area_selected_a']) == 0):
                                echo "<input data-parsley-error-message='A booth selection is required. Please click on a map button and select a booth.' style='display:none;' required='' name='booth_selections' type='text' value='{$map_select_bool}'>";
                            endif;

                            $map_button_label = $formData['booth_button_label'] != null ? $formData['booth_button_label'] : 'Select';
                            ?>

                            <?php foreach ($formData['amenities_selector_a'][$val] as $selectorKey => $selector): ?>

                                <?php
                                $mapData = $this->_get_map_data_by_id($selectorKey, $pk);
                                ?>

                                <div class="col-lg-10">
                                    <input type="hidden" name="amenity_types[amenity_types_id]">

                                    <div id="clients-form">

                                        <?php if($formData['order_lock'] == 0 && $map_policy == 2): ?>
                                            <a href="<?php echo esc_url(sanitize_url($this->_get_skip_url(['amenities' => '', 'map' => $selectorKey, 'pk' => $pk]))); ?>"
                                               class="btn btn-success" style="text-decoration: none; margin-left: 15px; margin-bottom: 6px; margin-top: 2px;"><?php echo $map_button_label ?> <?php echo sanitize_text_field($selector); ?></a>

                                        <?php elseif($formData['order_lock'] == 1 && $map_policy == 2): ?>
                                            <button
                                               class="btn btn-grey" style="cursor: no-drop; border: 1px solid #c8c8c8; text-decoration: none; margin-left: 15px; margin-bottom: 6px; margin-top: 6px;"><?php echo $map_button_label ?> <?php echo sanitize_text_field($selector); ?></button>
                                            <script>
                                            $("button").click(function(e) {
                                                e.preventDefault();
                                            });
                                            </script>
                                        <?php endif; ?>

                                        <?php if ($this->_count_array($formData['amenity_map_area_selected_a']) > 0): ?>
                                            <?php foreach ($formData['amenity_map_area_selected_a'] as $areaKey => $area): ?>
                                                <?php if ($area == $selectorKey): ?>
                                                    <?php
                                                    $map_select_bool = 'true';

                                                    // is blank if temp_pk
                                                    $area_data = $this->_get_area_data_by_id($areaKey, $mapData);
                                                    list(, $href) = explode(".", $area_data['href'], 2);

                                                    if(isset($map_reservation_fee_override_a[$area_data['map_area_id']])){
                                                        $area_data['alt'] = $map_reservation_fee_override_a[$area_data['map_area_id']];
                                                    }
                                                    ?>
                                                    <div class = "amenity-item-container">
                                                        <div id = "load_map_<?php echo esc_attr($val); ?>"
                                                             class="amenity-label checkbox">

                                                            <input class="amenity_type" type="checkbox" value="1" checked
                                                                <?php if($map_policy == 2): ?>
                                                                    id = "map_area_<?php echo $area_data['map_area_id']; ?>"
                                                                    name = "map_area_<?php echo $area_data['map_area_id']; ?>"
                                                                    onclick="toMap('<?php echo sanitize_text_field($this->_get_skip_url(['amenities' => '', 'map' => $selectorKey, 'pk' => esc_attr($_GET['pk'])])) ?>')"
                                                                <?php else: ?>
                                                                    id = "map_area_<?php echo $area_data['map_area_id']; ?>"
                                                                    name = "map_area_<?php echo $area_data['map_area_id']; ?>"
                                                                    onclick="this.checked=true;"
                                                                <?php endif; ?>
                                                            >

                                                            <label for=""><?php echo sanitize_text_field($href); ?>
                                                                <?php
                                                                if(!empty($area_data['title'])): echo " (".$area_data['title'] .")"; endif;
                                                                ?>
                                                            </label>
                                                            <?php

                                                            if($formData['order_lock'] == 0 && !empty($area_data['reserved']) && !isset($formData['amenity_map_area_paid_a'][$area_data['map_area_id']])):
                                                                $current_url .= esc_url(sanitize_url("/?amenities&maprel=".$area_data['map_area_id']."&pk=" . $pk . "&v=" . $mt));
                                                                echo '<a href="'.$current_url.'" class="maprel btn-nav btn-red" data-title="Release reserved location?">release</a>';
                                                            endif;
                                                            ?>

                                                            <?php
                                                            if(!empty($area_data['reserved']) && isset($formData['map_reservations_expiration_a'][$area_data['map_area_id']]) && !isset($formData['amenity_map_area_paid_a'][$area_data['map_area_id']])):
                                                                $expires_date = date("m/d/Y", strtotime($formData['map_reservations_expiration_a'][$area_data['map_area_id']]));
                                                                ?>
                                                                <div class="reserved_date tooltip" title="Reservations must be paid by the hold date or it will be released">
                                                                    Booth reserved through <?php echo $expires_date; ?>
                                                                    <i class="fa fa-info-circle" aria-hidden="true"></i></div>
                                                            <?php
                                                            endif;
                                                            ?>

                                                            <?php
                                                            if(isset($map_reservation_shared_a[$area_data['map_area_id']])):
                                                                $shared_with = isset($map_reservation_share_with_name_a[$area_data['map_area_id']]) ? $map_reservation_share_with_name_a[$area_data['map_area_id']] : '';
                                                                ?>
                                                                <div class="amenity_info tooltip" title="This booth is shared by you and another party">
                                                                    Shared with: <?php echo $shared_with; ?></div>
                                                            <?php
                                                            endif;
                                                            ?>

                                                            <?php
                                                            if($formData['booth_sharing'] == 1):
                                                                ?>
                                                                <span style="font-size: 12px; float: right; margin: 0; line-height: 8px; cursor: pointer" id="booth_share_<?php echo esc_attr($val); ?>">share space</span>
                                                                <div style="display: none" id="booth_share_form_<?php echo $val; ?>">
                                                                    e-mail of the second party
                                                                    <input id="booth_share_email_<?php echo $val; ?>" class="form-control" name="Clients[booth_share_email][<?php echo $val; ?>]" maxlength="255" value="" style="max-width: 300px" type="text">
                                                                    What percentage of the cost are THEY paying?
                                                                    <input id="booth_share_email_<?php echo $val; ?>" class="form-control" name="Clients[booth_share_percent][<?php echo $val; ?>]" maxlength="255" value="" style="max-width: 300px" type="text">
                                                                </div>
                                                            <?php
                                                            endif;
                                                            ?>
                                                        </div>
                                                        <div class="col-lg-8 amenity-price">
                                                            <?php echo sanitize_text_field($formData['currency_symbol'].$area_data['alt']); ?>
                                                            <span><strong>x</strong></span>
                                                            <input type="text" class="amenity_booth_qty" size="2" maxlength="2"
                                                                   name="" value="1" disabled>
                                                        </div>
                                                        <div class="flex-right-gutter"></div>
                                                    </div>

                                                    <script type="text/javascript">
                                                        $(document).ready(function () {
                                                            // initialize jQuery stuff after page load
                                                            new jBox('Modal', {
                                                                attach: '#booth_share_<?php echo $val; ?>',
                                                                animation: 'zoomIn',
                                                                overlay: false,
                                                                title: 'Share <?php echo $href; ?> with a second party',
                                                                content: $('#booth_share_form_<?php echo $val; ?>')
                                                            });
                                                        });
                                                    </script>

                                                <?php endif; ?>

                                            <?php endforeach; ?>
                                        <?php endif; ?>
                                    </div>
                                </div>
                            <?php endforeach; ?>

                        </div>

                    <?php } else {

                        $selector_type = $formData['amenity_types_selector_a'][$val] == 1 ? 'checkbox' : 'radio';
                        ?>

                        <?php if (array_key_exists($val, $formData['amenities_selector_a'])) { ?>

                            <?php
                            if(isset($formData['amenities_required_a'][$val])):
                                if($selector_type == 'checkbox') {
                                    $required_param = 'data-parsley-error-message="Please select an item from this section." data-parsley-mincheck="1" data-parsley-errors-container="#error-box-' . $val . '" required="required"';
                                }else{
                                    $required_param = 'data-parsley-error-message="Please select an item from this section." data-parsley-errors-container="#error-box-' . $val . '" required="required"';
                                }
                                $required_flag = "<span class='red-alert'>*</span>";
                                $error_div = '<div class="col-lg-offset-2" id="error-box-'. $val .'"></div>';

                            else:
                                $error_div = $required_param = $required_flag = '';

                            endif;
                            ?>

                            <div class="form-group field-event required">
                                <label class="col-lg-2 control-label well-label"
                                       for="amenity-types"><?php echo sanitize_text_field($formData['amenity_types_a'][$val].$required_flag); ?></label>

                                <div class="col-lg-2 control-desc"
                                     for="amenity-types"><?php echo sanitize_text_field($formData['amenity_types_desc_a'][$val]); ?></div>

                                <?php echo $error_div; ?>

                                <div class="col-lg-10" style="">
                                    <!-- input type="hidden" name="amenity_types[amenity_types_id]" value="" -->

                                    <div id="clients-form">
                                        <?php foreach ($formData['amenities_selector_a'][$val] as $selectorKey => $selector): ?>
                                            <?php
                                            $description = !empty($formData['amenities_selector_desc_a'][$val][$selectorKey]) ? $formData['amenities_selector_desc_a'][$val][$selectorKey] : '';
                                            $description_class = !empty($formData['amenities_selector_desc_a'][$val][$selectorKey]) ? 'tooltip' : '';

                                            if(isset($formData['amenity_avail_qty_a'][$val][$selectorKey])){
                                                if($formData['amenity_avail_qty_a'][$val][$selectorKey] == 0){
                                                    $formData['amenities_selector_default_qty_a'][$val][$selectorKey] = 0;
                                                }
                                            }
                                            ?>

                                            <div class = "amenity-item-container">
                                                <div class = "amenity-label <?php echo $selector_type; ?>">

                                                        <input type = "<?php echo $selector_type; ?>"

                                                        <?php if(isset($formData['disable_amenity_type_selectors_a'][$val])): ?>
                                                            disabled
                                                        <?php elseif(isset($formData['amenity_disable_a'][$selectorKey]) && !isset($formData['amenity_qty_selected_a'][$selectorKey])): ?>
                                                            disabled
                                                        <?php elseif($order_lock == 1): ?>
                                                            disabled
                                                        <?php endif; ?>

                                                        id = "amenity_type_<?php echo esc_attr($selectorKey); ?>"
                                                        class = "amenity_type amenity_type_selector_<?= esc_attr($val) ?>"

                                                        <?php if(isset($formData['amenity_id_selected_a'][$val]) && in_array($selectorKey, $formData['amenity_id_selected_a'][$val])): ?>
                                                            checked
                                                        <?php elseif($formData['amenities_selector_default_qty_a'][$val][$selectorKey] > 0): ?>
                                                            checked
                                                        <?php endif; ?>

                                                        name = "Clients[amenity_types][<?php echo esc_attr($val); ?>][]"
                                                        value = "<?php echo $selectorKey; ?>"
                                                        <?php echo $required_param; ?>>

                                                    <label for="amenity_type_<?php echo esc_attr($selectorKey); ?>" class="<?php echo $description_class; ?>" title="<?php echo $description; ?>">
                                                        <?php echo sanitize_text_field($selector); ?>

                                                        <?php if(!empty($description)): ?>
                                                            <i class="fa fa-info-circle" aria-hidden="true"></i>
                                                        <?php endif; ?>

                                                    </label>

                                                    <?php if(isset($formData['amenity_max_qty_a'][$val][$selectorKey])): ?>
                                                        <div class="amenity_info tooltip" title="Max qty available for this event.">
                                                            Available Qty:
                                                            <strong><?php echo $formData['amenity_avail_qty_a'][$val][$selectorKey]; ?> of <?php echo $formData['amenity_max_qty_a'][$val][$selectorKey]; ?> </strong>
                                                        </div>
                                                    <?php endif; ?>

                                                    <?php if(!empty($formData['amenity_purchased_by_list_a'][$val][$selectorKey])): ?>
                                                        <div class="amenity_members" title="People signed up for this.">
                                                           <?php echo $formData['amenity_purchased_by_list_a'][$val][$selectorKey]; ?>
                                                        </div>
                                                    <?php endif; ?>
                                                </div>

                                                <?php
                                                if(isset($formData['amenity_qty_selected_a'][$selectorKey])){
                                                    $amenity_qty = $formData['amenity_qty_selected_a'][$selectorKey];
                                                }elseif(isset($formData['amenities_selector_default_qty_a'][$val][$selectorKey])){
                                                    $amenity_qty = $formData['amenities_selector_default_qty_a'][$val][$selectorKey];
                                                }else{
                                                    $amenity_qty = 0;
                                                }
                                                ?>

                                                <?php if($formData['amenities_null_item_a'][$selectorKey] == 0): ?>
                                                    <div class="col-lg-8 amenity-price">

                                                        <?php if((int)$formData['amenities_base_rate_a'][$selectorKey] > 0): ?>
                                                            <?php echo $formData['currency_symbol'].$formData['amenities_base_rate_a'][$selectorKey]; ?>
                                                            <span><strong>x</strong></span>
                                                        <?php endif; ?>

                                                        <?php
                                                        $set_read_only = false;
                                                        if(isset($formData['amenity_type_read_only_a'][$val])):
                                                           if($formData['amenity_type_read_only_a'][$val] == 1):
                                                                $set_read_only = true;
                                                           endif;
                                                        endif;
                                                        ?>

                                                        <?php if($set_read_only): ?>

                                                            <input type="text" class="amenity_disable_qty" size="2" maxlength="2"
                                                                name="" value="<?php echo (isset($formData['amenity_qty_selected_a'][$selectorKey])) ? esc_attr($formData['amenity_qty_selected_a'][$selectorKey]) : 0; ?>" readonly>

                                                        <?php elseif($formData['amenities_multi_qty_a'][$selectorKey] == 0 && isset($formData['amenity_disable_a'][$selectorKey]) && isset($formData['amenity_qty_selected_a'][$selectorKey])): ?>

                                                            <input type="text" class="amenity_disable_qty" size="2" maxlength="2"
                                                                name="" value="<?php echo (isset($formData['amenity_qty_selected_a'][$selectorKey])) ? esc_attr($formData['amenity_qty_selected_a'][$selectorKey]) : 0; ?>" disabled>

                                                        <?php elseif(isset($formData['amenity_disable_a'][$selectorKey]) && !isset($formData['amenity_qty_selected_a'][$selectorKey])): ?>

                                                            <input type="text" class="amenity_disable_qty" size="2" maxlength="2"
                                                                name="" value="<?php echo (isset($formData['amenity_qty_selected_a'][$selectorKey])) ? esc_attr($formData['amenity_qty_selected_a'][$selectorKey]) : 0; ?>" disabled>

                                                        <?php elseif(isset($formData['disable_amenity_type_selectors_a'][$val])): ?>

                                                            <input type="text" class="amenity_disable_qty" size="2" maxlength="2"
                                                                name="" value="<?php echo (isset($formData['amenity_qty_selected_a'][$selectorKey])) ? esc_attr($formData['amenity_qty_selected_a'][$selectorKey]) : 0; ?>" disabled>

                                                        <?php elseif($order_lock == 1): ?>

                                                            <input type="text" class="amenity_disable_qty" size="2" maxlength="2"
                                                                name="" value="<?php echo (isset($formData['amenity_qty_selected_a'][$selectorKey])) ? esc_attr($formData['amenity_qty_selected_a'][$selectorKey]) : 0; ?>" disabled>

                                                        <?php // multi_qty 1 = show qty selector, 0 = default to 1 ?>
                                                        <?php elseif($formData['amenities_multi_qty_a'][$selectorKey] == 1): ?>
                                                            <input id="amenity_qty_<?php echo esc_attr($selectorKey); ?>"
                                                                   class="amenity_qty"
                                                                   size="2"
                                                                   maxlength="2"
                                                                   name="amenity_qty[<?php echo esc_attr($selectorKey); ?>]"
                                                                   type="number"
                                                                   value="<?php echo esc_attr($amenity_qty); ?>">
                                                            <input id="amenity_min_sel_qty_<?php echo esc_attr($selectorKey); ?>" type="hidden" value="<?php echo $formData['amenities_min_sel_qty_a'][$selectorKey] ?>">
                                                            <input id="amenity_max_sel_qty_<?php echo esc_attr($selectorKey); ?>" type="hidden" value="<?php echo $formData['amenities_max_sel_qty_a'][$selectorKey] ?>">

                                                        <?php else: ?>
                                                            <input id="amenity_qty_<?php echo esc_attr($selectorKey); ?>"
                                                                   class="amenity_qty_single"
                                                                   size="2"
                                                                   maxlength="2"
                                                                   name="amenity_qty[<?php echo esc_attr($selectorKey); ?>]"
                                                                   type="number"
                                                                   value="<?php echo $amenity_qty ?>">
                                                            <input id="amenity_min_sel_qty_<?php echo esc_attr($selectorKey); ?>" type="hidden" value="0">
                                                            <input id="amenity_max_sel_qty_<?php echo esc_attr($selectorKey); ?>" type="hidden" value="1">

                                                        <?php endif; ?>
                                                    </div>
                                                <?php else: ?>
                                                    <?php if($formData['amenity_id_amenity_type_a'][$selectorKey] == 6): ?>
                                                        <input name="amenity_qty[<?php echo esc_attr($selectorKey); ?>]" type="hidden" value="1">
                                                    <?php else: ?>
                                                        <!-- div class="col-lg-8 amenity-price-null" -->
                                                            <input name="amenity_qty[<?php echo esc_attr($selectorKey); ?>]" type="hidden" value="1">
                                                        <!-- /div -->
                                                    <?php endif; ?>
                                                <?php endif; ?>
                                                <div class="flex-right-gutter"></div>
                                            </div>

                                            <?php if(1 == 2 && $formData['amenity_id_amenity_type_a'][$selectorKey] == 3): ?>
                                                <div class = "amenity-item-container">
                                                    <div style = "display:<?php echo (isset($formData['amenity_id_selected_a'][$val]) && in_array($selectorKey, $formData['amenity_id_selected_a'][$val])) ? "initial" : "none"; ?>;" id="badge_note_<?php echo esc_attr($selectorKey); ?>" class="badge-note">
                                                        Add your details on the badges page
                                                    </div>
                                                    <div class="flex-right-gutter"></div>
                                                </div>
                                            <?php endif; ?>

                                        <?php endforeach; ?>

                                        <?php if(isset($formData['amenity_type_read_only_a'][$val])): ?>
                                           <?php if($formData['amenity_type_read_only_a'][$val] == 1): ?>
                                           <script type="text/javascript">
                                              jQuery('.amenity_type_selector_<?= esc_attr($val) ?>').click(function(){
                                                return false;
                                              });
                                            </script>
                                           <?php endif; ?>
                                        <?php endif; ?>

                                    </div>
                                </div>
                            </div>

                            <?php if(isset($formData['amenity_comment_labels_a'][$val])): ?>
                                <?php
                                $comment = isset($formData['amenity_comments_a'][$val]) ? esc_textarea($formData['amenity_comments_a'][$val]) : '';
                                $comment_label = isset($formData['amenity_comment_labels_a'][$val]) ? $formData['amenity_comment_labels_a'][$val] : '';
                                ?>
                                <div class = "amenity-comment-container">
                                    <div class="control-desc" for="amenity-types" style="padding-left:6px;">
                                        <?php echo $comment_label; ?>
                                    </div>
                                    <div class = "amenity-item-container" style="padding-left:2px;">
                                        <?php echo "<textarea name='Clients[comment][{$val}]' id='amenity_type_{$val}' class='form-control' style='margin-left:4px;'>{$comment}</textarea>"; ?>
                                    </div>
                                </div>
                            <?php endif; ?>
                            <div style="margin-bottom: 15px;"></div>
                        <?php
                        }
                    }
                }
            }
            ?>

            <?php // endforeach; ?>

            <?php if($this->_count_array($formData['amenities_required_a']) > 0): ?>
                <div class="col-lg-offset-2 col-lg-11" style="margin-bottom:10px;">
                    <span class="red-alert">*</span> = required selection
                </div>
            <?php endif; ?>

            <input type="hidden" id="clients-value-client_profile_key" class="form-control" name="Clients[Value][client_profile_key]" value="<?php echo esc_attr($event_attributes['client_a']['profile_key']); ?>">
            <input type="hidden" id="clients-value-applic_profile_key" class="form-control" name="Clients[Value][applic_profile_key]" value="<?php echo esc_attr($event_attributes['applicant_a']['profile_key']); ?>">
            <input type="hidden" id="clients-value-apply_step3" class="form-control" name="Clients[Value][apply_step3]" value="1">
            <?php
                $form_code = esc_attr($event_attributes['event_a']['form_code']);
                if(isset($_SESSION['ok'])) {
                    $form_code .= "_".$_SESSION['ok'];
                }
            ?>
            <input type="hidden" id="clients-value-event-code" class="form-control" name="Clients[Value][form_code]" value="<?php echo sanitize_text_field($form_code); ?>">

            <?php if(isset($_GET['pk']) && $_GET['pk'] != ''): ?>
                <input type="hidden" name="profile_key" value="<?php echo esc_attr($_GET['pk']); ?>">
            <?php endif; ?>

            <div class="form-group">
                <div class="col-lg-offset-2 col-lg-11">
                    <?php
                    if($this->_count_array($formData['amenities_selector_a']) > 0) {
                        echo '<button type="submit" id="submit-apply" class="btn btn-success-bottom pull-left">'.$this->_button_label_swap('save_continue').' <i style="margin-left:0px;" class="fa fa-chevron-right" aria-hidden="true"></i></button>';
                    }else{
                        echo '<button type="submit" id="submit-apply" class="btn btn-success-bottom pull-left">Next</button>';
                    }
                    ?>
                    <div id="submit-spinner" class="pull-left"></div>
                </div>
            </div>
        </div>
        <?php

        return ($form . $this->_generate_amenities_screen_field(ob_get_clean(), $this->event_attributes));
    }

    /**
     * @param $formData
     * @param $form
     * @return string
     */
    private function _create_extra_screen_fields($formData, $form, $form_attributes_a)
    {
        global $wp;

        $event_attributes = json_decode($this->event_attributes, true);

        $current_url = home_url(add_query_arg([], $wp->request));
        $mt = str_replace('.', '', microtime(true));

        ob_start();

        foreach($formData['am_field_amenity_id_a'] as $amenity_id => $val){
            if(isset($formData['amenity_qty_selected_a'][$amenity_id])) {
                $amenity_field_id_selected_qty_a[$amenity_id] = $formData['amenity_qty_selected_a'][$amenity_id];
            }
        }

        if(isset($_GET['dupflag']) && $_GET['dupflag'] != ''){
            // inject inline styles for badge blocks
            $dup_css_tenpl = '<style>#block-aid-set { border: 2px solid #ffb8b8; background-color: #ffe9e9;}</style>';
            $dup_uri = $_GET['dupflag'];
            $dups_a = explode("_", $dup_uri);
            foreach($dups_a AS $dup_a){
                $dup_block_id_css = $dup_css_tenpl;
                $dup_block_id_css = str_replace('aid-set', $dup_a, $dup_block_id_css);
                echo $dup_block_id_css;
            }
        }

        /*
         *  <input data-inputmask="'mask': '<?php echo $input_data['input_mask']; ?>'" type="tel" id="clients-<?php echo $input_data['model_field']; ?>" class="telephone form-control" name="<?php echo $input_data['model_label']; ?>[<?php echo $input_data['model_field']; ?>]" maxlength="255" value="<?php echo $input_data['value']; ?>" style="max-width: <?php echo $max_width; ?>" <?php echo $required; ?>>
         * */

        $flag_badge_invite = false;

        $d = 0;
        foreach ($amenity_field_id_selected_qty_a AS $amenity_id => $extra_qty) {
            $c = 0;
            ?>

            <?php if($d == 0 && $formData['amenity_badge_am_type_a'][$amenity_id] == 2): ?>
                <div class="col-lg-offset-2 col-lg-11">
                    <div class="well well-sm" style="margin-bottom:10px; margin-top:0px;">
                    <strong>Note:</strong> Badge profile links will be sent out when completed so each person can make changes (if needed).
                    Please make sure to include YOURSELF on the badge list if you require one.
                    <span class="">Partially filled records will be saved.</span>
                    </div>
                </div>
            <?php endif; ?>

            <div style="margin-bottom:10px;">
                <h4 style="font-weight: bold;"><?php echo $formData['amenities_label_a'][$amenity_id] ?></h4>
                <div style="margin-top:4px;"><?php echo $formData['amenities_desc_a'][$amenity_id] ?></div>
            </div>

            <div id="amenities_container">

            <?php
            $d++;

            $amenity_field_id_sorted_a = [];
            foreach ($formData['am_field_amenity_id_a'] AS $amenity_field_id => $amenity_field_id_a) {
                foreach($amenity_field_id_a AS $amenity_field_id => $tmp){
                    if(trim($formData['am_field_order_a'][$amenity_id][$amenity_field_id]) !== '') {
                        $amenity_field_id_sorted_a[$formData['am_field_order_a'][$amenity_id][$amenity_field_id]] = $amenity_field_id;
                    }
                }
            }

            ksort($amenity_field_id_sorted_a);

            // print_r($amenity_field_id_sorted_a); // die;
            // Array ( [1] => 889 [2] => 890 [3] => 891 [4] => 892 )

            while($extra_qty > $c) {
                $c++;
                if(in_array("{$amenity_id}-{$c}", $dups_a)){
                    echo "<h4>Duplicate e-mail found for this badge! Use a different e-mail address.</h4>";
                }
                ?>

                <div id="block-<?= $amenity_id ?>-<?= $c ?>" class="badge_block">

                <div class="amenity-title" style="float: left;">
                <strong><?php echo $formData['amenities_label_a'][$amenity_id] ?> #<?php echo $c ?></strong>
                </div>

                <?php if($formData['amenity_badge_am_type_a'][$amenity_id] == 2): ?>
                    <?php if(isset($formData['amenity_badge_short_url_a'][$amenity_id][$c])): ?>
                        <div style="float:right"><strong>Badge Details Form:</strong> <a target="_blank" href="<?php echo esc_url($formData['amenity_badge_short_url_a'][$amenity_id][$c]) ?>"><?= $formData['amenity_badge_short_url_a'][$amenity_id][$c] ?></a></div>
                    <?php else: ?>
                        <div style="float:right"><strong>Badge Details Form:</strong> <span class="red-alert"><strong>New or Incomplete</strong></span></div>
                    <?php endif; ?>
                <?php endif; ?>

                <?php
                foreach($amenity_field_id_sorted_a AS $amenity_field_id){

                    $max_width = '';
                    $required = $formData['am_field_required_a'][$amenity_id][$amenity_field_id] == 1 ? "required" : "";
                    $req_flag = $formData['am_field_required_a'][$amenity_id][$amenity_field_id] == 1 ? "<span class='red-alert' style='font-size: larger;'>*</span>" : "";
                    $filter_type = '';

                    $selector_a = !empty($formData['am_field_dropdown_a'][$amenity_id][$amenity_field_id]) ? json_decode($formData['am_field_dropdown_a'][$amenity_id][$amenity_field_id]) : [];
                    $value = isset($formData['am_field_data_values_a'][$amenity_id][$c]) ? $formData['am_field_data_values_a'][$amenity_id][$c][$amenity_field_id] : '';

                    $is_phone = $formData['am_field_model_type_a'][$amenity_id][$amenity_field_id] == 'phone' ? true : false;
                    if($is_phone){
                        $value = preg_replace('/[^\d]+/', '', $value);
                        if($value !== ''){
                            $value = '+'.$value;
                        }

                        $input_field_name = "amenity_extra[amenity_field_id_{$amenity_id}-{$amenity_field_id}-{$c}][{$amenity_id}][{$amenity_field_id}]";
                    }
                    ?>

                    <div class="form-group field-clients-name">
                        <label class="col-lg-2 control-label well-label" for="extra-<?php echo $amenity_field_id; ?>-<?php echo $c; ?>"><?php echo $formData['am_field_labels_a'][$amenity_id][$amenity_field_id]; ?><?php echo $req_flag ?></label>
                        <div class="col-lg-8">

                            <!-- div style="float:right"><?php // echo $amenity_field_id; ?></div -->
                            <?php if($this->_count_array($selector_a) > 0): ?>
                                <select id="extra-<?php echo $amenity_field_id; ?>-<?php echo $c; ?>" class="form-control" name="amenity_extra[amenity_field_id_<?php echo $amenity_id ?>-<?php echo $amenity_field_id; ?>-<?php echo $c; ?>][<?php echo $amenity_id ?>][<?php echo $amenity_field_id; ?>]" value="<?php echo $value; ?>" style="width:auto;" <?php echo $filter_type; ?> <?php echo $required; ?>>
                                    <option value="">Select...</option>
                                    <?php
                                    foreach($selector_a as $selector_val) {
                                        ?>
                                        <?php if($value == $selector_val): ?>
                                            <option value="<?php echo $selector_val; ?>" selected><?php echo $selector_val; ?></option>
                                        <?php else: ?>
                                            <option value="<?php echo $selector_val; ?>"><?php echo $selector_val; ?></option>
                                        <?php endif; ?>
                                    <?php
                                    }
                                    ?>
                                </select>
                            <?php else: ?>
                                <?php if($is_phone): ?>
                                    <input type="tel" id="extra-<?php echo $amenity_field_id; ?>-<?php echo $c; ?>" class="telephone form-control" name="amenity_extra[amenity_field_id_<?php echo $amenity_id ?>-<?php echo $amenity_field_id; ?>-<?php echo $c; ?>][<?php echo $amenity_id ?>][<?php echo $amenity_field_id; ?>]" maxlength="255" value="<?php echo $value; ?>" style="<?php echo $max_width; ?>" <?php echo $filter_type; ?> <?php echo $required; ?>>
                                <?php else: ?>
                                    <input type="text" id="extra-<?php echo $amenity_field_id; ?>-<?php echo $c; ?>" class="form-control" name="amenity_extra[amenity_field_id_<?php echo $amenity_id ?>-<?php echo $amenity_field_id; ?>-<?php echo $c; ?>][<?php echo $amenity_id ?>][<?php echo $amenity_field_id; ?>]" maxlength="255" value="<?php echo $value; ?>" style="<?php echo $max_width; ?>" <?php echo $filter_type; ?> <?php echo $required; ?>>
                                <?php endif; ?>
                            <?php endif; ?>
                        </div>
                    </div>

                    <?php if($is_phone): ?>

                        <?php
                        $input_preferred_countries_a = [];
                        if(!empty($form_attributes_a['event_a']['phone_code_default'])){
                            $input_preferred_countries_a[] = strtolower($form_attributes_a['event_a']['phone_code_default']);
                        }else{
                            $input_preferred_countries_a = ['us'];
                        }
                        ?>

                        <script type="text/javascript">
                            var $ = jQuery.noConflict();

                            $(document).ready(function ($) {
                                var input = document.querySelector("#extra-<?php echo $amenity_field_id; ?>-<?php echo $c; ?>");
                                window.intlTelInput(input, {
                                  // allowDropdown: false,
                                  // autoHideDialCode: false,
                                  // autoPlaceholder: "off",
                                  // dropdownContainer: document.body,
                                  // excludeCountries: ["us"],
                                  // formatOnDisplay: false,
                                  // geoIpLookup: function(callback) {
                                  //   $.get("http://ipinfo.io", function() {}, "jsonp").always(function(resp) {
                                  //     var countryCode = (resp && resp.country) ? resp.country : "";
                                  //     callback(countryCode);
                                  //   });
                                  // },
                                  hiddenInput: "<?php echo $input_field_name ?>",
                                  // initialCountry: "auto",
                                  // localizedCountries: { 'de': 'Deutschland' },
                                  // nationalMode: false,
                                  // onlyCountries: ['us', 'gb', 'ch', 'ca', 'do'],
                                  // placeholderNumberType: "MOBILE",
                                  preferredCountries: [<?php echo '"'.implode('","', $input_preferred_countries_a).'"' ?>],
                                  // preferredCountries: ['cn', 'jp'],
                                  // separateDialCode: true,
                                  // utilsScript: "build/js/utils.js",
                                });
                            });
                        </script>
                    <?php endif; ?>
                <?php
                }

                //////////////////////////////////
                // insert custom badge fields here
                $applic_badge_fields_a = $formData['applic_badge_fields_a'];

                foreach($applic_badge_fields_a AS $applic_field_id => $profile_field_id){

                    if (isset($formData['profile_badge_field_options_sorted_a'][$profile_field_id])) {
                        $input_data['option_values_a'] = $formData['profile_badge_field_options_sorted_a'][$profile_field_id];
                    }

                    $input_data['field_type'] = $formData['profile_badge_field_type_a'][$profile_field_id];
                    $input_data['field_label'] = $formData['profile_badge_field_label_a'][$profile_field_id];
                    $input_data['model_field'] = $formData['profile_badge_field_model_field_a'][$profile_field_id];
                    $input_data['model_label'] = $formData['profile_badge_field_model_label_a'][$profile_field_id];
                    $input_data['badge_dataset'] = $c;
                    $input_data['amenity_id'] = $amenity_id;

                    $input_data['value'] = '';
                    if(isset($formData['applicant_field_data_a'][$c.'-'.$profile_field_id.'-'.$amenity_id])){
                        $input_data['value'] = $formData['applicant_field_data_a'][$c.'-'.$profile_field_id.'-'.$amenity_id];
                    }

                    // model_field
                    // $input_data['value'] = '';
/*
                    echo "<pre>";
                    echo "applic_field_id: {$applic_field_id}, profile_field_id: {$profile_field_id}, amenity_id: {$amenity_id}
";
                    print_r($input_data);
                    echo "</pre>";
*/

                    echo $this->_generate_input_field($input_data['field_type'], $input_data);
                }

                echo '</div><!-- END badge_block -->';
            }
            echo '</div><!-- END amenities_container -->';
        }
        ?>

        <?php if($flag_badge_invite): ?>
            <div class="col-lg-offset-2 col-lg-11">
                <div class="well well-sm" style="margin-bottom:10px; margin-top:0px;">
                    <strong>Note:</strong> Badge profile links will be sent out when completed so each person can make changes (if needed).
                    Please make sure to include YOURSELF on the badge list if you require one.
                    <span class="">Partially filled records will be saved.</span>
                </div>
            </div>
        <?php endif; ?>

        <div id="amenities_container">

            <input type="hidden" id="clients-value-client_profile_key" class="form-control" name="Clients[Value][client_profile_key]" value="<?php echo esc_attr($event_attributes['client_a']['profile_key']); ?>">
            <input type="hidden" id="clients-value-applic_profile_key" class="form-control" name="Clients[Value][applic_profile_key]" value="<?php echo esc_attr($event_attributes['applicant_a']['profile_key']); ?>">
            <input type="hidden" id="clients-value-apply_step3" class="form-control" name="Clients[Value][apply_step3]" value="1">
            <?php
                $form_code = esc_attr($event_attributes['event_a']['form_code']);
                if(isset($_SESSION['ok'])) {
                    $form_code .= "_".$_SESSION['ok'];
                }
            ?>
            <input type="hidden" id="clients-value-event-code" class="form-control" name="Clients[Value][form_code]" value="<?php echo esc_attr($form_code); ?>">

            <?php if(isset($_GET['pk']) && $_GET['pk'] != ''): ?>
                <input type="hidden" name="profile_key" value="<?php echo esc_attr($_GET['pk']); ?>">
            <?php endif; ?>

            <div class="form-group">
                <div class="col-lg-offset-2 col-lg-11">

                    <?php
                    if($this->_count_array($formData['amenities_selector_a']) > 0) {
                        // echo 'Note: Partially filled records will be saved but not used to created profiles.';
                        echo '<button type="submit" id="submit-apply" class="btn btn-success-bottom pull-left">'.$this->_button_label_swap('save_continue').' <i style="margin-left:0px;" class="fa fa-chevron-right" aria-hidden="true"></i></button>';

                    }else{
                        echo '<button type="submit" id="submit-apply" class="btn btn-success-bottom pull-left">Next</button>';
                    }
                    ?>
                    <div id="submit-spinner" class="pull-left"></div>
                </div>
            </div>
        </div>

        <script type="text/javascript">
            /* remember field data and return on duplicate email catch */
            var $ = jQuery.noConflict();

            $(document).on("change", ".form-control", e => {
              if (!e.target.id) return;
              localStorage.setItem(e.target.id, $(e.target).val());
            });

            <?php if(isset($dup_block_id_css)): ?>
            $(() => $(".form-control").each(function() {
              if (!this.id) return;
              let val = localStorage.getItem(this.id);
              if (val) $(this).val(val);
            }));
            <?php endif; ?>
        </script>
        <?php

        return ($form . $this->_generate_amenities_screen_field(ob_get_clean(), $this->event_attributes));
        }

        /**
         * @param $formData
         * @param $form
         * @return string
         */
        private function _create_uploads_screen_fields($formData, $form)
        {
            $event_attributes = json_decode($this->event_attributes, true);
            ob_start();

            $upload_max_filesize = $this->_get_php_limits()["upload_max_filesize"];
            $upload_max_filesize_raw = floatval($upload_max_filesize);

            if($this->_count_array($formData['missed_docs_exist_a']) > 0){
                echo '<div class="red-alert">';
                echo $this->_count_array($formData['missed_docs_exist_a']) == 1 ? "1 required file missing." : $this->_count_array($formData['missed_docs_exist_a'])." required files missing.";
                echo '</div>';
            }

            $formData['lic_id_field_label_a'] = isset($formData['lic_id_field_label_a']) ? $formData['lic_id_field_label_a'] : [];

            foreach($formData['lic_id_field_label_a'] as $val):
                $current_field_key = explode("_", $val);
                $current_field_key = (int)end($current_field_key);

                $event_doc_id = isset($formData['client_lic_event_doc_id_a'][$current_field_key]) ? (int)$formData['client_lic_event_doc_id_a'][$current_field_key] : '';

                $doc_filename = isset($formData['event_docs_filename_a'][$event_doc_id]) ? esc_attr($formData['event_docs_filename_a'][$event_doc_id]) : false;
                $doc_key_url = isset($formData['event_doc_key_a'][$event_doc_id]) ? esc_attr($formData['event_doc_key_a'][$event_doc_id]) : false;

                if($formData['client_lic_doctype_a'][$current_field_key] == 1) {
                    $allowedFileExtensions = ['doc', 'pdf', 'docx', 'ppt'];

                }elseif($formData['client_lic_doctype_a'][$current_field_key] == 2){
                    $allowedFileExtensions = ['png', 'gif', 'jpg', 'jpeg'];

                }elseif($formData['client_lic_doctype_a'][$current_field_key] == 3){
                    $allowedFileExtensions = ['png', 'gif', 'jpg', 'jpeg', 'doc', 'pdf', 'docx', 'ppt'];
                }

                // get file upload limits //
                list($fsize_min, $fsize_max) = explode(":",$formData['client_lic_size_minmax_a'][$current_field_key]);
                $fsize_min = $fsize_min * 1024;

                if($fsize_max > 0 && ($fsize_max * 1024 <= $upload_max_filesize_raw * 1024)){
                    $fsize_max = $fsize_max * 1024;
                }else{
                    $fsize_max = $upload_max_filesize_raw * 1024;
                }

                $file_size_notice_a = [];
                $parsley_min_file_size = $parsley_max_file_size = '';

                if($fsize_min > 0){
                    $file_size_notice_a[] .= "Minimum ". $this->byte2Size($fsize_min);
                    $parsley_min_file_size = ' data-parsley-min-file-size="'.$fsize_min.'"';
                }

                if($fsize_max > 0){
                    $file_size_notice_a[] .= "Maximum ". $this->byte2Size($fsize_max);
                    $parsley_max_file_size = ' data-parsley-max-file-size="'.$fsize_max.'"';
                }

                ?>
                <div class="form-group field-dynamicmodel-<?php echo sanitize_text_field($val); ?> widget-box file-upload-container">
                    <div class="widget-header">
                        <?php
                        if($doc_filename) {
                            ?>
                            <button title="<?php echo $this->_button_label_swap('download') ?> <?php echo $doc_filename; ?>" type="button" id="doc_download_<?php echo $doc_key_url; ?>" class="tooltip btn btn-form-download" href="<?php echo esc_url(sanitize_url($this->base_site_url . "/events/download?dk=". $doc_key_url)) ?>">
                                <i class="fa fa-arrow-down" aria-hidden="true"></i> <?php echo $this->_button_label_swap('download') ?>
                            </button>
                            <?php
                        }
                        ?>
                        <div class="widget-title">
                            <h3><?php echo sanitize_text_field($formData['client_lic_label_a'][$current_field_key]); ?></h3>
                        </div>
                        <div class="widget-subtitle">
                            <?php echo sanitize_text_field($formData['client_lic_desc_a'][$current_field_key]); ?>
                        </div>
                    </div>

                    <div class="widget-body">
                        <div class="widget-main">

                            <?php if(isset($formData['client_lic_thumb_a'][$current_field_key])) : ?>
                                <div class="doc-thumb">
                                    <img src="<?php echo $formData['client_lic_thumb_a'][$current_field_key] ?>">
                                </div>
                            <?php endif; ?>

                            <input type="hidden" name="DynamicModel[<?php echo esc_attr($val); ?>]">

                            <input
                            type="file"
                            name="DynamicModel[<?php echo esc_attr($val); ?>]"
                            id="dynamicmodel-<?php echo esc_attr($val); ?>"
                            <?php echo $parsley_min_file_size ?>
                            <?php echo $parsley_max_file_size ?>
                            data-parsley-errors-container="#error-box-<?php echo esc_attr($val); ?>"
                            class="file-loading">

                            <div class="" id="error-box-<?php echo esc_attr($val); ?>"></div>

                            <script type="text/javascript">
                                var $ = jQuery.noConflict();

                                $(document).ready(function ($) {
                                    <?php if($fsize_min > 0): ?>
                                        window.Parsley.addValidator('minFileSize', {
                                            validateString: function(_value, minSize, parsleyInstance) {
                                                if (!window.FormData) {
                                                    alert('Your browser is too old to run this form properly');
                                                    return true;
                                                }
                                                var files = parsleyInstance.$element[0].files;

                                                  if (files.length == 0) {
                                                    // No file, so valid. (Required check should ensure file is selected)
                                                    return true;
                                                  }

                                                return files.length != 1 || files[0].size >= minSize * 1024;
                                            },
                                            requirementType: 'integer',
                                            messages: {
                                                en: '<i class="fa fa-lg fa-times"></i> Error: File too small. See minimum file size.',
                                            }
                                        });
                                    <?php endif; ?>

                                    window.Parsley.addValidator('maxFileSize', {
                                        validateString: function(_value, maxSize, parsleyInstance) {
                                            if (!window.FormData) {
                                                alert('Your browser is too old to run this form properly');
                                                return true;
                                            }
                                            var files = parsleyInstance.$element[0].files;

                                              if (files.length == 0) {
                                                // No file, so valid. (Required check should ensure file is selected)
                                                return true;
                                              }
                                            return files.length != 1 || files[0].size <= maxSize * 1024;
                                        },
                                        requirementType: 'integer',
                                        messages: {
                                            en: '<i class="fa fa-lg fa-times"></i> Error: File too large. See maximum file size.',
                                        }
                                    });
                                });
                            </script>

                            <div>
                                <p class="help-block-uploads">
                                    <strong>File types</strong>:
                                    <?php
                                    echo implode(", ",$allowedFileExtensions);
                                    ?>.
                                    <strong>File Size:</strong>
                                    <?= implode(", ", $file_size_notice_a); ?>
                                </p>
                                <div class="doc-status">
                                    <?php if(!in_array($current_field_key, $formData['lic_id_missing_a'])): ?>
                                        <?php echo $this->_uploaded_file_status($current_field_key, $formData); ?>

                                        <?php if(isset($formData['lic_id_notes_a'][$current_field_key])): ?>
                                            <div class="well well-sm" style="margin-bottom:10px; margin-top:10px;">
                                                <i style="float:left; margin-right:10px;" class="fa fa-2x fa-exclamation-triangle red" aria-hidden="true"></i>
                                                <?php echo $formData['lic_id_notes_a'][$current_field_key] ?>
                                            </div>
                                        <?php endif; ?>

                                    <?php else: ?>
                                        <span style="font-size: 17px;" class="red-alert">
                                            <i class="fa fa-times"></i>
                                        </span>
                                        Not uploaded yet.
                                        <?php if(in_array($current_field_key,$formData['lic_id_required_a'])): ?>
                                            <span class="red-alert"><strong>(Required)</strong></span>
                                        <?php endif; ?>
                                    <?php endif; ?>
                                </div>
                            </div>

                            <?php if($event_attributes['event_a']['rec_type'] == 2): ?>
                                <table style="width: 100%;" class="table table-striped table-bordered detail-view">
                                    <tbody>
                                    <tr>
                                        <th style="white-space: nowrap; width:80px;">Title</th>
                                        <td style="text-align: left;">
                                            <input type="text" name="DynamicModel[meta][lic_title_<?php echo $current_field_key; ?>]" id="dynamicmodel-lic_title_<?php echo $current_field_key; ?>" class="form-control" maxlength="100" value="<?php echo $formData['client_docs_meta_a'][$current_field_key]['title']; ?>">
                                        </td>
                                    </tr>
                                    <tr>
                                        <th style="white-space: nowrap;">Description</th>
                                        <td style="text-align: left;">
                                            <textarea name="DynamicModel[meta][lic_desc_<?php echo $current_field_key; ?>]" id="dynamicmodel-lic_desc_<?php echo $current_field_key; ?>" class="form-control"><?= esc_textarea($formData['client_docs_meta_a'][$current_field_key]['description']); ?></textarea>
                                        </td>
                                    </tr>
                                    </tbody>
                                </table>
                            <?php endif; ?>

                        </div><!-- /.widget-main -->
                    </div><!-- /.widget-body -->
                </div><!-- /.widget-box -->

            <?php
                //
            endforeach;
            ?>

            <input type="hidden" name="form_code"
                   value="<?php echo isset($event_attributes['event_a']['form_code']) ? esc_attr($event_attributes['event_a']['form_code']) : ''; ?>">

            <!-- input type="hidden" id="dynamicmodel-value-client_profile_key" class="form-control"
                   name="DynamicModel[Value][client_profile_key]"
                   value="<?php // echo isset($_GET['pk']) ? sanitize_text_field($_GET['pk']) : ''; ?>" -->

            <input type="hidden" id="dynamicmodel-value-applic_profile_key" class="form-control"
                   name="DynamicModel[Value][applic_profile_key]"
                   value="<?php echo isset($_GET['pk']) ? esc_attr($_GET['pk']) : ''; ?>">

            <input type="hidden" id="dynamicmodel-value-apply_step2" class="form-control"
                   name="DynamicModel[Value][apply_step2]" value="1">

            <?php

            if($this->_count_array($formData['lic_id_field_label_a']) == 0){
                ?>
                <h4>No Uploads Required.</h4>
                <div class="form-group">
                    <div class="col-lg-offset-2 col-lg-11">
                        <button type="submit" class="btn btn-success-bottom pull-left">Continue <i style="margin-left:0px;" class="fa fa-chevron-right" aria-hidden="true"></i></button>
                    </div>
                </div>

            <?php
            }else{
                echo '<div class="well well-sm" style="margin-bottom:10px; margin-top:0px;">
                <i style="float:left; margin-right:10px;" class="fa fa-2x fa-exclamation-circle blue" aria-hidden="true"></i>
                Before uploading, please make sure your files are <strong>no larger than '.str_replace('M',' Megs',$this->_get_php_limits()["upload_max_filesize"]).'
                each.</strong>. Also see: <a href="https://www.google.com/search?num=10&q=how+to+resize+image+files" target="_blank">How to resize images</a></div>';
                ?>

                <div class="form-group">
                    <div class="col-lg-offset-2 col-lg-11">
                        <button type="submit" class="btn btn-success-bottom pull-left"><?php echo $this->_button_label_swap('upload_docs') ?></button>
                        <button type="submit" class="btn btn-info pull-left" style="margin-left: 6px;" id="upload_get_skip_url"><?php echo $this->_button_label_swap('skip') ?>
                        </button>
                        <div id="submit-uploading" class="pull-left"></div>
                        <div id="submit-spinner" class="pull-left"></div>
                        <div class="hidden">
                            <a href="<?php echo esc_url(sanitize_url($this->_get_skip_url(["uploads" => '', "pk" => sanitize_text_field($_GET['pk'])]))); ?>"
                               id="skipFilesUpload"></a>
                        </div>
                    </div>
                </div>
            <?php
            }

            return ($form . $this->_generate_uploads_screen_field(ob_get_clean(), $this->event_attributes));
        }

        /**
         * @param $formData
         * @param $form
         * @return string
         */
        private function _create_error_screen($formData, $form)
        {
            // redirect to root of form on 404
            if($formData['code'] == 0 && $formData['status'] == 404){

                if(isset($_SESSION["pk"]) && isset($_SESSION["current_screen"])){
                    $screen = !empty($_SESSION["current_screen"]) ? $_SESSION["current_screen"] : 'profile';
                    $redirect_url = "//" . $_SERVER['HTTP_HOST'] . strtok($_SERVER["REQUEST_URI"], '?') . "?".$screen."&pk=".$_SESSION["pk"];

                }else{
                    $redirect_url = "//" . $_SERVER['HTTP_HOST'] . strtok($_SERVER["REQUEST_URI"], '?') . "?clearsession";
                }

                wp_redirect($redirect_url);
                exit();
            }

            ob_start();
            ?>

            <div class="form-group">
                <div class="col-lg-offset-2 col-lg-11">
                    <div style="font-size: larger; text-align: center;">
                        <?php if(sanitize_text_field($_GET['status']) == '410' || sanitize_text_field($_GET['status']) == '411'): ?>
                            <img style="width: 200px; height: 183px;"
                                 src="<?php echo WAVENAMI_WORDPRESS_CLIENT_URL; ?>/front-end/assets/img/magnifying-glass.png"
                                 alt="broken">
                            <!-- see: https://pixabay.com/en/magnifying-glass-lense-loupe-97635/ -->
                        <?php else: ?>
                            <img style="width: 192px; height: 300px;"
                                 src="<?php echo WAVENAMI_WORDPRESS_CLIENT_URL; ?>/front-end/assets/img/broken-roger.png"
                                 alt="broken">
                        <?php endif; ?>
                        <br>
                        <?php
                        if(sanitize_text_field($_GET['status']) == '409') {
                            echo "<h3><span class='red-alert'>Your email has already been used for this event application.</span></h3><br>
                        <strong>I just sent you a message with your existing application profile link.</strong><br>
                        <strong>Please check your email or phone now for the application profile link, or
                        <a href='https://app.wavenami.com/signup' target='_blank' style='font-size: 14px; margin-bottom: 4px;' class='btn-nav btn-blue'>create an account</a>
                        on Wavenami to manage all your applications in one place.</strong><br>";

                            echo "Status Code: ".sanitize_text_field($_GET['status']);

                        }elseif(sanitize_text_field($_GET['status']) == '410') {
                            echo "<h2><span class='green-alert'>Your application profile has been found!</span></h2>
                        <strong>I just sent you a message with your existing application link.</strong><br>
                        <strong>Please check your email or phone now, or
                        <a href='https://app.wavenami.com/signup' target='_blank' style='font-size: 14px; margin-bottom: 4px;' class='btn-nav btn-blue'>create an account</a>
                        on Wavenami to manage all your applications in one place.</strong><br>";

                            echo "Status Code: ".sanitize_text_field($_GET['status']);

                        }elseif(sanitize_text_field($_GET['status']) == '411') {
                            echo "<h2><span class='red-alert'>Your application profile was not found with this email!</span></h2>
                        <strong>If you did fill out an application already, maybe you registered with a different email address.</strong><br>
                        <strong>Please check your email for the original application profile link, or
                        <a href='https://app.wavenami.com/signup' target='_blank' style='font-size: 14px; margin-bottom: 4px;' class='btn-nav btn-blue'>create an account</a>
                        on Wavenami to manage all your applications in one place.</strong><br>";

                            echo "Status Code: ".sanitize_text_field($_GET['status']);

                        }elseif($formData['code'] == 0 && $formData['status'] == 404) {
                            echo "I couldn't find this application profile.<br>Please check the URL and make sure it's complete and not missing anything!<br>";
                            echo "Status Code: {$formData['status']}";

                        }elseif($formData['code'] == 0 && $formData['status'] == 503) {
                            echo "Application is currently down for maintenance.<br>Please try again at a later time and thank you for your patience.<br>";
                            echo "Status Code: {$formData['status']}";

                        }elseif($formData['code'] == 0 && $formData['status'] == 402) {
                            echo "This application form is currently in test mode.<br>Please check back later to apply.<br>";
                            echo "Status Code: {$formData['status']}";

                        }elseif($formData['code'] == 0 && $formData['status'] == 403) {
                            echo "API access has NOT been granted to you yet.<br>Please contact support@wavenami.com to enable this (it's free).<br>";
                            echo "Status Code: {$formData['status']}";

                        }elseif($formData['code'] == 0 && $formData['status'] == 401) {
                            echo "<strong>Please login before continuing</strong><br>";
                            echo "Status Code: {$formData['status']}";

                        }elseif($formData['code'] == 0 && $formData['status'] == 405) {
                            echo "<h3><span style='color:red'>Application Closed</span></h3>
                            This form is no longer accepting new applications.<br>";
                            echo "Status Code: {$formData['status']}";

                        }elseif($formData['code'] == 407) {
                            echo "<h3><span style='color:red'>Missing Privacy Policy</span></h3>
                            This form is missing an important privacy policy link in the event setup and cannot continue.<br>Please contact the event organizer.<br>";
                            echo "Status Code: {$formData['status']}";

                        }else{
                            echo "Sorry, an error has occurred.<br>";
                        }
                        ?>
                        <div style="margin-top:10px; margin-bottom:20px">
                        <a title="Continue" type="button" id="error_continue" class="btn btn-error" href="<?php echo esc_url(sanitize_url($this->_get_base_url())) ?>">
                            Continue
                        </a>
                        </div>
                    </div>
                </div>
            </div>

            <?php

            return $form . ob_get_clean();
        }

        /**
         * @param $formData
         * @param $form
         * @return string
         */
        private function _create_login_screen_fields($formData, $form, $audit = 0, $ref = '')
        {
            global $wp;

            $client_a = isset($formData['client_a']) ? $formData['client_a'] : [];

            if($client_a["client_id"] == '1056'){
                // print_r($client_a); die;
            }

            $event_a = $formData['event_a'];
            $pre_launch_count = $formData['pre_launch_count'];

            $selector_fields = ['dropdown','radio','checkboxes'];

            $redirect_url = home_url($wp->request) . "/";
            $register_url = $redirect_url . "?register";
            $register_url .= $ref != '' ? "&ref=". sanitize_text_field($ref) : "";

            ob_start();

            $button = "<button type='button' id='' class='btn btn-form-register' href='{$register_url}'>
                Create Account
            </button>";

            $reset_password_url = $redirect_url.'?passreset';

            $current_url = $_SERVER['REQUEST_URI']; // home_url(add_query_arg([], $wp->request));
            $logout_flag = false;
            if(stristr($current_url,'/?logout')){
                $logout_flag = true;
            }
            ?>

            <?php if($event_a['rsvp_form_host_id'] > 0): ?>
                <?php if(!isset($_SESSION['ok']) && !isset($_GET['ok']) && !$logout_flag): ?>
                    <div class="well-warning form-group-top-error field-clients-value-apply_step1">
                        <div class="col-lg-8">
                            <div class='red-alert'><h4>Origin Key not found for NEW profiles. Please check form URL.</h4></div>
                            <h5>The form URL should end with /?ok=12345 (example).</h5>
                            <div style="margin-top:20px;"><h5>If you ALREADY created a profile, click Login to continue.</h5></div>
                        </div>
                    </div>
                <?php endif; ?>
            <?php endif; ?>

            <?php
            if(isset($_GET['res'])): ?>
                <div class="form-group-top-error field-clients-value-apply_step1">
                    <div class="col-lg-8">
                    <?php if($_GET['res'] == 403): ?>
                        <div class='red-alert'><h4>Password NOT created yet.</h4></div>
                        <h5>To create a password, click 'reset password' to create one.</h5>
                    <?php elseif($_GET['res'] == 402): ?>
                        <div class='red-alert'><h4>Account email not found.</h4></div>
                        <h5>If your email is not found, you probably need to create an account.</h5>
                    <?php elseif($_GET['res'] == 401): ?>
                        <div class='red-alert'><h4>Incorrect password.</h4></div>
                        <h5>You can try again, or click 'reset password' to change it.</h5>
                    <?php endif; ?>
                    </div>
                </div>

            <?php elseif(isset($_GET['cpk'])): ?>
                <div class="form-group-top-error field-clients-value-apply_step1">
                    <div class="col-lg-8">
                        <div class='green-alert'><h4>Account login already exists.</h4></div>
                    </div>
                </div>

            <?php elseif(isset($_GET['pr'])): ?>
                <?php if($_GET['pr'] == 0): ?>
                    <div class="form-group-top-error field-clients-value-apply_step1">
                        <div class="col-lg-8">
                            <div class='red-alert'><h4>Password reset failed or account not found.</h4></div>
                        </div>
                    </div>
                <?php elseif($_GET['pr'] == 1): ?>
                    <div class="form-group-top-success field-clients-value-apply_step1">
                        <div class="col-lg-8">
                            <div class='green-alert'><h4>Password has been reset.</h4></div>
                        </div>
                    </div>
                <?php endif; ?>
            <?php endif; ?>

            <?php
            $input_data = '';
            if(isset($formData['login_field_data_a'])) {

                foreach ($formData['login_field_data_a'] AS $input_data) {

                    if (isset($input_data['field_type'])) {

                        if (in_array($input_data['field_type'], $selector_fields)) {
                            $input_data['option_values_a'] = json_decode($input_data['option_values_a'], true);
                        }

                        // hide applic type or badge sub-form
                        if($input_data['model_field'] == 'client_types_a' || $input_data['model_field'] == 'com_prefs'){
                            continue;
                        }

                        if(isset($formData['client_a'])){
                            if(isset($formData['client_a'][$input_data['model_field']])){
                                $input_data['value'] = $formData['client_a'][$input_data['model_field']];
                            }
                        }

                        // stuff country code into input data
                        $input_data['input_default_country_code'] = $formData['event_a']['phone_code_default'];

                        $field = $this->_generate_input_field($input_data['field_type'], $input_data, $audit);

                        $field = str_replace("%button%", $button, $field);
                        $field = str_replace("_reset_password_url_", $reset_password_url, $field);
                        $field = str_replace("group-hover-disabled", 'login-fields', $field);
                        $field = str_replace("help-block", 'help-block-login', $field);
                        $field = str_replace("form-group", 'form-group-login', $field);

                        echo $field;
                    }
                }
            }
            ?>

            <div class="form-group field-clients-value-apply_step1">
                <div class="col-lg-8">
                    <input type="hidden" id="clients-value-apply_step1" class="form-control" name="Clients[Value][apply_step1]" value="1">
                </div>
            </div>

            <div class="col-lg-offset-2 col-lg-11" style="margin-bottom:10px; margin-left:10px;">
                <span class="red-alert">*</span> = required field
            </div>

            <div class="form-group">
                <div class="col-lg-offset-2 col-lg-11">
                    <button type="submit" id="submit-apply" class="btn btn-success pull-left">
                        Login <i style="margin-left:0px;" class="fa fa-chevron-right" aria-hidden="true"></i>
                    </button>
                    <div id="submit-spinner" class="pull-left"></div>
                </div>
            </div>

            <?php if(isset($hidden_input_client_type)): ?>
                <?php echo $hidden_input_client_type; ?>
            <?php endif; ?>

            <?php if(isset( $formData['login_redirect']) && $formData['login_redirect'] != ''): ?>
                <input type="hidden" name="login_redirect" value="<?= esc_attr($formData['login_redirect']) ?>">
            <?php endif; ?>

            <?php if(isset($ref) && $ref != ''): ?>
                <input type="hidden" name="redirect" value="<?= esc_attr($ref) ?>">
            <?php endif; ?>

            <?php if(isset( $_GET['return']) && $_GET['return'] != ''): ?>
                <input type="hidden" name="return_vendor" value="<?= (int)$_GET['return'] ?>">
            <?php endif; ?>

            <?php if(isset($event_a['form_code']) && $event_a['form_code'] != ''): ?>
                <?php
                    $form_code = esc_attr($event_a['form_code']);
                    if(isset($_SESSION['ok'])) {
                        $form_code .= "_".$_SESSION['ok'];
                    }
                ?>
                <input type="hidden" name="form_code" value="<?php echo sanitize_text_field($form_code); ?>">
            <?php endif; ?>

            <?php if(isset( $_GET['rfc']) && $_GET['rfc'] != ''): ?>
                <input type="hidden" name="rfc" value="<?php echo esc_attr($_GET['rfc']); ?>">
            <?php endif; ?>

            <?php if(isset( $_GET['rpk']) && $_GET['rpk'] != ''): ?>
                <input type="hidden" name="rpk" value="<?php echo esc_attr($_GET['rpk']); ?>">
            <?php endif; ?>

            <?php
            return ($form . $this->_generate_login_screen_field(ob_get_clean(), $client_a, $event_a, $pre_launch_count));
        }

        /**
         * @param $formData
         * @param $form
         * @return string
         */
        private function _create_register_screen_fields($formData, $form)
        {
            global $wp;

            $client_a = isset($formData['client_a']) ? $formData['client_a'] : [];
            $event_a = $formData['event_a'];
            $pre_launch_count = $formData['pre_launch_count'];

            // field types (from profile_fields::field_type) that are stored in json_encoded array (in applicant_field_data::text_long)
            $selector_fields = ['dropdown','radio','checkboxes'];

            $redirect_url = home_url($wp->request) . "/";

            ob_start();

            $button = '<button type="button" id="" class="btn btn-form-register" href="'.$redirect_url.'?login">
                Login
            </button>';

            if(isset($_GET['pr'])): ?>
                <?php if($_GET['pr'] == 0): ?>
                    <div class="form-group-top-error field-clients-value-apply_step1">
                        <div class="col-lg-8">
                            <div class='red-alert'><h4>Code verify failed. Please check and re-enter.</h4></div>
                        </div>
                    </div>
                <?php endif; ?>
            <?php endif;

            if(isset($_GET['dup'])): ?>
                <?php if($_GET['dup'] == 1): ?>
                    <div class="form-group-top-error field-clients-value-apply_step1">
                        <div class="col-lg-8">
                            <div class='red-alert'><h4>Duplicate email found. You only have to register once.</h4></div>
                            <h5>You can try a password reset if you have forgotten your password.</h5>
                        </div>
                    </div>
                <?php endif; ?>
            <?php endif;

            // print_r($formData); die;

            $input_data = '';
            if(isset($formData['profile_field_data_a'])) {

                foreach ($formData['profile_field_data_a'] AS $input_data) {
                    if (isset($input_data['field_type'])) {

                        if (in_array($input_data['field_type'], $selector_fields)) {
                            $input_data['option_values_a'] = json_decode($input_data['option_values_a'], true);
                        }

                        // hide applic type or badge sub-form
                        if($input_data['model_field'] == 'client_types_a' || $input_data['model_field'] == 'com_prefs'){
                            continue;
                        }

                        if(isset($formData['client_a'])){
                            if(isset($formData['client_a'][$input_data['model_field']])){
                                $input_data['value'] = $formData['client_a'][$input_data['model_field']];
                            }
                        }

                        // stuff country code into input data
                        $input_data['input_default_country_code'] = $formData['event_a']['phone_code_default'];

                        $field = $this->_generate_input_field($input_data['field_type'], $input_data);

                        $send_targets = '';
                        if(!empty($formData['client_a']['email'])){
                            $send_targets = $formData['client_a']['email'];
                        }

                        if(!empty($formData['client_a']['phone'])){
                            $phone = self::_formatPhoneNumber($formData['client_a']['phone'], true);
                            // $phone = 'your cell #';
                            $send_targets = !empty($send_targets) ? $send_targets . ' and ' . $phone : $phone;
                        }

                        $field = str_replace("%send_targets%", $send_targets, $field);
                        $field = str_replace("%button%", $button, $field);

                        echo $field;
                    }
                }
            }

            if($formData['mode'] == 'passcreate') {
                $button_label = 'Finish';
            }elseif($formData['mode'] == 'regconfirm') {
                $button_label = 'Confirm';
            }else{
                $button_label = 'Continue';
            }
            ?>

            <div class="form-group field-clients-value-apply_step1">
                <div class="col-lg-8">
                    <input type="hidden" id="clients-value-apply_step1" class="form-control" name="Clients[Value][apply_step1]" value="1">
                </div>
            </div>

            <?php if($formData['mode'] != 'regconfirm'): ?>
                <div class="col-lg-offset-2 col-lg-11" style="margin-bottom:10px; margin-left:10px;">
                    <span class="red-alert">*</span> = required field
                </div>
            <?php endif; ?>

            <div class="form-group">
                <div class="col-lg-offset-2 col-lg-11">
                    <button type="submit" id="submit-apply" class="btn btn-success pull-left">
                        <?php echo $button_label ?> <i style="margin-left:0px;" class="fa fa-chevron-right" aria-hidden="true"></i>
                    </button>
                    <div id="submit-spinner" class="pull-left"></div>
                </div>
            </div>

            <?php if(isset($hidden_input_client_type)): ?>
                <?php echo $hidden_input_client_type; ?>
            <?php endif; ?>

            <?php if(isset( $_GET['return']) && $_GET['return'] != ''): ?>
                <input type="hidden" name="return_vendor" value="<?= (int)$_GET['return'] ?>">
            <?php endif; ?>

            <?php if(isset( $_GET['token']) && $_GET['token'] != ''): ?>
                <input type="hidden" name="token" value="<?php echo esc_attr($_GET['token']); ?>">
                <input type="hidden" name="Clients[token]" value="<?php echo esc_attr($_GET['token']); ?>">
            <?php endif; ?>

            <?php if(isset($event_a['form_code']) && $event_a['form_code'] != ''): ?>
                <?php
                    $form_code = esc_attr($event_a['form_code']);
                    if(isset($_SESSION['ok'])) {
                        $form_code .= "_".$_SESSION['ok'];
                    }
                ?>
                <input type="hidden" name="form_code" value="<?php echo sanitize_text_field($form_code); ?>">
            <?php endif; ?>

            <?php if(isset( $_GET['cpk']) && $_GET['cpk'] != ''): ?>
                <input type="hidden" name="cpk" value="<?php echo esc_attr($_GET['cpk']); ?>">
                <input type="hidden" name="Clients[cpk]" value="<?php echo esc_attr($_GET['cpk']); ?>">
            <?php endif; ?>

            <?php if(isset($formData['mode']) && $formData['mode'] != ''): ?>
                <input type="hidden" name="mode" value="<?php echo esc_attr($formData['mode']); ?>">
                <input type="hidden" name="Clients[mode]" value="<?php echo esc_attr($formData['mode']); ?>">
            <?php endif; ?>

            <?php if(isset( $_GET['rfc']) && $_GET['rfc'] != ''): ?>
                <input type="hidden" name="rfc" value="<?php echo esc_attr($_GET['rfc']); ?>">
            <?php endif;

            return ($form . $this->_generate_register_screen_field(ob_get_clean(), $client_a, $event_a, $pre_launch_count));
        }

        /**
         * @param $formData
         * @param $form
         * @return string
         */
        private function _create_passreset_screen_fields($formData, $form)
        {
            global $wp;

            $client_a = isset($formData['client_a']) ? $formData['client_a'] : [];
            $event_a = $formData['event_a'];
            $pre_launch_count = $formData['pre_launch_count'];

            // field types (from profile_fields::field_type) that are stored in json_encoded array (in applicant_field_data::text_long)
            $selector_fields = ['dropdown','radio','checkboxes'];

            $redirect_url = home_url($wp->request) . "/";

            ob_start();

            $button = '<button type="button" id="" class="btn btn-form-register" href="'.$redirect_url.'?login">
                Back to Login
            </button>';

            if(isset($_GET['pr'])): ?>
                <?php if($_GET['pr'] == 0): ?>
                    <div class="form-group-top-error field-clients-value-apply_step1">
                        <div class="col-lg-8">
                            <div class='red-alert'><h4>Incorrect code given.</h4></div>
                        </div>
                    </div>
                <?php endif; ?>
            <?php endif;

            $input_data = '';
            if(isset($formData['profile_field_data_a'])) {

                foreach ($formData['profile_field_data_a'] AS $input_data) {
                    if (isset($input_data['field_type'])) {

                        if (in_array($input_data['field_type'], $selector_fields)) {
                            $input_data['option_values_a'] = json_decode($input_data['option_values_a'], true);
                        }

                        // hide applic type or badge sub-form
                        if($input_data['model_field'] == 'client_types_a' || $input_data['model_field'] == 'com_prefs'){
                            continue;
                        }

                        if(isset($formData['client_a'])){
                            if(isset($formData['client_a'][$input_data['model_field']])){
                                $input_data['value'] = $formData['client_a'][$input_data['model_field']];
                            }
                        }

                        // stuff country code into input data
                        $input_data['input_default_country_code'] = $formData['event_a']['phone_code_default'];

                        $field = $this->_generate_input_field($input_data['field_type'], $input_data);

                        $send_targets = '';
                        if(!empty($formData['client_a']['email'])){
                            $send_targets = $formData['client_a']['email'];
                        }

                        if(!empty($formData['client_a']['phone'])){
                            $phone = self::_formatPhoneNumber($formData['client_a']['phone'], true);
                            // $phone = 'your cell #';
                            $send_targets = !empty($send_targets) ? $send_targets . ' and ' . $phone : $phone;
                        }

                        $field = str_replace("%send_targets%", $send_targets, $field);

                        $field = str_replace("form-group", 'form-group-login', $field);
                        $field = str_replace("group-hover-disabled", 'login-fields', $field);
                        $field = str_replace("help-block", 'help-block-login', $field);
                        echo str_replace("%button%", $button, $field);
                    }
                }
            }

            // mode is returned via API

            if($formData['mode'] == 'passreset') {
                $button_label = 'Reset Password';
            }elseif($formData['mode'] == 'passtoken'){
                $button_label = 'Continue';
            }elseif($formData['mode'] == 'passforgot'){
                $button_label = 'Continue';
            }else{
                $button_label = 'Submit';
            }
            ?>

            <div class="form-group field-clients-value-apply_step1">
                <div class="col-lg-8">
                    <input type="hidden" id="clients-value-apply_step1" class="form-control" name="Clients[Value][apply_step1]" value="1">
                </div>
            </div>

            <?php if($formData['mode'] != 'passtoken'): ?>
            <div class="col-lg-offset-2 col-lg-11" style="margin-bottom:10px; margin-left:10px;">
                <span class="red-alert">*</span> = required field
            </div>
            <?php endif; ?>

            <div class="form-group">
                <div class="col-lg-offset-2 col-lg-11">
                    <button type="submit" id="submit-apply" class="btn btn-success pull-left">
                        <?php echo $button_label ?> <i style="margin-left:0px;" class="fa fa-chevron-right" aria-hidden="true"></i>
                    </button>
                    <div id="submit-spinner" class="pull-left"></div>
                </div>
            </div>

            <?php if(isset($hidden_input_client_type)): ?>
                <?php echo $hidden_input_client_type; ?>
            <?php endif; ?>

            <?php if(isset( $_GET['cpk']) && $_GET['cpk'] != ''): ?>
                <input type="hidden" name="Clients[cpk]" value="<?php echo esc_attr($_GET['cpk']); ?>">
            <?php endif; ?>

            <?php if(isset( $_GET['token']) && $_GET['token'] != ''): ?>
                <input type="hidden" name="Clients[token]" value="<?php echo esc_attr($_GET['token']); ?>">
            <?php endif; ?>

            <?php if(isset( $_GET['return']) && $_GET['return'] != ''): ?>
                <input type="hidden" name="return_vendor" value="<?= (int)$_GET['return'] ?>">
            <?php endif; ?>

            <?php if(isset($client_a['profile_key']) && $client_a['profile_key'] != ''): ?>
                <input type="hidden" name="profile_key" value="<?php echo esc_attr($client_a['profile_key']); ?>">
            <?php endif; ?>

            <?php if(isset($event_a['form_code']) && $event_a['form_code'] != ''): ?>
                <?php
                    $form_code = esc_attr($event_a['form_code']);
                    if(isset($_SESSION['ok'])) {
                        $form_code .= "_".$_SESSION['ok'];
                    }
                ?>
                <input type="hidden" name="form_code" value="<?php echo sanitize_text_field($form_code); ?>">
            <?php endif; ?>

            <?php if(isset($formData['mode']) && $formData['mode'] != ''): ?>
                <input type="hidden" name="mode" value="<?php echo esc_attr($formData['mode']); ?>">
                <input type="hidden" name="Clients[mode]" value="<?php echo esc_attr($formData['mode']); ?>">
            <?php endif; ?>

            <?php if(isset( $_GET['rfc']) && $_GET['rfc'] != ''): ?>
                <input type="hidden" name="rfc" value="<?php echo esc_attr($_GET['rfc']); ?>">
            <?php endif;

            return ($form . $this->_generate_passreset_screen_field(ob_get_clean(), $client_a, $event_a, $pre_launch_count));
        }

        /**
         * @param $formData
         * @param $form
         * @return string
         */
        private function _create_privacysign_screen_fields($formData, $form)
        {
            $client_a = isset($formData['client_a']) ? $formData['client_a'] : [];
            $event_a = $formData['event_a'];
            $pre_launch_count = $formData['pre_launch_count'];

            // field types (from profile_fields::field_type) that are stored in json_encoded array (in applicant_field_data::text_long)
            $selector_fields = ['dropdown','radio','checkboxes'];

            ob_start();

            $input_data = '';
            if(isset($formData['profile_field_data_a'])) {
                foreach ($formData['profile_field_data_a'] AS $input_data) {
                    if (isset($input_data['field_type'])) {

                        if (in_array($input_data['field_type'], $selector_fields)) {
                            $input_data['option_values_a'] = json_decode($input_data['option_values_a'], true);
                        }

                        // skip com_prefs on all forms
                        if($input_data['model_field'] == 'com_prefs'){
                            continue;
                        }

                        // hide applic type or badge sub-form
                        if($input_data['model_field'] == 'client_types_a' &&
                            ($event_a['client_type_hide'] == 1 || (int)$formData["applicant_a"]["origin_applic_id"] > 0)){
                            $hidden_input_client_type = '<input type="hidden" name="Clients[client_applic_type][]" value="'.$event_a['client_types'][0].'">';
                            continue;
                        }

                        // stuff country code into input data
                        $input_data['input_default_country_code'] = $formData['event_a']['phone_code_default'];

                        echo $this->_generate_input_field($input_data['field_type'], $input_data);
                    }
                }
            }
            ?>

            <div class="form-group field-clients-value-apply_step1">
                <div class="col-lg-8">
                    <input type="hidden" id="clients-value-apply_step1" class="form-control" name="Clients[Value][apply_step1]" value="1">
                </div>
            </div>

            <div class="col-lg-offset-2 col-lg-11" style="margin-bottom:10px; margin-left:10px;">
                <span class="red-alert">*</span> = required field
            </div>

            <div class="form-group">
                <div class="col-lg-offset-2 col-lg-11">
                    <button type="submit" id="submit-apply" class="btn btn-success-bottom pull-left">
                        <?php if(isset( $_GET['pk']) && $_GET['pk'] != ''): ?>
                            <?php echo $this->_button_label_swap('save_continue'); ?> <i style="margin-left:0px;" class="fa fa-chevron-right" aria-hidden="true"></i>
                        <?php endif; ?>
                    </button>
                    <div id="submit-spinner" class="pull-left"></div>
                </div>
            </div>

            <?php if(isset($hidden_input_client_type)): ?>
            <?php echo $hidden_input_client_type; ?>
        <?php endif; ?>

        <?php if(isset( $_GET['return']) && $_GET['return'] != ''): ?>
            <input type="hidden" name="return_vendor" value="<?= (int)$_GET['return'] ?>">
        <?php endif; ?>

        <?php if(isset($_GET['pk']) && $_GET['pk'] != ''): ?>
            <input type="hidden" name="profile_key" value="<?php echo esc_attr($_GET['pk']); ?>">
        <?php endif; ?>

        <?php if(isset($event_a['form_code']) && $event_a['form_code'] != ''): ?>
            <?php
                $form_code = esc_attr($event_a['form_code']);
                if(isset($_SESSION['ok'])) {
                    $form_code .= "_".$_SESSION['ok'];
                }
            ?>
            <input type="hidden" name="form_code" value="<?php echo sanitize_text_field($form_code); ?>">
        <?php endif; ?>

        <?php if(isset( $_GET['rfc']) && $_GET['rfc'] != ''): ?>
            <input type="hidden" name="rfc" value="<?php echo esc_attr($_GET['rfc']); ?>">
        <?php endif;

            return ($form . $this->_generate_privacysign_screen_field(ob_get_clean(), $client_a, $event_a, $pre_launch_count));
        }

        /**
         * @param $formData
         * @param $form
         * @return string
         */
        private function _create_profile_screen_fields($formData, $form)
        {
            $client_a = isset($formData['client_a']) ? $formData['client_a'] : [];
            $event_a = $formData['event_a'];
            $pre_launch_count = $formData['pre_launch_count'];

            if(isset($client_a['is_admin'])){
                $audit = $client_a['is_admin'];
            }else{
                $audit = false;
            }
            ?>

            <?php
            // field types (from profile_fields::field_type) that are stored in json_encoded array (in applicant_field_data::text_long)
            $selector_fields = ['dropdown','radio','checkboxes'];

            ob_start();

            $is_new = true;
            $skip_profile = false;
            if(isset( $_GET['rfc']) && $_GET['rfc'] != ''){
                $is_new = $_GET['rfc'] == 'new' ? true : false;
            }elseif(isset( $_GET['pk']) && $_GET['pk'] != ''){
                $is_new = false;
            }
            ?>

            <?php if($event_a['rsvp_form_host_id'] > 0): ?>
                <?php if($is_new && !isset($_SESSION['ok']) && !isset($_GET['ok']) && !$logout_flag): ?>
                    <?php $skip_profile = true; ?>
                    <div class="well-warning form-group-top-error field-clients-value-apply_step1">
                        <div class="col-lg-8">
                            <div class='red-alert'><h4>Origin Key not found for NEW profiles. Please check form URL.</h4></div>
                            <h5>The form URL should end with /?ok=12345 (example).</h5>
                            <div style="margin-top:20px;"><h5>If you ALREADY created a profile, click Login to continue.</h5></div>
                        </div>
                    </div>
                <?php endif; ?>
            <?php endif; ?>

            <?php if(!$skip_profile): ?>
                <?php
                $input_data = '';
                if(isset($formData['profile_field_data_a'])) {
                    foreach ($formData['profile_field_data_a'] AS $input_data) {
                        if (isset($input_data['field_type'])) {

                            if (in_array($input_data['field_type'], $selector_fields)) {
                                $input_data['option_values_a'] = json_decode($input_data['option_values_a'], true);
                            }

                            // skip com_prefs on all forms
                            if($input_data['model_field'] == 'com_prefs'){
                                continue;
                            }

                            // hide applic type or badge sub-form
                            if($input_data['model_field'] == 'client_types_a' &&
                                ($event_a['client_type_hide'] == 1 || (int)$formData["applicant_a"]["origin_applic_id"] > 0)){
                                $hidden_input_client_type = '<input type="hidden" name="Clients[client_applic_type][]" value="'.$event_a['client_types'][0].'">';
                                continue;
                            }

                            // stuff country code into input data
                            $input_data['input_default_country_code'] = $formData['event_a']['phone_code_default'];

                            echo $this->_generate_input_field($input_data['field_type'], $input_data, $audit);
                        }
                    }
                }
                ?>
            <?php endif; ?>

            <div class="form-group field-clients-value-apply_step1">
                <div class="col-lg-8">
                    <input type="hidden" id="clients-value-apply_step1" class="form-control" name="Clients[Value][apply_step1]" value="1">
                </div>
            </div>

            <?php if(!$skip_profile): ?>
                <div class="col-lg-offset-2 col-lg-11" style="margin-bottom:10px; margin-left:10px;">
                    <span class="red-alert">*</span> = required field
                </div>

                <?php if(!empty($formData['event_a']['privacy_policy_url'])): ?>
                    <div class="form-group field-event">
                        <div class="col-lg-offset-2 col-lg-10">
                            <div class="block_text well">
                                <?php echo $formData['privacy_policy_dialogue'] ?>
                            </div>
                        </div>
                    </div>
                <?php endif; ?>

                <div class="form-group">
                    <div class="col-lg-offset-2 col-lg-11">
                        <button type="submit" id="submit-apply" class="btn btn-success-bottom pull-left">
                            <?php if(isset( $_GET['pk']) && $_GET['pk'] != ''){ ?>
                                <?php if((int)$formData["applicant_a"]["origin_applic_id"] > 0): ?>
                                    Save Badge Details
                                <?php else: ?>
                                    <?php echo $this->_button_label_swap('save_continue') ?> <i style="margin-left:0px;" class="fa fa-chevron-right" aria-hidden="true"></i>
                                <?php endif; ?>
                            <?php }else{ ?>
                                Next
                            <?php } ?>
                        </button>
                        <div id="submit-spinner" class="pull-left"></div>
                    </div>
                </div>
            <?php endif; ?>

            <?php if(isset($hidden_input_client_type)): ?>
            <?php echo $hidden_input_client_type; ?>
            <?php endif; ?>

            <?php if(isset( $_GET['return']) && $_GET['return'] != ''): ?>
                <input type="hidden" name="return_vendor" value="<?= (int)$_GET['return'] ?>">
            <?php endif; ?>

            <?php if(isset($_GET['pk']) && $_GET['pk'] != ''): ?>
                <input type="hidden" name="profile_key" value="<?php echo esc_attr($_GET['pk']); ?>">
            <?php endif; ?>

            <?php if(isset($event_a['form_code']) && $event_a['form_code'] != ''): ?>
                <?php
                    $form_code = esc_attr($event_a['form_code']);
                    if(isset($_SESSION['ok'])) {
                        $form_code .= "_".$_SESSION['ok'];
                    }
                ?>
                <input type="hidden" name="form_code" value="<?php echo sanitize_text_field($form_code); ?>">
            <?php endif; ?>

            <?php if(isset( $_GET['rfc']) && $_GET['rfc'] != ''): ?>
                <input type="hidden" name="rfc" value="<?php echo esc_attr($_GET['rfc']); ?>">
            <?php endif; ?>

            <?php if(isset( $_GET['rpk']) && $_GET['rpk'] != ''): ?>
                <input type="hidden" name="rpk" value="<?php echo esc_attr($_GET['rpk']); ?>">
            <?php endif; ?>

            <?php
            return ($form . $this->_generate_profile_screen_field(ob_get_clean(), $client_a, $event_a, $pre_launch_count));
        }

        /**
         * @param $formData
         * @param $form
         * @return string
         */
        private function _create_session_screen_fields($formData, $form)
        {
            $client_a = isset($formData['client_a']) ? $formData['client_a'] : [];
            $event_a = $formData['event_a'];
            $pre_launch_count = $formData['pre_launch_count'];

            if(isset($client_a['is_admin'])){
                $audit = $client_a['is_admin'];
            }else{
                $audit = false;
            }
            ?>

            <?php
            // field types (from profile_fields::field_type) that are stored in json_encoded array (in applicant_field_data::text_long)
            $selector_fields = ['dropdown','radio','checkboxes'];

            ob_start();

            $is_new = true;
            $skip_profile = false;
            if(isset( $_GET['rfc']) && $_GET['rfc'] != ''){
                $is_new = $_GET['rfc'] == 'new' ? true : false;
            }elseif(isset( $_GET['pk']) && $_GET['pk'] != ''){
                $is_new = false;
            }
            ?>

            <?php if($event_a['rsvp_form_host_id'] > 0): ?>
                <?php if($is_new && !isset($_SESSION['ok']) && !isset($_GET['ok']) && !$logout_flag): ?>
                    <?php $skip_profile = true; ?>
                    <div class="well-warning form-group-top-error field-clients-value-apply_step1">
                        <div class="col-lg-8">
                            <div class='red-alert'><h4>Origin Key not found for NEW profiles. Please check form URL.</h4></div>
                            <h5>The form URL should end with /?ok=12345 (example).</h5>
                            <div style="margin-top:20px;"><h5>If you ALREADY created a profile, click Login to continue.</h5></div>
                        </div>
                    </div>
                <?php endif; ?>
            <?php endif; ?>

            <?php if(!$skip_profile): ?>
                <?php
                $input_data = '';
                if(isset($formData['profile_field_data_a'])) {
                    foreach ($formData['profile_field_data_a'] AS $input_data) {
                        if (isset($input_data['field_type'])) {

                            if (in_array($input_data['field_type'], $selector_fields)) {
                                $input_data['option_values_a'] = json_decode($input_data['option_values_a'], true);
                            }

                            // skip com_prefs on all forms
                            if($input_data['model_field'] == 'com_prefs'){
                                continue;
                            }

                            // hide applic type or badge sub-form
                            if($input_data['model_field'] == 'client_types_a' &&
                                ($event_a['client_type_hide'] == 1 || (int)$formData["applicant_a"]["origin_applic_id"] > 0)){
                                $hidden_input_client_type = '<input type="hidden" name="Clients[client_applic_type][]" value="'.$event_a['client_types'][0].'">';
                                continue;
                            }

                            // stuff country code into input data
                            $input_data['input_default_country_code'] = $formData['event_a']['phone_code_default'];

                            // stuff session top input data
                            $input_data['session_top_level_a'] = $formData['event_a']['session_top_level_a'];

                            // stuff session input values
                            $input_data['session_chain_values_a'] = $formData['event_a']['session_chain_values_a'];

                            // stuff session levels array
                            $input_data['session_levels_a'] = $formData['event_a']['session_levels_a'];

                            // allow custom keywords
                            $input_data['custom_keywords_allowed'] = 1;

                            echo $this->_generate_input_field($input_data['field_type'], $input_data, $audit);
                        }
                    }
                }
                ?>
            <?php endif; ?>

            <div class="form-group field-clients-value-apply_step1">
                <div class="col-lg-8">
                    <input type="hidden" id="clients-value-apply_step1" class="form-control" name="Sessions[Value][apply_step1]" value="1">
                </div>
            </div>

            <?php if(!$skip_profile): ?>
                <div class="col-lg-offset-2 col-lg-11" style="margin-bottom:10px; margin-left:10px;">
                    <span class="red-alert">*</span> = required field
                </div>

                <div class="form-group">
                    <div class="col-lg-offset-2 col-lg-11">
                        <button type="submit" id="submit-apply" class="btn btn-success-bottom pull-left">
                            <?php if(isset( $_GET['pk']) && $_GET['pk'] != ''){ ?>
                                <?php if((int)$formData["applicant_a"]["origin_applic_id"] > 0): ?>
                                    Save Badge Details
                                <?php else: ?>
                                    <?php echo $this->_button_label_swap('save_continue') ?> <i style="margin-left:0px;" class="fa fa-chevron-right" aria-hidden="true"></i>
                                <?php endif; ?>
                            <?php }else{ ?>
                                Next
                            <?php } ?>
                        </button>
                        <div id="submit-spinner" class="pull-left"></div>
                    </div>
                </div>
            <?php endif; ?>

            <?php if(isset($hidden_input_client_type)): ?>
            <?php echo $hidden_input_client_type; ?>
            <?php endif; ?>

            <?php if(isset( $_GET['return']) && $_GET['return'] != ''): ?>
                <input type="hidden" name="return_vendor" value="<?= (int)$_GET['return'] ?>">
            <?php endif; ?>

            <?php if(isset($_GET['pk']) && $_GET['pk'] != ''): ?>
                <input type="hidden" name="profile_key" value="<?php echo esc_attr($_GET['pk']); ?>">
            <?php endif; ?>

            <?php if(isset($event_a['form_code']) && $event_a['form_code'] != ''): ?>
                <?php
                    $form_code = esc_attr($event_a['form_code']);
                    if(isset($_SESSION['ok'])) {
                        $form_code .= "_".$_SESSION['ok'];
                    }
                ?>
                <input type="hidden" name="form_code" value="<?php echo sanitize_text_field($form_code); ?>">
            <?php endif; ?>

            <?php if(isset( $_GET['rfc']) && $_GET['rfc'] != ''): ?>
                <input type="hidden" name="rfc" value="<?php echo esc_attr($_GET['rfc']); ?>">
            <?php endif; ?>

            <?php if(isset( $_GET['rpk']) && $_GET['rpk'] != ''): ?>
                <input type="hidden" name="rpk" value="<?php echo esc_attr($_GET['rpk']); ?>">
            <?php endif; ?>

            <?php
            return ($form . $this->_generate_session_screen_field(ob_get_clean(), $client_a, $event_a, $pre_launch_count));
        }

        /**
         * @param $input_type
         * @param $self
         * @param $screen
         * @return string
         */
        private function _generate_input_field($input_type, $input_data, $audit = 0)
        {
            $input_data['value'] = isset($input_data['value']) ? $input_data['value'] : '';
            $input_data['phone_intl'] = isset($input_data['phone_intl']) ? $input_data['phone_intl'] : '';

            switch($input_type) {

                case "hr":

                    ob_start();
                    ?>

                    <div class="form-group field-event">
                        <hr class="<?php echo $input_data['block_text']; ?>">
                    </div>

                <?php
                return ob_get_clean();
                break;

                case "blocktext":

                $input_data['field_label'] = $this->_format_required_labels($input_data['field_label'], $input_data['required']);

                ob_start();
                ?>
                    <div class="form-group field-event">
                        <div class="col-lg-offset-2 col-lg-10">
                        <?php if($input_data['scrollbox'] == 0): ?>
                            <div class="<?php echo $input_data['class_tags'] ?>">
                                <?php echo $input_data['block_text']; ?>
                            </div>
                         <?php elseif($input_data['scrollbox'] == 1): ?>
                            <div id="summernote">
                                <?php echo $input_data['block_text']; ?>
                            </div>
                            <script type="text/javascript">
                                var $ = jQuery.noConflict();
                                $(document).ready(function ($) {
                                    $('#summernote').summernote({
                                        toolbar: false,
                                        height: 300
                                    });
                                });
                            </script>
                         <?php endif; ?>
                        </div>
                    </div>

                <?php
                return ob_get_clean();
                break;

                case "checkboxes":

                $horizontal = $input_data['horizontal'] == 1 ? 'checkbox-horizontal' : '';
                $input_data['field_label'] = $this->_format_required_labels($input_data['field_label'], $input_data['required']);

                ob_start();
                ?>

                    <div class="form-group group-hover-disabled field-event">
                        <label class="col-lg-2 control-label well-label" for="clients-<?php echo $input_data['model_field']; ?>"><?php echo $input_data['field_label']; ?></label>
                        <div class="col-lg-offset-2" id="error-box-<?php echo $input_data['model_field']; ?>"></div>
                        <div class="col-lg-10">
                            <input name="<?php echo $input_data['model_label']; ?>[<?php echo $input_data['model_field']; ?>]" type="hidden">
                            <div id="clients-form" class="selectors-shift-left">

                                <?php
                                $option_labels_a = $input_data['option_labels_a'];
                                $option_values_a = $input_data['option_values_a'];
                                $option_values_selected_a = $input_data['value'] != null ? json_decode($input_data['value'],true) : [];

                                $c = 0;
                                foreach($option_values_a as $key => $val) {
                                    $c++;
                                    $required = $c == 1 && $input_data['required'] == 1 ? 'data-parsley-mincheck="1" data-parsley-errors-container="#error-box-'.$input_data['model_field'].'" required' : '';
                                    ?>

                                    <div class="col-lg-8 checkbox <?php echo $horizontal ?>">

                                        <?php if(in_array($key, $option_values_selected_a)): ?>
                                            <input <?php echo $required; ?> id="<?php echo $input_data['model_field']; ?>_<?php echo $key ?>" class="client_type" type="checkbox" checked="checked" name="<?php echo $input_data['model_label']; ?>[<?php echo $input_data['model_field']; ?>][]" value="<?php echo $key; ?>">
                                        <?php else: ?>
                                            <input <?php echo $required; ?> id="<?php echo $input_data['model_field']; ?>_<?php echo $key ?>" class="client_type" type="checkbox" name="<?php echo $input_data['model_label']; ?>[<?php echo $input_data['model_field']; ?>][]" value="<?php echo $key; ?>">
                                        <?php endif; ?>

                                        <label for="<?php echo $input_data['model_field']; ?>_<?php echo $key ?>"><?php echo $val ?></label>

                                        <?php if(!empty($option_labels_a[$key])): ?>
                                            <div class='well well-infobox client_desc'><?php echo $option_labels_a[$key] ?></div>
                                        <?php endif; ?>
                                    </div>

                                <?php
                                }
                                ?>

                            </div>
                        </div>
                    </div>
                    <div class="col-lg-offset-2">
                        <p class="help-block"><?php echo $input_data['help_text']; ?></p>
                    </div>

                <?php
                return ob_get_clean();
                break;

                case "radio":

                $required = $input_data['required'] == 1 ? 'required' : '';
                $horizontal = $input_data['horizontal'] == 1 ? 'radio-horizontal' : '';
                $input_data['field_label'] = $this->_format_required_labels($input_data['field_label'], $input_data['required']);

                $g_hover = '';
                if(!isset($input_data['badge_dataset'])){
                    $g_hover = 'group-hover-disabled';
                }
                ob_start();
                ?>
                    <div class="form-group <?php echo $g_hover ?> field-clients-<?php echo $input_data['model_field']; ?>">
                        <label class="col-lg-2 control-label well-label" for="clients-<?php echo $input_data['model_field']; ?>"><?php echo $input_data['field_label']; ?></label>
                        <div class="col-lg-offset-2" id="error-box-<?php echo $input_data['model_field']; ?>"></div>
                        <div class="col-lg-8">
                            <div class="selectors-shift-left">

                                <?php
                                $option_values_a = $input_data['option_values_a'];
                                $option_value_selected_a = $input_data['value'];

                                $c = 0;
                                foreach($option_values_a as $key => $val) {
                                    $c++;
                                    $required = $c == 1 && $input_data['required'] == 1 ? 'data-parsley-errors-container="#error-box-'.$input_data['model_field'].'" required' : '';

                                    // insert badge dataset if exists
                                    $badge_dataset = '';
                                    if(isset($input_data['badge_dataset'])){
                                        $badge_dataset = "[{$input_data['amenity_id']}-{$input_data['badge_dataset']}]";
                                    }
                                    ?>
                                    <div class="col-lg-8 radio <?php echo $horizontal ?>">
                                        <input type="radio" id="<?php echo $input_data['model_label']; ?><?php echo $badge_dataset; ?>[<?php echo $input_data['model_field']; ?>]-<?php echo esc_attr($key); ?>" name="<?php echo $input_data['model_label']; ?><?php echo $badge_dataset; ?>[<?php echo $input_data['model_field']; ?>]" value="<?php echo $key; ?>" <?php checked($key, $option_value_selected_a); ?> <?php echo $required; ?>>
                                        <label for="<?php echo $input_data['model_label']; ?><?php echo $badge_dataset; ?>[<?php echo $input_data['model_field']; ?>]-<?php echo esc_attr($key); ?>" style="">
                                            <?php echo sanitize_text_field($val); ?>
                                        </label>
                                    </div>

                                <?php
                                }
                                ?>
                                <p class="help-block-selectors"><?php echo $input_data['help_text']; ?></p>
                            </div>
                        </div>
                    </div>

                <?php
                return ob_get_clean();
                break;

                case "dropdown":

                $required = $input_data['required'] == 1 ? 'required' : '';
                $input_data['field_label'] = $this->_format_required_labels($input_data['field_label'], $input_data['required']);
                $lock_field = empty($input_data['value']) ? 0 : $input_data['lock_field'];

                ob_start();
                ?>
                    <div class="form-group group-hover-disabled field-clients-<?php echo $input_data['model_field']; ?>">
                        <label class="col-lg-2 control-label well-label" for="clients-<?php echo $input_data['model_field']; ?>"><?php echo $input_data['field_label']; ?></label>
                        <div class="col-lg-offset-2" id="error-box-<?php echo $input_data['model_field']; ?>"></div>
                        <div class="col-lg-8">
                            <div class="selectors-shift-left">
                                <?php
                                $option_values_a = $input_data['option_values_a'];
                                $option_value_selected_a = $input_data['value'];
                                ?>
                                <select id="<?php echo $input_data['model_label']; ?>[<?php echo $input_data['model_field']; ?>]" style="width:auto;" class="form-control" name="<?php echo $input_data['model_label']; ?>[<?php echo $input_data['model_field']; ?>]" <?php echo $required; ?>>
                                    <option value="">Select...</option>
                                    <?php

                                    foreach($option_values_a as $key => $val) {
                                        ?>
                                        <?php if($key == $option_value_selected_a): ?>
                                            <option value="<?php echo $key; ?>" selected><?php echo $val; ?></option>
                                        <?php else: ?>
                                            <option value="<?php echo $key; ?>"><?php echo $val; ?></option>
                                        <?php endif; ?>
                                    <?php
                                    }
                                    ?>
                                </select>
                            </div>
                        </div>
                    </div>
                    <div class="col-lg-offset-2">
                        <p class="help-block"><?php echo $input_data['help_text']; ?></p>
                    </div>

                    <script type="text/javascript">
                        $(document).ready(function () {
                            <?php if($audit == 0 && $lock_field == 1): ?>
                                $( "#<?php echo $input_data['model_label']; ?>[<?php echo $input_data['model_field']; ?>]" ).prop( "readonly", <?php echo $audit ?> );
                                $( "#<?php echo $input_data['model_label']; ?>[<?php echo $input_data['model_field']; ?>]" ).css('background-color' , '#DEDEDE');
                            <?php endif; ?>
                        });
                    </script>
                <?php
                return ob_get_clean();
                break;

                case "chain-selector":

                $required = $input_data['required'] == 1 ? 'required' : '';
                $input_data['field_label'] = $this->_format_required_labels($input_data['field_label'], $input_data['required']);
                $lock_field = empty($input_data['value']) ? 0 : $input_data['lock_field'];

                ob_start();
                ?>
                    <div class="form-group group-hover-disabled field-clients-<?php echo $input_data['model_field']; ?>">
                        <label class="col-lg-2 control-label well-label" for="clients-session-select"><?php echo $input_data['field_label']; ?></label>

                        <div class="col-lg-8">
                            <div class="selectors-shift-left">

                                <?php
                                // option tooltip
                                $session_top_level_a = $input_data['session_top_level_a'];
                                $session_option_values_a = $input_data['session_chain_values_a'];
                                $session_levels_a = $input_data['session_levels_a'];
                                ?>

                                <?php foreach($session_levels_a AS $key => $v): ?>
                                    <select size="4" id="sessions-session_topic_tl<?php echo $key ?>" style="margin-top:6px; width:auto;" class="form-control" name="Sessions[session_topic][<?php echo $key ?>]">
                                    <?php if($key == 1): ?>
                                        <!-- option value="0" selected>Select...</option -->
                                        <?php foreach($session_top_level_a as $key => $val_a): ?>

                                            <?php
                                            $label = $val_a[0];
                                            $description = $val_a[1];
                                            $desc_meta = !empty($description) ? "class=\"tooltip_chained\" data-jbox-content=\"{$description}\"" : "";
                                            ?>

                                            <?php if($key == $session_option_values_a[1]): ?>
                                                <option <?php echo $desc_meta ?> value="<?php echo $key; ?>" selected><?php echo $label; ?></option>
                                            <?php else: ?>
                                                <option <?php echo $desc_meta ?> value="<?php echo $key; ?>"><?php echo $label; ?></option>
                                            <?php endif; ?>
                                        <?php endforeach; ?>
                                    <?php endif; ?>
                                    </select>
                                <?php endforeach; ?>
                            </div>
                        </div>
                    </div>
                    <div class="col-lg-offset-2" style="margin-top:8px;">
                        <p class="help-block"><?php echo $input_data['help_text']; ?></p>
                    </div>
                <?php
                return ob_get_clean();
                break;

                case "applic_keywords":

                $keywords_disabled = $input_data['max_keywords'] == 0 ? true : false;

                if($keywords_disabled){
                    break;
                }

                $required = $input_data['required'] == 1 ? 'data-parsley-errors-container="#error-box-'.$input_data['model_field'].'" required' : '';

                $input_data['field_label'] = $this->_format_required_labels($input_data['field_label'], $input_data['required']);
                ob_start();
                ?>
                    <script type="text/javascript">
                        $(document).ready(function () {
                            // initialize jQuery stuff after page load
                            $(function(){
                                $('#clients-applic_keywords').select2({
                                    createTag: function(params) {
                                        var open_tags = <?php echo $input_data['custom_keywords_allowed'] ?>;
                                        var term = jQuery.trim(params.term);
                                        if(open_tags == 0) {
                                            return undefined;
                                        } else {
                                            return {
                                                id: term,
                                                text: term
                                            }
                                        }
                                    },
                                    data: [<?php echo $input_data['keywords_unselected']; ?>],
                                    tags: true,
                                    maximumSelectionLength: <?php echo $input_data['max_keywords']; ?>,
                                    tokenSeparators: [','],
                                    placeholder: "Add your keyword tags here",
                                    selectOnClose: false,
                                    allowClear: true
                                });
                            })
                        });
                    </script>

                    <div class="form-group group-hover-disabled field-event">
                        <label class="col-lg-2 control-label well-label" for="clients-<?php echo $input_data['model_field']; ?>"><?php echo $input_data['field_label']; ?></label>
                        <div class="col-lg-offset-2" id="error-box-<?php echo $input_data['model_field']; ?>"></div>
                        <div class="col-lg-10">
                            <div class="selectors-shift-left">
                                <input name="<?php echo $input_data['model_label']; ?>[<?php echo $input_data['model_field']; ?>]" type="hidden">
                                <select id="clients-<?php echo $input_data['model_field']; ?>" class="form-control" name="<?php echo $input_data['model_label']; ?>[<?php echo $input_data['model_field']; ?>][]" multiple="multiple" style="width:100%" <?php echo $required; ?>>
                                    <?php
                                    if(isset($input_data['keywords_selected'])) {
                                        foreach ($input_data['keywords_selected'] AS $key_id => $keyword_label) {
                                            ?>
                                            <option value="<?php echo $key_id; ?>" selected><?php echo $keyword_label ?></option>
                                        <?php
                                        }
                                    }
                                    ?>
                                </select>
                            </div>
                        </div>
                    </div>
                    <div class="col-lg-offset-2">
                        <?php if($input_data['help_text'] !== ''): ?>
                            <p class="help-block"><?php echo $input_data['help_text']; ?></p>
                        <?php elseif($input_data['custom_keywords_allowed'] == 1): ?>
                            <p class="help-block">Select related keywords from dropdown list or ADD your own. Use ENTER or COMMA to separate keywords.</p>
                        <?php else: ?>
                            <p class="help-block">Select related keywords from dropdown list.</p>
                        <?php endif; ?>
                    </div>
                <?php
                return ob_get_clean();
                break;

                case "valuepair":

                $max_width = $input_data['max_width'] != null ? 'max-width: '.$input_data['max_width'].'px' : '';
                $required = $input_data['required'] == 1 ? 'required' : '';
                $filter_type = $input_data['filter'] != null && $input_data['filter'] != 'general' ? 'data-parsley-type="'.$input_data['filter'].'"' : '';
                $input_data['field_label'] = $this->_format_required_labels($input_data['field_label'], $input_data['required']);
                $lock_field = empty($input_data['value']) ? 0 : $input_data['lock_field'];

                $values_a = $input_data['value'] != null ? json_decode($input_data['value'],true) : [];

                ob_start();
                ?>

                    <div class="form-group group-hover-disabled field-clients-name">
                        <label class="col-lg-2 control-label well-label" for="clients-<?php echo $input_data['model_field']; ?>"><?php echo $input_data['field_label']; ?></label>
                        <div class="col-lg-offset-2" id="error-box-<?php echo $input_data['model_field']; ?>"></div>
                        <div class="value-pair-container">
                            <div class="pair-item selectors-shift-left">
                                <input
                                    type="text"
                                    id="clients-<?php echo $input_data['model_field']; ?>-item"
                                    class="pair-item-input form-control"
                                    name="Clients[<?php echo $input_data['model_field']; ?>][item]"
                                    maxlength="100"
                                    value="<?php echo $values_a['item']; ?>"
                                    style="<?php echo $max_width; ?>" <?php echo $filter_type; ?> <?php echo $required; ?>>
                            </div>
                            <div class="pair-value">
                                <span class="input-group-addon">
                                    <i class="fa fa-usd" aria-hidden="true"></i>
                                </span>
                                <input type="number"
                                       id="clients-<?php echo $input_data['model_field']; ?>-value"
                                       class="pair-value-input form-control"
                                       name="Clients[<?php echo $input_data['model_field']; ?>][value]"
                                       maxlength="10"
                                       value="<?php echo $values_a['value']; ?>"
                                       style="<?php echo $max_width; ?>" <?php echo $filter_type; ?> <?php echo $required; ?>>

                            </div>
                        </div>
                    </div>
                    <div class="col-lg-offset-2">
                        <p class="help-block"><?php echo $input_data['help_text']; ?></p>
                    </div>

                    <script type="text/javascript">
                        $(document).ready(function () {
                            <?php if($audit == 0 && $lock_field == 1): ?>
                                $( "#clients-<?php echo $input_data['model_field']; ?>" ).prop( "readonly", <?php echo $audit ?> );
                                $( "#clients-<?php echo $input_data['model_field']; ?>" ).css('background-color' , '#DEDEDE');
                            <?php endif; ?>
                        });
                    </script>

                <?php
                return ob_get_clean();
                break;

                case "socialurl":

                $max_width = $input_data['max_width'] != null ? 'max-width: '.$input_data['max_width'].'px' : '';
                $required = $input_data['required'] == 1 ? 'required' : '';
                $filter_type = $input_data['filter'] != null && $input_data['filter'] != 'general' ? 'data-parsley-errors-container="#error-box-'.$input_data['model_field'].'" data-parsley-trigger="change" data-parsley-type="'.$input_data['filter'].'"' : '';
                $input_data['field_label'] = $this->_format_required_labels($input_data['field_label'], $input_data['required']);
                $audit = empty($input_data['value']) ? 0 : $audit;
                $lock_field = empty($input_data['value']) ? 0 : $input_data['lock_field'];
                $field_value = empty($input_data['value']) ? '' : $input_data['value'];

                if($input_data['lock_field'] == 1 && !empty($input_data['value']) && $audit == 0){
                    $field_disabled = 'disabled';
                }else{
                    $field_disabled = '';
                }

                ob_start();
                ?>

                <?php if($input_data['flex_row'] == 1): ?>

                    <div class="form-group group-hover-disabled field-clients-name field-inline-container">

                        <div class="field-inline-label">
                            <label class="control-label well-label" for="clients-<?php echo $input_data['model_field']; ?>"><?php echo $input_data['field_label']; ?></label>
                        </div>

                        <div class="field-inline-value">
                            <div class="" id="error-box-<?php echo $input_data['model_field']; ?>"></div>
                            <?php if($input_data['filter'] == 'url'): ?>
                                <script type="text/javascript">
                                    $(document).ready(function () {
                                        // initialize jQuery stuff after page load
                                        $(function(){
                                            $('#clients-<?php echo $input_data['model_field']; ?>').parsley().on('field:validate', function() {
                                                $url_filtered = $('#clients-<?php echo $input_data['model_field']; ?>').val().replace(/^https?:\/\//, '');
                                                $('#clients-<?php echo $input_data['model_field']; ?>').val($url_filtered);
                                            });
                                        });
                                    });
                                </script>
                                <span class="input-group-addon input-group-addon-flex">
                                    https://
                                </span>
                            <?php endif; ?>
                            <input type="text" id="clients-<?php echo $input_data['model_field']; ?>" class="form-control" name="<?php echo $input_data['model_label']; ?>[<?php echo $input_data['model_field']; ?>]" maxlength="255" value="<?php echo $input_data['value']; ?>" style="<?php echo $max_width; ?>" <?php echo $filter_type; ?> <?php echo $required; ?> <?php echo $field_disabled ?>>
                            <p class="help-block-inline"><?php echo $input_data['help_text']; ?></p>
                        </div>
                    </div>

                <?php else: ?>

                    <div class="form-group group-hover-disabled field-clients-name">
                        <label class="col-lg-2 control-label well-label" for="clients-<?php echo $input_data['model_field']; ?>"><?php echo $input_data['field_label']; ?></label>
                        <div class="col-lg-offset-2" id="error-box-<?php echo $input_data['model_field']; ?>"></div>
                        <div class="col-lg-8">
                            <div class="selectors-shift-left">
                                <?php if($input_data['filter'] == 'url'): ?>
                                    <script type="text/javascript">
                                        $(document).ready(function () {
                                            $(function(){
                                                $('#clients-<?php echo $input_data['model_field']; ?>').parsley().on('field:validate', function() {
                                                    $url_filtered = $('#clients-<?php echo $input_data['model_field']; ?>').val().replace(/^https?:\/\//, '');
                                                    $('#clients-<?php echo $input_data['model_field']; ?>').val($url_filtered);
                                                });
                                            });
                                        });
                                    </script>
                                    <span class="input-group-addon input-group-addon-block">
                                        https://
                                    </span>
                                <?php endif; ?>
                                <input type="text" id="clients-<?php echo $input_data['model_field']; ?>" class="form-control" name="<?php echo $input_data['model_label']; ?>[<?php echo $input_data['model_field']; ?>]" maxlength="255" value="<?php echo $field_value; ?>" style="<?php echo $max_width; ?>" <?php echo $filter_type; ?> <?php echo $required; ?> <?php echo $field_disabled ?>>
                            </div>
                        </div>
                    </div>
                    <div class="col-lg-offset-2">
                        <p class="help-block"><?php echo $input_data['help_text']; ?></p>
                    </div>

                <?php endif; ?>

                    <script type="text/javascript">
                        $(document).ready(function () {
                            <?php if($audit == 0 && $lock_field == 1): ?>
                                $( "#clients-<?php echo $input_data['model_field']; ?>" ).prop( "readonly", <?php echo $audit ?> );
                                $( "#clients-<?php echo $input_data['model_field']; ?>" ).css('background-color' , '#DEDEDE');
                            <?php endif; ?>
                        });
                    </script>

                <?php
                return ob_get_clean();
                break;

                case "textfield":

                $max_width = $input_data['max_width'] != null ? 'max-width: '.$input_data['max_width'].'px' : '';
                $required = $input_data['required'] == 1 ? 'required' : '';
                $filter_type = $input_data['filter'] != null && $input_data['filter'] != 'general' ? 'data-parsley-errors-container="#error-box-'.$input_data['model_field'].'" data-parsley-trigger="change" data-parsley-type="'.$input_data['filter'].'"' : '';
                $input_data['field_label'] = $this->_format_required_labels($input_data['field_label'], $input_data['required']);
                $audit = empty($input_data['value']) ? 0 : $audit;
                $lock_field = empty($input_data['value']) ? 0 : $input_data['lock_field'];
                $field_value = empty($input_data['value']) ? '' : $input_data['value'];

                if($input_data['lock_field'] == 1 && !empty($input_data['value']) && $audit == 0){
                    $field_disabled = 'disabled';
                }else{
                    $field_disabled = '';
                }

                ob_start();
                ?>

                <?php if($input_data['flex_row'] == 1): ?>

                    <div class="form-group group-hover-disabled field-clients-name field-inline-container">

                        <div class="field-inline-label">
                            <label class="control-label well-label" for="clients-<?php echo $input_data['model_field']; ?>"><?php echo $input_data['field_label']; ?></label>
                            <div class="col-lg-offset-2" id="error-box-<?php echo $input_data['model_field']; ?>"></div>
                        </div>

                        <div class="field-inline-value">
                            <?php if($input_data['filter'] == 'url'): ?>
                                <script type="text/javascript">
                                    $(document).ready(function () {
                                        // initialize jQuery stuff after page load
                                        $(function(){
                                            $('#clients-<?php echo $input_data['model_field']; ?>').parsley().on('field:validate', function() {
                                                $url_filtered = $('#clients-<?php echo $input_data['model_field']; ?>').val().replace(/^https?:\/\//, '');
                                                $('#clients-<?php echo $input_data['model_field']; ?>').val($url_filtered);
                                            });
                                        });
                                    });
                                </script>
                                <span class="input-group-addon input-group-addon-flex">
                                    https://
                                </span>
                            <?php endif; ?>

                            <input type="text" id="clients-<?php echo $input_data['model_field']; ?>" class="form-control" name="<?php echo $input_data['model_label']; ?>[<?php echo $input_data['model_field']; ?>]" maxlength="255" value="<?php echo $input_data['value']; ?>" style="<?php echo $max_width; ?>" <?php echo $filter_type; ?> <?php echo $required; ?> <?php echo $field_disabled ?>>
                            <p class="help-block-inline"><?php echo $input_data['help_text']; ?></p>
                        </div>
                    </div>

                <?php else: ?>

                    <div class="form-group group-hover-disabled field-clients-name">
                        <label class="col-lg-2 control-label well-label" for="clients-<?php echo $input_data['model_field']; ?>"><?php echo $input_data['field_label']; ?></label>
                        <div class="col-lg-offset-2" id="error-box-<?php echo $input_data['model_field']; ?>"></div>
                        <div class="col-lg-8">
                            <div class="selectors-shift-left">
                                <?php if($input_data['filter'] == 'url'): ?>
                                    <script type="text/javascript">
                                        $(document).ready(function () {
                                            $(function(){
                                                $('#clients-<?php echo $input_data['model_field']; ?>').parsley().on('field:validate', function() {
                                                    $url_filtered = $('#clients-<?php echo $input_data['model_field']; ?>').val().replace(/^https?:\/\//, '');
                                                    $('#clients-<?php echo $input_data['model_field']; ?>').val($url_filtered);
                                                });
                                            });
                                        });
                                    </script>
                                    <span class="input-group-addon input-group-addon-block">
                                        https://
                                    </span>
                                <?php endif; ?>
                                <input type="text" id="clients-<?= $input_data['model_field']; ?>" class="form-control" name="<?= $input_data['model_label']; ?>[<?= $input_data['model_field']; ?>]" maxlength="255" value="<?= isset($input_data['value']) ? $input_data['value'] : ''; ?>" style="<?= $max_width; ?>" <?= $filter_type; ?> <?= $required; ?> <?= $field_disabled ?>>
                            </div>
                        </div>
                    </div>
                    <div class="col-lg-offset-2">
                        <p class="help-block"><?php echo $input_data['help_text']; ?></p>
                    </div>

                <?php endif; ?>

                    <script type="text/javascript">
                        $(document).ready(function () {
                            <?php if($audit == 0 && $lock_field == 1): ?>
                                $( "#clients-<?php echo $input_data['model_field']; ?>" ).prop( "readonly", <?php echo $audit ?> );
                                $( "#clients-<?php echo $input_data['model_field']; ?>" ).css('background-color' , '#DEDEDE');
                            <?php endif; ?>
                        });
                    </script>

                <?php
                return ob_get_clean();
                break;

                case "textarea":

                $required = $input_data['required'] == 1 ? 'required' : '';
                $input_data['field_label'] = $this->_format_required_labels($input_data['field_label'], $input_data['required']);
                $lock_field = empty($input_data['value']) ? 0 : $input_data['lock_field'];

                $max_char_js = $max_length_attr = $max_char_count = '';

                if($input_data['max_width'] != null) {
                    $max_length_attr =  ' maxlength="' . $input_data['max_width'] . '"';

                    $max_char_js = "
                        $(function(){
                            var maxLength = {$input_data['max_width']};
                            $('#clients-{$input_data['model_field']}').keyup(function() {
                                var textlen = maxLength - $(this).val().length;
                                $('#clients-char-count-{$input_data['model_field']}').text(textlen);
                            });
                        })
                        ";

                    $max_count = !empty($input_data['value']) ? ($input_data['max_width'] - strlen($input_data['value'])) : $input_data['max_width'];
                    $max_char_count = "<div style='margin-left:5px; display:inline'>
                           (<strong><span id='clients-char-count-{$input_data['model_field']}'>{$max_count}</span></strong> chars left)
                        </div>";
                }

                ob_start();
                ?>

                    <script type="text/javascript">
                        $(document).ready(function () {
                            // initialize jQuery stuff after page load
                            <?php echo $max_char_js; ?>
                            // take care of auto-height and grow
                            $('#clients-<?php echo $input_data['model_field']; ?>').height(
                                $('#clients-<?php echo $input_data['model_field']; ?>')[0].scrollHeight
                            );
                            $('#clients-<?php echo $input_data['model_field']; ?>').autogrow();
                        });
                    </script>

                    <div class="form-group group-hover-disabled field-clients-<?php echo $input_data['model_field']; ?>">
                        <label class="col-lg-2 control-label well-label" for="clients-<?php echo $input_data['model_field']; ?>"><?php echo $input_data['field_label']; ?></label>
                        <?php echo $max_char_count ?>
                        <div class="col-lg-offset-2" id="error-box-<?php echo $input_data['model_field']; ?>"></div>
                        <div class="col-lg-8">
                            <div class="selectors-shift-left">
                                <textarea <?php echo $max_length_attr ?> name="<?php echo $input_data['model_label']; ?>[<?php echo $input_data['model_field']; ?>]" id="clients-<?php echo $input_data['model_field']; ?>" class="form-control form-textarea" <?php echo $required; ?>><?= esc_textarea($input_data['value']); ?></textarea>
                            </div>
                        </div>
                    </div>
                    <div class="col-lg-offset-2">
                        <p class="help-block"><?php echo $input_data['help_text']; ?></p>
                    </div>

                    <script type="text/javascript">
                        $(document).ready(function () {
                            <?php if($audit == 0 && $lock_field == 1): ?>
                                $( "#clients-<?php echo $input_data['model_field']; ?>" ).prop( "readonly", <?php echo $audit ?> );
                                $( "#clients-<?php echo $input_data['model_field']; ?>" ).css('background-color' , '#DEDEDE');
                            <?php endif; ?>
                        });
                    </script>

                <?php
                return ob_get_clean();
                break;

                case "richtextarea":

                $required = $input_data['required'] == 1 ? 'required' : '';
                $input_data['field_label'] = $this->_format_required_labels($input_data['field_label'], $input_data['required']);
                $lock_field = empty($input_data['value']) ? 0 : $input_data['lock_field'];
                ob_start();
                ?>

                    <div class="form-group group-hover-disabled field-clients-<?php echo $input_data['model_field']; ?>">
                        <label class="col-lg-2 control-label well-label" for="clients-<?php echo $input_data['model_field']; ?>"><?php echo $input_data['field_label']; ?></label>
                        <div class="col-lg-offset-2" id="error-box-<?php echo $input_data['model_field']; ?>"></div>
                        <div class="col-lg-8">
                            <div class="selectors-shift-left">
                                <textarea name="<?php echo $input_data['model_label']; ?>[<?php echo $input_data['model_field']; ?>]" id="clients-<?php echo $input_data['model_field']; ?>" class="rich-textarea form-control" <?php echo $required; ?>><?= esc_textarea($input_data['value']); ?></textarea>
                            </div>
                        </div>
                    </div>
                    <div class="col-lg-offset-2">
                        <p class="help-block"><?php echo $input_data['help_text']; ?></p>
                    </div>

                    <script type="text/javascript">
                        $(document).ready(function () {
                            <?php if($audit == 0 && $lock_field == 1): ?>
                                $( "#clients-<?php echo $input_data['model_field']; ?>" ).prop( "readonly", <?php echo $audit ?> );
                                $( "#clients-<?php echo $input_data['model_field']; ?>" ).css('background-color' , '#DEDEDE');
                            <?php endif; ?>
                        });
                    </script>
                <?php
                return ob_get_clean();
                break;

                case "telephone":

                $max_width = $input_data['max_width'] != null ? $input_data['max_width'].'px' : '250px;';
                $min_width = '200px;';
                $phone_number_intl = isset($phone_number_intl) ? $phone_number_intl : '';
                $required = $input_data['required'] == 1 ? 'required' : '';
                $input_data['field_label'] = $this->_format_required_labels($input_data['field_label'], $input_data['required']);
                $lock_field = empty($input_data['value']) ? 0 : $input_data['lock_field'];
                ob_start();

                if($input_data['phone_intl'] == 1){

                    $phone_number = preg_replace('/[^\d]+/', '', $input_data['value']);
                    if($phone_number !== ''){
                        $phone_number_intl = '+'.$phone_number;
                    }

                    $input_field_name = "{$input_data['model_field']}";
                    $input_field_name_tmp = "{$input_data['model_label']}[{$input_data['model_field']}_tmp]";

                    if(!empty($input_data['input_default_country_code'])){
                        $input_preferred_countries_a[] = strtolower($input_data['input_default_country_code']);
                    }else{
                        $input_preferred_countries_a = ['us'];
                    }

                }else{
                    $phone_number = preg_replace('/[^\d]+/', '', $input_data['value']);
                }
                ?>

                <?php if($input_data['flex_row'] == 1): ?>

                    <div class="form-group group-hover-disabled field-inline-container field-clients-<?php echo $input_data['model_field']; ?>">
                        <div class="field-inline-label">
                            <label class="col-lg-2 control-label well-label" for="clients-<?php echo $input_data['model_field']; ?>"><?php echo $input_data['field_label']; ?></label>
                            <div class="col-lg-offset-2" id="error-box-<?php echo $input_data['model_field']; ?>"></div>
                        </div>
                        <div class="field-inline-value">
                            <?php if($input_data['phone_intl'] == 1): ?>
                                <input type="tel" id="clients-<?php echo $input_data['model_field']; ?>" class="telephone form-control" name="<?php echo $input_field_name_tmp ?>" maxlength="255" value="<?php echo $phone_number_intl; ?>" style="min-width: <?php echo $min_width; ?> max-width: <?php echo $max_width; ?>" <?php echo $required; ?>>
                            <?php else: ?>
                                <input data-inputmask="'mask': '<?php echo $input_data['input_mask']; ?>'" type="tel" id="clients-<?php echo $input_data['model_field']; ?>" class="telephone form-control" name="<?php echo $input_data['model_label'] ?>[<?php echo $input_data['model_field'] ?>]" maxlength="255" value="<?php echo $phone_number ?>" style="min-width: <?php echo $min_width; ?> max-width: <?php echo $max_width; ?>" <?php echo $required; ?>>
                            <?php endif; ?>
                            <p class="help-block-inline"><?php echo $input_data['help_text']; ?></p>
                        </div>
                    </div>

                <?php else: ?>

                    <div class="form-group group-hover-disabled field-clients-<?php echo $input_data['model_field']; ?>">
                        <label class="col-lg-2 control-label well-label" for="clients-<?php echo $input_data['model_field']; ?>"><?php echo $input_data['field_label']; ?></label>
                        <div class="col-lg-offset-2" id="error-box-<?php echo $input_data['model_field']; ?>"></div>
                        <div class="col-lg-8">
                            <div class="selectors-shift-left">
                                <?php if($input_data['phone_intl'] == 1): ?>
                                    <input type="tel" id="clients-<?php echo $input_data['model_field']; ?>" class="telephone form-control" name="<?php echo $input_field_name_tmp ?>" maxlength="255" value="<?php echo $phone_number_intl; ?>" style="min-width: <?php echo $min_width; ?> max-width: <?php echo $max_width; ?>" <?php echo $required; ?>>
                                <?php else: ?>
                                    <input data-inputmask="'mask': '<?php echo $input_data['input_mask']; ?>'" type="tel" id="clients-<?php echo $input_data['model_field']; ?>" class="telephone form-control" name="<?php echo $input_data['model_label'] ?>[<?php echo $input_data['model_field'] ?>]" maxlength="255" value="<?php echo $phone_number ?>" style="min-width: <?php echo $min_width; ?> max-width: <?php echo $max_width; ?>" <?php echo $required; ?>>
                                <?php endif; ?>
                            </div>
                        </div>
                    </div>
                    <div class="col-lg-offset-2">
                        <p class="help-block"><?php echo $input_data['help_text']; ?></p>
                    </div>

                <?php endif; ?>

                    <script type="text/javascript">
                        var $ = jQuery.noConflict();

                        $(document).ready(function ($) {
                            <?php if($input_data['phone_intl'] == 1): ?>
                                var input = document.querySelector("#clients-<?php echo $input_data['model_field']; ?>");
                                window.intlTelInput(input, {
                                  // allowDropdown: false,
                                  // autoHideDialCode: false,
                                  // autoPlaceholder: "off",
                                  // dropdownContainer: document.body,
                                  // excludeCountries: ["us"],
                                  // formatOnDisplay: false,
                                  // geoIpLookup: function(callback) {
                                  //   $.get("http://ipinfo.io", function() {}, "jsonp").always(function(resp) {
                                  //     var countryCode = (resp && resp.country) ? resp.country : "";
                                  //     callback(countryCode);
                                  //   });
                                  // },
                                  hiddenInput: "<?php echo $input_field_name ?>",
                                  // initialCountry: "auto",
                                  // localizedCountries: { 'de': 'Deutschland' },
                                  // nationalMode: false,
                                  // onlyCountries: ['us', 'gb', 'ch', 'ca', 'do'],
                                  // placeholderNumberType: "MOBILE",
                                  preferredCountries: [<?php echo '"'.implode('","', $input_preferred_countries_a).'"' ?>],
                                  separateDialCode: true,
                                  // utilsScript: "build/js/utils.js",
                                });
                            <?php endif; ?>
                        });
                    </script>

                    <script type="text/javascript">
                        $(document).ready(function () {
                            <?php if($audit == 0 && $lock_field == 1): ?>
                                $( "#clients-<?php echo $input_data['model_field']; ?>" ).prop( "readonly", <?php echo $audit ?> );
                                $( "#clients-<?php echo $input_data['model_field']; ?>" ).css('background-color' , '#DEDEDE');
                            <?php endif; ?>
                        });
                    </script>
                <?php
                return ob_get_clean();
                break;

                case "com_prefs":

                $required = $input_data['required'] == 1 ? ' aria-required="true" required' : '';
                $input_data['field_label'] = $this->_format_required_labels($input_data['field_label'], $input_data['required']);
                ob_start();
                ?>
                    <div class="form-group group-hover-disabled field-clients-<?php echo $input_data['model_field']; ?>_temp">
                        <label class="col-lg-2 control-label well-label" for="clients-<?php echo $input_data['model_field']; ?>_temp"><?php echo $input_data['field_label']; ?></label>
                        <div class="col-lg-offset-2">
                            <p class="help-block"><?php echo $input_data['help_text']; ?></p>
                        </div>
                        <div class="col-lg-8">
                            <div class="selectors-shift-left">
                                <?php echo $this->_generate_communication_prefs($input_data['value'],$input_data['horizontal']); ?>
                            </div>
                        </div>
                    </div>

                <?php
                return ob_get_clean();
                break;

                case "client_types_c":

                $required = $input_data['required'] == 1 ? 'required' : '';
                $input_data['field_label'] = $this->_format_required_labels($input_data['field_label'], $input_data['required']);
                ob_start();
                ?>

                    <div class="form-group group-hover-disabled field-event">
                        <label class="col-lg-2 control-label well-label" for="clients-<?php echo $input_data['model_field']; ?>"><?php echo $input_data['field_label']; ?></label>
                        <div class="col-lg-offset-2" id="error-box-<?php echo $input_data['model_field']; ?>"></div>
                        <div class="col-lg-10">
                            <div class="selectors-shift-left">
                                <input name="<?php echo $input_data['model_label']; ?>[<?php echo $input_data['model_field']; ?>]" type="hidden">
                                <div id="clients-form" class="">
                                    <?php echo $this->_generate_checkboxes_client_types($input_data,'checkbox'); ?>
                                </div>
                                <p class="help-block-selectors"><?php echo $input_data['help_text']; ?></p>
                            </div>
                        </div>
                    </div>

                <?php
                return ob_get_clean();
                break;

                case "client_types_r":

                $required = $input_data['required'] == 1 ? 'required' : '';
                $input_data['field_label'] = $this->_format_required_labels($input_data['field_label'], $input_data['required']);
                ob_start();
                ?>

                    <div class="form-group group-hover-disabled field-event">
                        <label class="col-lg-2 control-label well-label" for="clients-<?php echo $input_data['model_field']; ?>"><?php echo $input_data['field_label']; ?></label>
                        <div class="col-lg-offset-2" id="error-box-<?php echo $input_data['model_field']; ?>"></div>
                        <div class="col-lg-10">
                            <div class="selectors-shift-left">
                                <input name="<?php echo $input_data['model_label']; ?>[<?php echo $input_data['model_field']; ?>]" type="hidden">
                                <div id="clients-form" class="">
                                    <?php echo $this->_generate_checkboxes_client_types($input_data,'radio'); ?>
                                </div>
                                <p class="help-block-selectors"><?php echo $input_data['help_text']; ?></p>
                            </div>
                        </div>
                    </div>

                <?php
                return ob_get_clean();
                break;

                default:
                    break;

                case "new_password":

                $max_width = $input_data['max_width'] != null ? 'max-width: '.$input_data['max_width'].'px' : '';
                $required = $input_data['required'] == 1 ? 'required' : '';
                $filter_type = $input_data['filter'] != null && $input_data['filter'] != 'general' ? 'data-parsley-type="'.$input_data['filter'].'"' : '';
                $input_data['field_label1'] = $this->_format_required_labels('Password', $input_data['required']);
                $input_data['field_label2'] = $this->_format_required_labels('Password Confirm', $input_data['required']);

                ob_start();
                ?>
                    <div class="form-group field-clients-name">
                        <label class="col-lg-2 control-label well-label" for="clients-<?php echo $input_data['model_field']; ?>"><?php echo $input_data['field_label1']; ?></label>
                        <div class="col-lg-8">
                            <div class="selectors-shift-left">
                                <input type="password" id="clients-<?php echo $input_data['model_field']; ?>-1" class="form-control" name="<?php echo $input_data['model_label']; ?>[password]" maxlength="255" value="<?php echo $input_data['value']; ?>" style="<?php echo $max_width; ?>" <?php echo $filter_type; ?> <?php echo $required; ?>>
                            </div>
                        </div>
                    </div>
                    <div class="form-group field-clients-name">
                        <label class="col-lg-2 control-label well-label" for="clients-<?php echo $input_data['model_field']; ?>"><?php echo $input_data['field_label2']; ?></label>
                        <div class="col-lg-8">
                            <div class="selectors-shift-left">
                                <input data-parsley-equalto="#clients-<?php echo $input_data['model_field']; ?>-1" type="password" id="clients-<?php echo $input_data['model_field']; ?>-2" class="form-control" name="<?php echo $input_data['model_label']; ?>[password2]" maxlength="255" value="<?php echo $input_data['value']; ?>" style="<?php echo $max_width; ?>" <?php echo $filter_type; ?> <?php echo $required; ?>>
                            </div>
                        </div>
                    </div>
                    <div class="col-lg-offset-2">
                        <p class="help-block"><?php echo $input_data['help_text']; ?></p>
                    </div>

                <?php
                return ob_get_clean();
                break;

                case "password":

                $max_width = $input_data['max_width'] != null ? 'max-width: '.$input_data['max_width'].'px' : '';
                $required = $input_data['required'] == 1 ? 'required' : '';
                $filter_type = $input_data['filter'] != null && $input_data['filter'] != 'general' ? 'data-parsley-type="'.$input_data['filter'].'"' : '';
                $input_data['field_label1'] = $this->_format_required_labels('Password', $input_data['required']);

                ob_start();
                ?>
                    <div class="form-group field-clients-name">
                        <label class="col-lg-2 control-label well-label" for="clients-<?php echo $input_data['model_field']; ?>"><?php echo $input_data['field_label1']; ?></label>
                        <div class="col-lg-8">
                            <div class="selectors-shift-left">
                                <input type="password" id="clients-<?php echo $input_data['model_field']; ?>" class="form-control" name="<?php echo $input_data['model_label']; ?>[password]" maxlength="255" value="<?php echo $input_data['value']; ?>" style="<?php echo $max_width; ?>" <?php echo $filter_type; ?> <?php echo $required; ?>>
                            </div>
                        </div>
                    </div>
                    <div class="col-lg-offset-2">
                        <p class="help-block"><?php echo $input_data['help_text']; ?></p>
                    </div>

                <?php
                return ob_get_clean();
                break;

                case "pass_token":

                $max_width = $input_data['max_width'] != null ? 'max-width: '.$input_data['max_width'].'px' : '';
                $required = $input_data['required'] == 1 ? 'required' : '';
                $filter_type = $input_data['filter'] != null && $input_data['filter'] != 'general' ? 'data-parsley-type="'.$input_data['filter'].'"' : '';
                $input_data['field_label1'] = $this->_format_required_labels($input_data['field_label'], $input_data['required']);
                $input_digits = 4;
                $c = 1;

                ob_start();
                ?>
                    <div class="form-group field-clients-name">
                        <div class="col-lg-8">
                        <?php
                            while($input_digits >= $c){
                        ?>
                            <div class="mm-number-input-item">
                                <input name="<?php echo $input_data['model_label']; ?>[token][<?php echo $c ?>]" id="clients-token-<?php echo $c ?>" maxLength="1" size="1" min="0" max="9" pattern="[0-9]{1}" class="animated" data-parsley-error-message="" placeholder="X" <?php echo $filter_type; ?> <?php echo $required; ?>>
                            </div>
                        <?php
                            $c++; }
                        ?>
						</div>
                    </div>
                    <div class="col-lg-offset-2" style="clear: both;">
                        <p class="help-block"><?php echo $input_data['help_text']; ?></p>
                    </div>

                <script type="text/javascript">
                    $('.mm-number-input-item:nth-child(1) input').focus();

                    $('.mm-number-input-item').each(function(index) {
                        var item, id, input;
                        item = $(this);
                        id = index + 1;
                        input = item.children('input');
                        item.addClass('mm-number-input-item-'+id);
                        input.data('id',id);
                    });

                    $('.mm-number-input-item input').on('keyup', function(e) {

                        var item, value, id, count, pass = [];
                        item = $(this);
                        value = item.val();
                        id = item.data('id');
                        count = $('.mm-number-input-item').length;

                        var keyCode = e.keyCode || e.which;
                        if (keyCode >= 96 && keyCode <= 105) {
                            // Numpad keys
                            keyCode -= 48;
                        }

                        var key = String.fromCharCode(keyCode);
                        var number = parseInt(key);

                        if (key === '%'){
                            $('.mm-number-input-item-'+(id-1)+' input').focus().select();
                        }else if (key === "`"){
                            $('.mm-number-input-item-'+(id+1)+' input').focus().select();
                        }else if (e.which != 8 && e.which != 0 && (number < 0 || number > 10)) {
                            $('.mm-number-input-item-'+(id)+' input').val('');
                        }else{
                            if(!value) {
                                $('.mm-number-input-item-'+id+' input').focus().select();
                            } else {
                                if(id < count) {
                                    $('.mm-number-input-item-'+(id+1)+' input').focus().select();
                                } else {
                                    //
                                }
                            }
                        }
                    });
                </script>

                <?php
                return ob_get_clean();
                break;
            }
        }

        /**
         * @param string $label
         * @param int $required
         * @return string
         */
        private function _format_required_labels($label = '', $required = '')
        {
            $label = $required == 1 ? $label.'<span class="red-alert">*</span>' : $label;

            return $label;
        }

        /**
         * @param int $temp_prefs
         * @return mixed
         */
        private function _get_preference_tag($temp_prefs = 0)
        {
            $prefs = ['None', 'e-Mail', 'Cell Text Msg', 'Both (recommended)'];

            return $prefs[$temp_prefs];
        }

        /**
         * @param string $links
         * @return string
         */
        private function _generate_social_links($links = "")
        {
            $links = explode("\r\n", $links);

            ob_start();
            foreach($links as $key => $link) :
                if($link != ''):
                    ?>
                    <a href="<?php echo esc_url(sanitize_url($link)) ?>" target="_blank" title="<?php echo $link ?>"><?php echo $link; ?></a>
                    <br>
                <?php
                endif;
            endforeach;

            return ob_get_clean();
        }

        /**
         * @param array $mercs
         * @return string
         */
        private function _generate_merchandise_list($mercs = [])
        {
            ob_start();

            if($this->_count_array($mercs) > 0):
                foreach($mercs as $key => $merc):
                    ?>
                    <span class="tooltip-info label label-info" data-original-title="" style="white-space: nowrap;  text-decoration: none; cursor: default;"><?php echo esc_attr($merc); ?></span>
                <?php
                endforeach;
            endif;

            return ob_get_clean();
        }

        /**
         * @param array $tags
         * @return string
         */
        private function _generate_tag_list($tags = [])
        {
            ob_start();

            if($this->_count_array($tags) > 0):
                foreach($tags as $key => $tag):
                    ?>
                    <span class="tooltip-info label label-info" data-original-title="" style="white-space: nowrap;  text-decoration: none; cursor: default;"><?php echo esc_attr($tag); ?></span>
                <?php
                endforeach;
            endif;

            return ob_get_clean();
        }

        /**
         * @param int $temp_prefs
         * @return string
         */
        private function _generate_communication_prefs($temp_prefs = 3,$horizontal = 0)
        {
            $prefs = ['1' => 'Email', '2' => 'Cell Text Msg', '3' => 'Both (recommended)'];
            $horizontal = $horizontal == 1 ? 'radio-horizontal' : '';
            $temp_prefs = $temp_prefs == null ? 3 : $temp_prefs;

            ob_start();
            foreach($prefs as $key => $val) {
                ?>
                <div class="col-lg-8 radio <?php echo $horizontal; ?>">
                    <input type="radio" id="Clients[com_prefs]-<?php echo esc_attr($key)?>" name="Clients[com_prefs]" value="<?php echo esc_attr($key); ?>" <?php checked($key,$temp_prefs); ?>>
                    <label for="Clients[com_prefs]-<?php echo esc_attr($key); ?>" style="white-space: nowrap">
                        <?php echo sanitize_text_field($val); ?>
                    </label>
                </div>
            <?php
            }

            ?>
            <div class="form-group field-client-com_prefs_temp">
                <div class="col-lg-8">
                    <input type="hidden" name="Clients[com_prefs_temp]">
                    <div id="client-com_prefs_temp"></div>
                </div>
            </div>
            <?php

            return ob_get_clean();
        }

        /**
         * @param $fields
         * @param $attributes
         * @return string
         */
        private function _generate_payment_screen_field($field_html, $attributes)
        {
            $attributes = json_decode($attributes, true);

            ob_start();
            ?>
            <div id="letter" class="content-inner">
                <div id="curriculum-vitae" class="block">

                    <div id="block-content">
                        <div class="clients-form">
                            <?php echo $field_html; ?>
                        </div>
                    </div>
                    <div class="clear"></div>
                </div>
            </div>
            <?php

            return ob_get_clean();
        }

        /**
         * @param $fields
         * @param $attributes
         * @return string
         */
        private function _generate_terms_screen_field($field_html, $attributes)
        {
            $attributes = json_decode($attributes, true);

            ob_start();
            ?>

            <div id="letter" class="content-inner">
                <div id="curriculum-vitae" class="block">

                    <div id="block-content">
                        <div class="clients-form">
                            <?php echo $field_html; ?>
                        </div>
                    </div>
                    <div class="clear"></div>
                </div>
            </div>
            <?php

            return ob_get_clean();
        }

        /**
         * @param $fields
         * @param $attributes
         * @return string
         */
        private function _generate_amenities_screen_field($field_html, $attributes)
        {
            $attributes = json_decode($attributes, true);

            ob_start();
            ?>
            <div id="letter" class="content-inner">
                <div id="curriculum-vitae" class="block">

                    <div class="block-content">
                        <div class="clients-form">
                            <form data-parsley-required-message="a value is required" data-parsley-validate="" class="form-horizontal" name="step-3" action="<?php echo admin_url('admin-ajax.php'); ?>" id="clients-form" method="post" enctype="multipart/form-data">
                                <input type="hidden" name="_csrf" value="">
                                <input type="hidden" name="wvnmi_screen_name" value="amenities">
                                <?php wp_nonce_field('wvnmi_form_submission', 'wvnmi_verify_submission'); ?>
                                <input type="hidden" name="action" value="wvnmi_form_submission">
                                <?php echo $field_html; ?>
                            </form>
                        </div>
                    </div>
                    <div class="clear"></div>
                </div>
            </div>
            <?php

            return ob_get_clean();
        }

        /**
         * @param $fields
         * @param $attributes
         * @return string
         */
        private function _generate_uploads_screen_field($field_html, $attributes)
        {
            $attributes = json_decode($attributes, true);

            ob_start();
            ?>
            <div id="letters" class="content-inner">
                <div id="curriculum-vitae" class="block">

                    <div class="block-content">
                        <div class="clients-form">
                            <form data-parsley-required-message="this upload is required" class="form-horizontal" name="step-2" action="<?php echo admin_url('admin-ajax.php'); ?>" id="clients-form" method="post" enctype="multipart/form-data">
                                <input type="hidden" name="_csrf" value="">
                                <input type="hidden" name="wvnmi_screen_name" value="uploads">
                                <?php wp_nonce_field('wvnmi_form_submission', 'wvnmi_verify_submission'); ?>
                                <input type="hidden" name="action" value="wvnmi_form_submission">
                                <?php echo $field_html; ?>
                            </form>
                        </div>
                    </div>
                    <div class="clear"></div>
                </div>
            </div>
            <?php

            return ob_get_clean();
        }

        /**
         * @return string
         */
        private function _get_base_url()
        {
            global $wp;
            $base_url = home_url(add_query_arg(array(), $wp->request));
            return $base_url . "/";
        }

        /**
         * @param $fields
         * @param $client_a
         * @return string
         */
        private function _generate_privacysign_screen_field($field_html, $client_a, $event_a, $pre_launch_count = 0)
        {
            global $wp;
            $current_url = home_url(add_query_arg([], $wp->request));

            ob_start();

            // print_r($_SESSION);

            ?>
            <div id="" class="content-inner">
                <div id="" class="block">

                    <!-- DISPLAY FORM BLOCK -->
                    <div class="block-content">
                        <div class="clients-form">
                            <form data-parsley-required-message="this field is required" data-parsley-validate="" id="clients-form" class="form-horizontal" name="step-1" action="<?php echo admin_url('admin-ajax.php'); ?>" method="post" enctype="multipart/form-data">
                                <input type="hidden" name="_csrf" value="">
                                <input type="hidden" name="wvnmi_screen_name" value="privacysign">
                                <?php wp_nonce_field('wvnmi_form_submission', 'wvnmi_verify_submission'); ?>
                                <input type="hidden" name="action" value="wvnmi_form_submission">
                                <?php echo $field_html; ?>
                            </form>
                        </div>
                    </div>

                    <div class="clear"></div>
                </div>
            </div>
            <?php

            return ob_get_clean();
        }

        /**
         * @param $fields
         * @param $client_a
         * @return string
         */
        private function _generate_profile_screen_field($field_html, $client_a, $event_a, $pre_launch_count = 0)
        {
            global $wp;
            $current_url = home_url(add_query_arg([], $wp->request));

            ob_start();

            ?>
            <div id="" class="content-inner">
                <div id="" class="block">

                    <?php if($event_a['event_status'] == 0): ?>
                    <!-- DISPLAY pre_launch_count APPLICANTS -->
                        <div id="">
                            <h3><span style="color:#ff6b6b">Pre-Launch Applicants:</span> <?php echo $pre_launch_count; ?> of 5</h3>
                        </div>
                    <?php endif; ?>

                    <?php if($client_a['admin_audit'] == 1): ?>
                        <!-- DISPLAY audit message -->
                        <div class="well well-sm" style="margin-bottom:10px; margin-top:0px;">
                            <h4>Audit Mode: Some profile fields are read-only and can only be modified by the primary.
                            </h4>
                        </div>
                    <?php endif; ?>

                    <div id="">

                        <?php if(isset( $_SESSION['r1_book_code'] )): ?>
                        <!-- BOOK CODES FROM MAP BOOTH SELECTOR -->
                            <?php if(!empty($_SESSION['r1_book_code'] )): ?>
                                <?php
                                $booth_label = '';
                                list(,,$booth_label) = explode("-",base64_decode(sanitize_text_field($_SESSION['r1_book_code'])));
                                $booth_label = base64_decode($booth_label);
                                ?>
                                <div class="well well-sm" style="margin-bottom:10px; margin-top:0px;">
                                    <h4>Notice: Booth <strong><?php echo $booth_label ?></strong> will be reserved for you ONLY AFTER you fill out
                                        the first page of this application. If you already filled out an application, please navigate to your
                                        application profile to reserve the booth you selected on the map.</h4>
                                </div>
                            <?php endif; ?>
                        <?php endif; ?>

                        <?php if(isset( $_GET['rfc']) && $_GET['rfc'] != '' && $_GET['rfc'] != 'new'): ?>
                        <!-- TEXT BLOCK DISPLAYED IF INVITE CODE FOUND -->

                            <div class="well well-sm" style="margin-bottom:10px; margin-top:0px;">
                                <h4>This page has been pre-filled for your convenience.
                                    Please review the details for accuracy and then click <strong><?php echo $this->_button_label_swap('save_continue') ?></strong> at the bottom
                                    of this page.</h4>
                            </div>
                        <?php endif; ?>

                        <?php if(isset( $_GET['saved'])): ?>
                        <!-- TEXT BLOCK DISPLAYED IF INVITE CODE FOUND -->

                            <div class="well well-sm" style="margin-bottom:10px; margin-top:0px;">
                                <h4>Record Saved.</h4>
                            </div>
                        <?php endif; ?>
                    </div>

                    <!-- DISPLAY FORM BLOCK -->
                    <div class="block-content">
                        <div class="clients-form">
                            <!-- data-parsley-required-message="this field is required" -->
                            <form data-parsley-required-message="" data-parsley-validate="" id="clients-form" class="form-horizontal" name="step-1" action="<?php echo admin_url('admin-ajax.php'); ?>" method="post" enctype="multipart/form-data">
                                <input type="hidden" name="_csrf" value="">
                                <input type="hidden" name="wvnmi_screen_name" value="profile">
                                <?php wp_nonce_field('wvnmi_form_submission', 'wvnmi_verify_submission'); ?>
                                <input type="hidden" name="action" value="wvnmi_form_submission">
                                <?php echo $field_html; ?>
                            </form>
                        </div>
                    </div>

                    <div class="clear"></div>
                </div>
            </div>
            <?php

            return ob_get_clean();
        }

        /**
         * @param $fields
         * @param $client_a
         * @return string
         */
        private function _generate_session_screen_field($field_html, $client_a, $event_a, $pre_launch_count = 0)
        {
            global $wp;
            $current_url = home_url(add_query_arg([], $wp->request));

            ob_start();

            ?>
            <div id="" class="content-inner">
                <div id="" class="block">

                    <?php if($event_a['event_status'] == 0): ?>
                    <!-- DISPLAY pre_launch_count APPLICANTS -->
                        <div id="">
                            <h3><span style="color:#ff6b6b">Pre-Launch Applicants:</span> <?php echo $pre_launch_count; ?> of 5</h3>
                        </div>
                    <?php endif; ?>

                    <?php if($client_a['admin_audit'] == 1): ?>
                        <!-- DISPLAY audit message -->
                        <div class="well well-sm" style="margin-bottom:10px; margin-top:0px;">
                            <h4>Audit Mode: Some profile fields are read-only and can only be modified by the primary.
                            </h4>
                        </div>
                    <?php endif; ?>

                    <div id="">
                        <?php if(isset( $_GET['saved'])): ?>
                        <!-- TEXT BLOCK DISPLAYED IF INVITE CODE FOUND -->

                            <div class="well well-sm" style="margin-bottom:10px; margin-top:0px;">
                                <h4>Record Saved.</h4>
                            </div>
                        <?php endif; ?>
                    </div>

                    <!-- DISPLAY FORM BLOCK -->
                    <div class="block-content">
                        <div class="clients-form">
                            <form data-parsley-required-message="this field is required" data-parsley-validate="" id="clients-form" class="form-horizontal" name="step-1" action="<?php echo admin_url('admin-ajax.php'); ?>" method="post" enctype="multipart/form-data">
                                <input type="hidden" name="_csrf" value="">
                                <input type="hidden" name="wvnmi_screen_name" value="session">
                                <?php wp_nonce_field('wvnmi_form_submission', 'wvnmi_verify_submission'); ?>
                                <input type="hidden" name="action" value="wvnmi_form_submission">
                                <?php echo $field_html; ?>
                            </form>
                        </div>
                    </div>

                    <script type="text/javascript">
                    <?php echo $event_a['select_chained_js'] ?>
                    </script>

                    <div class="clear"></div>
                </div>
            </div>
            <?php

            return ob_get_clean();
        }

        /**
         * @param $fields
         * @param $client_a
         * @return string
         */
        private function _generate_login_screen_field($field_html, $client_a, $event_a, $pre_launch_count = 0)
        {
            global $wp;
            $current_url = home_url(add_query_arg([], $wp->request));

            /*
            <div class="well well-sm" style="margin-bottom:10px; margin-top:0px;">
                <i style="float:left; margin-right:10px;" class="fa fa-2x fa-exclamation-circle blue" aria-hidden="true"></i>
                Before uploading, please make sure your files are <strong>no larger than 16 Megs
                each.</strong>. Also see: <a href="https://www.google.com/search?num=10&amp;q=how+to+resize+image+files" target="_blank">How to resize images</a></div>
            */

            ob_start();

            ?>
            <div id="" class="content-inner">
                <div id="" class="block wellx well-register">

                    <?php if($event_a['event_status'] == 0 && $event_a['rec_type'] == 1): ?>
                    <!-- DISPLAY pre_launch_count APPLICANTS -->
                        <div id="">
                            <h3><span style="color:#ff6b6b">Pre-Launch Applicants:</span> <?php echo $pre_launch_count; ?> of 5</h3>
                        </div>
                    <?php endif; ?>

                    <?php if(isset( $_SESSION['r1_book_code'] )): ?>
                        <?php if(!empty($_SESSION['r1_book_code'] )): ?>
                            <!-- BOOK CODES FROM MAP BOOTH SELECTOR -->
                            <div id="">
                                <?php
                                $booth_label = '';
                                list(,,$booth_label) = explode("-",base64_decode(sanitize_text_field($_SESSION['r1_book_code'])));
                                $booth_label = base64_decode($booth_label);
                                ?>
                                <div class="well well-sm" style="margin-bottom:10px; margin-top:10px;">
                                    <h4>Selected: Booth <strong><?php echo $booth_label ?></strong></h4>
                                </div>
                            </div>
                        <?php endif; ?>
                    <?php endif; ?>

                    <!-- DISPLAY FORM BLOCK -->
                    <div class="block-content">
                        <div class="clients-form">
                            <form data-parsley-required-message="this field is required" data-parsley-validate="" id="clients-form" class="form-horizontal" name="step-1" action="<?php echo admin_url('admin-ajax.php'); ?>" method="post" enctype="multipart/form-data">
                                <input type="hidden" name="_csrf" value="">
                                <input type="hidden" name="wvnmi_screen_name" value="login">
                                <?php wp_nonce_field('wvnmi_form_submission', 'wvnmi_verify_submission'); ?>
                                <input type="hidden" name="action" value="wvnmi_form_submission">
                                <?php echo $field_html; ?>
                            </form>
                        </div>
                    </div>

                    <div class="clear"></div>
                </div>
            </div>
            <?php

            return ob_get_clean();
        }

        /**
         * @param $fields
         * @param $client_a
         * @return string
         */
        private function _generate_register_screen_field($field_html, $client_a, $event_a, $pre_launch_count = 0)
        {
            global $wp;
            $current_url = home_url(add_query_arg([], $wp->request));

            ob_start();

            ?>
            <div id="" class="content-inner">
                <div id="" class="block wellx well-register">

                    <!-- DISPLAY FORM BLOCK -->
                    <div class="block-content">
                        <div class="clients-form">
                            <form data-parsley-required-message="this field is required" data-parsley-validate="" id="clients-form" class="form-horizontal" name="step-1" action="<?php echo admin_url('admin-ajax.php'); ?>" method="post" enctype="multipart/form-data">
                                <input type="hidden" name="_csrf" value="">
                                <input type="hidden" name="wvnmi_screen_name" value="register">
                                <?php wp_nonce_field('wvnmi_form_submission', 'wvnmi_verify_submission'); ?>
                                <input type="hidden" name="action" value="wvnmi_form_submission">
                                <?php echo $field_html; ?>
                            </form>
                        </div>
                    </div>

                    <div class="clear"></div>
                </div>
            </div>
            <?php

            return ob_get_clean();
        }

        /**
         * @param $fields
         * @param $client_a
         * @return string
         */
        private function _generate_passreset_screen_field($field_html, $client_a, $event_a, $pre_launch_count = 0, $mode = '')
        {
            global $wp;
            $current_url = home_url(add_query_arg([], $wp->request));

            ob_start();

            ?>
            <div id="" class="content-inner">
                <div id="" class="block wellx well-register">

                    <!-- DISPLAY FORM BLOCK -->
                    <div class="block-content">
                        <div class="clients-form">
                            <form data-parsley-required-message="this field is required" data-parsley-validate="" id="clients-form" class="form-horizontal" name="step-1" action="<?php echo admin_url('admin-ajax.php'); ?>" method="post" enctype="multipart/form-data">
                                <input type="hidden" name="_csrf" value="">
                                <input type="hidden" name="wvnmi_screen_name" value="passreset">
                                <?php wp_nonce_field('wvnmi_form_submission', 'wvnmi_verify_submission'); ?>
                                <input type="hidden" name="action" value="wvnmi_form_submission">
                                <?php echo $field_html; ?>
                            </form>
                        </div>
                    </div>

                    <div class="clear"></div>
                </div>
            </div>
            <?php

            return ob_get_clean();
        }

        /**
         * @param $current
         * @param $self
         * @param $screen
         * @return string
         */
        private function _check_step_completeness($current, $self, $screen)
        {
            global $wp_query;

            // Dynamic form_key with url slug
            $attributes['id_hash'] = isset($wp_query->query_vars['id_hash']) ? $wp_query->query_vars['id_hash'] : 0;
            $request_url = $this->base_request_url . $attributes['id_hash'] . "/";

            switch($screen) {

                case "login":
                    if($current < $self) return "";
                    if($current == $self) return "active";

                    return "complete";

                    break;

                case "register":
                    if($current < $self) return "";
                    if($current == $self) return "active";

                    return "complete";

                    break;

                case "profile":
                    if($current < $self) return "";
                    if($current == $self) return "active";
                    $errors = 0;
                    $attributes = is_array($this->event_attributes) ? $this->event_attributes : json_decode( $this->event_attributes, true);

                    if(isset($attributes['applicant_a']['client_type'])) {
                        $client_types = json_decode($attributes['applicant_a']['client_type'], true);
                        if($this->_count_array($client_types) == 0) {
                            $errors++;
                        }
                    }else{
                        $errors++;
                    }

                    if($errors) {
                        return "error";
                    }else {
                        return "complete";
                    }
                    break;

                case "session":
                    if($current < $self) return "";
                    if($current == $self) return "active";
                    $errors = 0;
                    $attributes = is_array($this->event_attributes) ? $this->event_attributes : json_decode( $this->event_attributes, true);

                    if(isset($attributes['applicant_a']['client_type'])) {
                        $client_types = json_decode($attributes['applicant_a']['client_type'], true);
                        if($this->_count_array($client_types) == 0) {
                            $errors++;
                        }
                    }else{
                        $errors++;
                    }

                    if($errors) {
                        return "error";
                    }else {
                        return "complete";
                    }
                    break;

                case "uploads":
                    if($current < $self) return "";
                    if($current == $self) return "active";
                    if($current > $self) {

                        $attributes = is_array($this->event_attributes) ? $this->event_attributes : json_decode($this->event_attributes, true);

                        if(isset( $_GET['pk']) && $_GET['pk'] != '') {
                            /*
                            'uploads'
                            'terms'
                            'map'
                            'fee'
                             * */
                            if(in_array('uploads', $attributes['error_details_a'])){
                                return "error";
                            }else{
                                return "complete";
                            }

                        }else{
                            return "error";
                        }
                    }
                    break;

                case "amenities":
                    if($current < $self) return "";
                    if($current == $self) return "active";
                    if($current > $self) {

                        $attributes = is_array($this->event_attributes) ? $this->event_attributes : json_decode($this->event_attributes, true);

                        if(isset( $_GET['pk']) && $_GET['pk'] != '') {
                            /*
                            'uploads'
                            'terms'
                            'map'
                            'fee'
                             * */
                            if(in_array('map', $attributes['error_details_a'])){
                                return "error";
                            }else{
                                return "complete";
                            }

                        }else{
                            return "complete";
                        }
                    }
                    break;

                case "badges":
                    if($current < $self) return "";
                    if($current == $self) return "active";
                    if($current > $self) {

                        $attributes = is_array($this->event_attributes) ? $this->event_attributes : json_decode($this->event_attributes, true);

                        if(isset( $_GET['pk']) && $_GET['pk'] != '') {
                            /*
                            'uploads'
                            'terms'
                            'map'
                            'fee'
                             * */
                            if(in_array('map', $attributes['error_details_a'])){
                                return "error";
                            }else{
                                return "complete";
                            }

                        }else{
                            return "complete";
                        }
                    }
                    break;

                case "terms":
                    if($current < $self) return "";
                    if($current == $self) return "active";
                    if($current > $self) {
                        $attributes = is_array($this->event_attributes) ? $this->event_attributes : json_decode($this->event_attributes, true);

                        if(isset( $_GET['pk']) && $_GET['pk'] != '') {
                            /*
                            'uploads'
                            'terms'
                            'map'
                            'fee'
                             * */
                            if(in_array('terms', $attributes['error_details_a'])){
                                return "error";
                            }else{
                                return "complete";
                            }

                        }else{
                            return "complete";
                        }
                    }
                    break;

                case "payment":
                    if($current < $self) return "";
                    // if($current == $self) return "active";
                    if($current == $self) {
                        $attributes = is_array($this->event_attributes) ? $this->event_attributes : json_decode($this->event_attributes, true);

                        if(isset( $_GET['pk']) && $_GET['pk'] != '') {
                            /*
                            'uploads'
                            'terms'
                            'map'
                            'fee'
                             * */
                            if(in_array('payment', $attributes['error_details_a'])){
                                return "error";
                            }else{
                                return "complete";
                            }

                        }else{
                            return "complete";
                        }
                    }
                    break;

                default:
                    break;
            }
        }

        /**
         * @param $screen
         * @return string
         */
        private function _get_steps_list($screen, $formData)
        {
            global $wp;
            $current_url = home_url(add_query_arg([], $wp->request));

            $event_a = is_array($this->event_attributes) ? $this->event_attributes : json_decode($this->event_attributes,true);

            $profile_status = false;
            $is_temp_pk = false;
            $steps = [];

            if(isset( $_GET['pk']) && $_GET['pk'] != '') {
                $profile_status = true;
                if(stristr($_GET['pk'], '.temp_pk')){
                    $is_temp_pk = true;
                }
            }

            // 1 = exhibit, 3 = ticket
            $form_type = $event_a['event_a']['rec_type'];
            $ticketing_nav_order = $event_a['event_a']['nav_order'];

            $current_screen = self::_get_current_screen($form_type, $ticketing_nav_order);

            if(isset($formData['nav_steps_list'])){
                $steps = $formData['nav_steps_list'][0];
                $nav_label_replace_a = $formData['nav_steps_list'][1];
                $extra_amenity_id = $formData['nav_steps_list'][2];

                // insert last step if not in navigation
                if(!in_array('payment', $steps)){
                    $steps[] .= 'payment';
                }

            }else{
                $steps = ['login', 'profile', 'session', 'uploads', 'amenities', 'badges', 'terms', 'payment'];
            }

            if($form_type == 3 && ($current_screen !== 'login' && $current_screen !== 'register')){
                $ticket_form = true;

                if(($step_login_key = array_search('login',$steps)) !== false){
                    if(isset($steps[$step_login_key])){
                        unset($steps[$step_login_key]);
                    }
                }
                if(isset($nav_label_replace_a)){
                    if(($step_login_key = array_search('login',$nav_label_replace_a)) !== false){
                        //if(isset($steps[$nav_label_replace_a])){
                        //    unset($steps[$nav_label_replace_a]);
                        //}
                    }
                }
            }

            $steps = array_values($steps);
            ksort($steps);

            if(isset($formData['status'])){
                if($formData['status'] == '404'){
                    $steps = ['login', 'profile'];
                }
            }

            $origin_applic_id = isset($formData["applicant_a"]["origin_applic_id"]) ? $formData["applicant_a"]["origin_applic_id"] : 0;

            // only display profile for badge sub-applicants
            if((int)$origin_applic_id > 0) {
                $steps = ['profile'];
            }

            $current_step = array_search($screen, $steps);

            ob_start();

            foreach($steps as $key => $val) {

                $null_link = false;
                if($is_temp_pk){
                    if($val == 'payment'){
                        $null_link = true;
                    }
                }

                $is_last_step = ($this->_count_array($steps) == $current_step+1 && $current_step == $key)  ? true : false;

                $mt = str_replace('.', '', microtime(true));

                $nav_label = isset($nav_label_replace_a[$val]) ? $nav_label_replace_a[$val] : $val;

                $li_class = $this->_check_step_completeness($current_step+1, $key+1, $steps[$key]);

                $step_style = ($li_class == 'active' || $is_last_step) ? 'font-weight:bold;' : '';

                $link_class = ($li_class == 'active' || $is_last_step) ? 'btn-nav btn-nav-active' : 'btn-nav btn-nav-inactive';

                // append badge navigation
                if($steps[$key] == 'badges' && $extra_amenity_id > 0){
                    $val .= "&extra=$extra_amenity_id";
                }

                $skip_menu = false;

                $origin_applic_id = 0;
                if(isset($formData["applicant_a"]["origin_applic_id"])) {
                    $origin_applic_id = $formData["applicant_a"]["origin_applic_id"];
                }

                if($origin_applic_id > 0) {
                    ?>
                    <div id="" class="content-inner">
                        <div id="" class="block">
                            <div class="block-content">
                                <a class="<?php echo $link_class ?>" href="<?php echo esc_url(sanitize_url($current_url . "/?" . $val . "&pk=" . sanitize_text_field($_GET['pk']) . "&v=" . $mt)); ?>"><?= ucfirst($nav_label); ?></a>
                            </div>
                        </div>
                    </div>
                    <?php
                }elseif(!$skip_menu){
                    ?>
                    <li id="<?php echo esc_attr($key); ?>" data-step="<?php echo($key + 1); ?>" class="<?php echo $li_class; ?>">
                        <span class="step"><?php echo($key + 1) ?></span>
                        <span class="title" style="<?php echo $step_style; ?>">
                            <?php if ($null_link): ?>
                                <a class="<?php echo $link_class ?>"
                                   href="#"><?= ucfirst($nav_label); ?></a>
                            <?php elseif ($profile_status && isset( $_GET['rfc'])): ?>
                                <a class="<?php echo $link_class ?>"
                                   href="<?php echo esc_url(sanitize_url($current_url . "/?profile&pk=" . sanitize_text_field($_GET['pk']) . "&rfc=" . $_GET['rfc'])); ?>"><?= ucfirst($nav_label); ?></a>
                            <?php elseif ($profile_status): ?>
                                <a class="<?php echo $link_class ?>"
                                   href="<?php echo esc_url(sanitize_url($current_url . "/?" . $val . "&pk=" . sanitize_text_field($_GET['pk']) . "&v=" . $mt)); ?>"><?= ucfirst($nav_label); ?></a>
                            <?php elseif (!$profile_status && isset( $_SESSION['pk'])): ?>
                                <a class="<?php echo $link_class ?>"
                                   href="<?php echo esc_url(sanitize_url($current_url . "/?" . $val . "&pk=" . $_SESSION['pk'] . "&v=" . $mt)); ?>"><?= ucfirst($nav_label); ?></a>
                            <?php elseif ($val == 'profile' && !isset($_GET['pk']) && $form_type == 3): ?>
                                <a class="<?php echo $link_class ?>"
                                   href="<?php echo esc_url(sanitize_url($current_url . "/?profile")); ?>"><?= ucfirst($nav_label); ?></a>
                            <?php else: ?>
                                <a class="<?php echo $link_class ?>"
                                   href="<?php echo esc_url(sanitize_url($current_url)); ?>/"><?php echo ($val == "terms") ? ucfirst($nav_label) : ucfirst($nav_label); ?></a>
                            <?php endif; ?>
                        </span>
                    </li>
                <?php
                }
            }

            return ob_get_clean();
        }

        /**
         * @param string $screen
         * @param string $form
         * @return string
         */
        private function _set_application_steps($screen = "", $form = "", $formData = "", $raw_output = false)
        {
            $formData["applicant_a"]["origin_applic_id"] = isset($formData["applicant_a"]["origin_applic_id"]) ? $formData["applicant_a"]["origin_applic_id"] : 0;

            if(!$raw_output){
                $origin_applic_id = isset($formData["applicant_a"]["origin_applic_id"]) ? $formData["applicant_a"]["origin_applic_id"] : 0;

                if((int)$origin_applic_id == 0) {
                    $form .= "<ul id=\"steps\" class=\"steps\">";
                }

                $form .= $this->_get_steps_list($screen, $formData);

                if((int)$origin_applic_id == 0) {
                    $form .= "</ul>";
                }
            }
            return $form;
        }

        /**
         * @param $event_a
         * @param string $form
         * @return string
         */
        private function _set_application_title($event_a, $form = "", $raw_output = false)
        {
            global $wp;
            $current_url = esc_url(sanitize_url(home_url(add_query_arg([], $wp->request))));

            if($raw_output){
                return $form;

            }else{

                $event_a = json_decode($event_a, true);
                $attributes = is_array($this->event_attributes) ? $this->event_attributes : json_decode( $this->event_attributes, true);

                // print_r($attributes); die;

                if (isset($attributes['event_a']['logo_img_url']) && !empty($attributes['event_a']['logo_img_url'])) {
                    $logo_image = "<img class='logo-image' src='{$attributes['event_a']['logo_img_url']}'>";
                }

                if(isset($event_a['event_a']['home_url'])){
                    $home_url = isset($logo_image) ? "<a href='". esc_url(sanitize_url($event_a['event_a']['home_url'])) . "'>{$logo_image}</a>" : "<a href='". esc_url(sanitize_url($event_a['event_a']['home_url'])) . "'>" .  $event_a['event_a']['form_name'] . "</a>";

                }else{
                    // $home_url = "<a href='/'>Home</a>";
                    $home_url = isset($logo_image) ? "<a href='/'>{$logo_image}</a>" : "<a href='/'>" .  $event_a['event_a']['form_name'] . "</a>";
                }

                if(isset($event_a['application_status'])){
                    $status = $event_a['application_status'] == 1 ? " <span class='green-alert'>Complete!</span>" : " <span class='red-alert'>Incomplete</span>";
                }else{
                    $status = 'New';
                }

                if(isset($attributes['client_a']['name']) && $attributes['client_a']['name'] != ''):
                    $base_url = esc_url(sanitize_url($this->_get_base_url()));
                    $pk = isset($_GET['pk']) ? sanitize_text_field($_GET['pk']) : '';

                    $is_logged_in = isset($attributes['client_a']['is_logged_in']) ? $attributes['client_a']['is_logged_in'] : false;

                    $login_label = "{$attributes['client_a']['name']} ";

                    if($is_logged_in){
                         $login_label .= "<a class='btn-nav btn-blue' href='{$base_url}?clearsession&pk={$pk}'>logout</a>";
                    }else{
                        $login_label .= "<a title='Clear Temporary Session' class='tooltip btn-nav btn-red' href='{$base_url}?clearsession'>x</a> ";
                        $login_label .= "<a class='btn-nav btn-blue' href='{$base_url}?login'>login</a>";
                    }

                    $pk = $pdf_link = '';

                    if(isset($attributes['applicant_a'])
                        && $event_a['event_a']['hide_ticket'] == 0):
                        // if notticket holder, continue
                        if($attributes['applicant_a']['rec_type'] == 1):
                            if($pk = $attributes['applicant_a']['profile_key']):

                                if($attributes['fee_total'] > 0):

                                    $fee_total_formatted = $attributes['currency_symbol'].number_format($attributes['fee_total'],2);
                                    $pdf_link = "<a title='Due: {$fee_total_formatted}' class='tooltip btn-nav btn-blue' href='" . esc_url(sanitize_url($this->base_site_url . "/invoice/" . $pk)) . "'>
                                    <i style='color:#c45353' aria-hidden='true' class='fa fa-1x fa-circle'></i> Invoice</a>
                                    </a>";
                                else:
                                    $pdf_link = "<a title='View Invoice' class='btn-nav btn-blue' href='" . esc_url(sanitize_url($this->base_site_url . "/invoice/" . $pk)) . "'>
                                    <i style='color:#aad05e' aria-hidden='true' class='fa fa-1x fa-circle'></i> Invoice</a>
                                    </a>";
                                endif;
                            endif;
                        elseif($attributes['applicant_a']['rec_type'] > 1):
                            if($pk = $attributes['applicant_a']['profile_key']):

                                if($attributes['fee_total'] > 0):

                                    $fee_total_formatted = $attributes['currency_symbol'].number_format($attributes['fee_total'],2);
                                    $pdf_link = "<a title='Due: {$fee_total_formatted}' class='tooltip btn-nav btn-red' href='" . esc_url(sanitize_url($this->base_site_url . "/ticket/" . $pk)) . "'>
                                    <i aria-hidden='true' class='fa fa-1x fa-ticket'></i> {$event_a['event_a']['invoice_label']}</a>
                                    </a>";
                                else:
                                    $pdf_link = "<a title='View Ticket' class='btn-nav btn-red' href='" . esc_url(sanitize_url($this->base_site_url . "/ticket/" . $pk)) . "'>
                                    <i aria-hidden='true' class='fa fa-1x fa-ticket'></i> {$event_a['event_a']['invoice_label']}</a>
                                    </a>";
                                endif;
                            endif;
                        endif;
                    endif;
                else:
                    $base_url = esc_url(sanitize_url($this->_get_base_url()));

                    $login_link = " <a class='btn-nav btn-blue' href='{$base_url}?login'>login</a>";

                    // <div class='header-recover'><span style='font-style:italic' class='green-alert'>Please login to access this form</span>
                    $login_label = "<div style='float:right; text-align: left;'>
                    {$login_link}</div>";
                    $pdf_link = '';
                endif;

                if(isset($event_a['event_a']['title'])) {

                    if(isset($logo_image)) {
                        $form_header = "<div class='pull-left form-logo-header'>{$home_url}</div>";
                    }else{
                        $form_header = "<div class='pull-left form-title-header'><h2>{$home_url}</h2></div>";
                    }

                    $form_header .= "<div class='pull-right form-info-header' style='margin-bottom: 6px;'>
                    <div class='pull-right'>
                        <h5>{$login_label}</h5>
                    </div>";

                    if(isset($attributes['client_a']['name']) && $attributes['client_a']['name'] != ''):
                        $form_header .= "<div class='pull-right' style='clear:both'>
                        <h4>Status: {$status} {$pdf_link}</h4>
                    </div>";
                    endif;

                    /* debug */
                    if(isset($_GET['pk']) && 1 == 2) {
                        if(strlen($_GET['pk']) == 0){
                            $debug = true;

                            if(isset($_SESSION['api_token'])){
                                $form_header .= "<br>api_token: {$_SESSION['api_token']}";
                            }
                        }
                    }

                    $form_header .= "</div>";

                    return $form . $form_header;
                }else{
                    return "";
                }
            }
        }

        /**
         * @param $event_a
         * @param string $form
         * @return string
         */
        private function _get_signature_status($attributes, $request_url)
        {
            global $wp_query;

            // Dynamic form_key with url slug
            $attributes['id_hash'] = $wp_query->query_vars['id_hash'] ? $wp_query->query_vars['id_hash'] : 0;
            $request_url = $this->base_request_url . $attributes['id_hash'] . "/";

            $no_signatures_required = $terms_require_sign = $contract_require_sign = $no_contract_signature_required = false;
            $terms_signed = $contract_signed = $approval_status = '';

            if(isset( $_GET['pk']) && $_GET['pk'] != '') {

                $approval_status = $attributes['applicant_a']['approval_status'];
                $terms_id = $attributes['event_a']['terms_id'];
                $contract = $attributes['event_a']['contract'];
                $c_cfg2 = $attributes['event_a']['c_cfg2'];

                if ($approval_status != 1) {
                    if ($terms_id > 0) {
                        $terms_require_sign = true;
                    } elseif ($contract == 1 && $c_cfg2 == 1) {
                        $contract_require_sign = true;
                    }

                } elseif ($approval_status == 1) {
                    if ($terms_id > 0) {
                        $terms_require_sign = true;
                    }
                    if ($contract == 1 && $c_cfg2 == 2) {
                        $contract_require_sign = true;
                    }
                }

                if($attributes['event_a']['terms_id'] == null && $attributes['event_a']['contract'] == 0){
                    $no_signatures_required = true;
                }else{
                    $applicant_signature = json_decode($this->_get_data("signature", $attributes), true);
                }

                if(isset($applicant_signature['signature'])) {
                    foreach($applicant_signature['signature'] AS $signature){
                        if($signature['terms_scope'] == 1){
                            $terms_signed = true;
                        }
                        if($signature['terms_scope'] == 2){
                            $contract_signed = true;
                        }
                    }
                }
            }

            $sign_status_passed = true;

            // no terms or contract
            if($no_signatures_required){
                return true;

            }else{
                if($terms_require_sign && !$terms_signed) {
                    $sign_status_passed = false;
                }
                if($contract_require_sign && !$contract_signed) {
                    $sign_status_passed = false;
                }
            }
            return $sign_status_passed;
        }

        /*
        * @param
        * @return array('mem_limit','upload_max_filesize','post_max_size')
        */
        private function _get_php_limits()
        {
            $php_env_limits['mem_limit'] = ini_get('memory_limit');
            $php_env_limits['upload_max_filesize'] = ini_get('upload_max_filesize');
            $php_env_limits['post_max_size'] = ini_get('post_max_size');

            // Memory Limit: $this->_get_php_limits()['mem_limit']
            // Max Upload Size: $this->_get_php_limits()['upload_max_filesize']
            // Max Post Size: $this->_get_php_limits()['post_max_size']

            return $php_env_limits;
        }

        /*
        * @param
        * @return string
        */
        private function _formatPhoneNumber($phoneNumber, $show_last4 = false) {
            $phoneNumber = preg_replace('/[^0-9]/','',$phoneNumber);

            if(strlen($phoneNumber) > 10) {
                $countryCode = substr($phoneNumber, 0, strlen($phoneNumber)-10);
                $areaCode = substr($phoneNumber, -10, 3);
                $nextThree = substr($phoneNumber, -7, 3);
                $lastFour = substr($phoneNumber, -4, 4);

                if($show_last4){
                    $areaCode = preg_replace('/(\K)?./s', 'x', $areaCode);
                    $countryCode = preg_replace('/(\K)?./s', 'x', $countryCode);
                    $nextThree = preg_replace('/(\K)?./s', 'x', $nextThree);
                }
                $phoneNumber = '+'.$countryCode.' ('.$areaCode.') '.$nextThree.'-'.$lastFour;
            }
            else if(strlen($phoneNumber) == 10) {
                $areaCode = substr($phoneNumber, 0, 3);
                $nextThree = substr($phoneNumber, 3, 3);
                $lastFour = substr($phoneNumber, 6, 4);

                if($show_last4){
                    $areaCode = preg_replace('/(\K)?./s', 'x', $areaCode);
                    $nextThree = preg_replace('/(\K)?./s', 'x', $nextThree);
                }

                $phoneNumber = '('.$areaCode.') '.$nextThree.'-'.$lastFour;
            }
            else if(strlen($phoneNumber) == 7) {
                $nextThree = substr($phoneNumber, 0, 3);
                $lastFour = substr($phoneNumber, 3, 4);

                if($show_last4){
                    $nextThree = preg_replace('/(\K)?./s', 'x', $nextThree);
                }

                $phoneNumber = $nextThree.'-'.$lastFour;
            }
            return $phoneNumber;
        }

        /**
         * @param $current
         * @param $self
         * @param $screen
         * @return string
         */
        private function _button_label_swap($button = 'save_continue', $screen = '')
        {
            $attributes = is_array($this->event_attributes) ? $this->event_attributes : json_decode( $this->event_attributes, true);
            global $wp_query;

            $button_label_a = [
                'save_continue' => 'Save & Continue',
                'upload_docs' => 'Upload Docs',
                'skip' => 'Skip',
                'download' => 'Download',
                'submit_payment' => 'Submit Payment',
                'sign_here' => 'Sign Here',
                'clear' => 'Clear',
                'cancel' => 'Cancel',
                'signature_save' => 'Save Signature',
                'signature_req' => 'Signature required',
                'docs_req' => 'Documents required',
                'amenities_req' => 'Amenity selection required',
                'booth_select_button' => 'Select Booth',
                'close' => 'Close',
                'select_another' => 'Select Another',
                'close_map' => 'Close Map'
            ];

            $button_custom_labels = $attributes['event_a']['button_labels'];

            return !empty($button_custom_labels[$button]) ? $button_custom_labels[$button] : $button_label_a[$button];
        }

        private function byte2Size($bytes, $RoundLength=1) {
            $kb = 1024;         // Kilobyte
            $mb = 1024 * $kb;   // Megabyte
            $gb = 1024 * $mb;   // Gigabyte
            $tb = 1024 * $gb;   // Terabyte

            $bytes = $bytes * 1024;

            if($bytes < $kb) {
                if(!$bytes){
                    $bytes = '0';
                }
                return (($bytes + 1)-1).' B';
            } else if($bytes < $mb) {
                return round($bytes/$kb,$RoundLength).' KB';
            } else if($bytes < $gb) {
                return round($bytes/$mb,$RoundLength).' MB';
            } else if($bytes < $tb) {
                return round($bytes/$gb,$RoundLength).' GB';
            } else {
                return round($bytes/$tb,$RoundLength).' TB';
            }
        }

        private function _clear_cookies()
        {
            if(isset($_COOKIE['rpk'])){
                unset($_COOKIE['rpk']);
                setcookie('rpk', '', 0 * DAY_IN_SECONDS, COOKIEPATH, COOKIE_DOMAIN);
            }
            if(isset($_COOKIE['rfc'])){
                unset($_COOKIE['rfc']);
                setcookie('rfc', '', 0 * DAY_IN_SECONDS, COOKIEPATH, COOKIE_DOMAIN);
            }
            if(isset($_COOKIE['pk'])){
                unset($_COOKIE['pk']);
                setcookie('pk', '', 0 * DAY_IN_SECONDS, COOKIEPATH, COOKIE_DOMAIN);
            }
        }

        private function _count_array($a = false) {
            $count = 0;
            if(isset($a)){
                if(is_array($a)){
                    $count = count($a);
                }
            }
            return $count;
        }

        /**
         * @param $form
         * @return string
         */
        private function _wrap_with_parents($form = "", $raw_output = false)
        {
        $attributes = is_array($this->event_attributes) ? $this->event_attributes : json_decode( $this->event_attributes, true);
        ob_start();
        ?>
        <?php if($raw_output): ?>

            <?php echo $form; ?>

        <?php else: ?>

            <div id="wrapper" class="wrapper">
                <div id="container">
                    <div id="apply">
                        <div class="content">

                            <?php if($this->_count_array($attributes['transport_form_id_a']) > 0): ?>
                            <div style="width:100%; display: inline-block;">
                                <button id="form-transport-button" style="width:auto; float: right;" class="btn-nav btn-blue" href="#">
                                <i aria-hidden="true" class="fa fa-1x fa-chevron-right"></i>
                                </button>
                                <select id="form-transport-url" style="width:auto; float: right;" class="form-transport" name="" required="">
                                <option value="">Available forms...</option>
                                <?php foreach($attributes['transport_form_id_a'] AS $form_url => $form_label): ?>
                                    <?php
                                    $select = '';
                                    if(stristr($form_url,'_https:')){
                                        $select = 'selected';
                                        $form_url = str_replace('_https:','https:', $form_url);
                                    }
                                    ?>
                                    <option value="<?php echo $form_url ?>" <?php echo $select ?>><?php echo $form_label ?></option>
                                <?php endforeach; ?>
                                </select>
                            </div>
                            <?php endif; ?>

                            <?php echo $form; ?>

                            <div id="poweredby">
                            <?php
                            if ($this->footer_powered_by_option == 1){
                                ?>
                                Powered by <a href="https://www.wavenami.com">Wavenami</a>
                            <?php
                            }
                            ?>
                            v1.0.11
                            : <a href="https://app.wavenami.com/privacy-policy" target="_blank">Privacy Policy</a>
                            <?php
                            if(1 == 2){
                                echo "<hr>";
                                if($_SESSION['temp_pk']){
                                    echo "session::temp_pk: ";
                                    echo $_SESSION['temp_pk'];
                                    echo "<br>";
                                }
                                if($_SESSION['pk']){
                                    echo "session::pk: ";
                                    echo $_SESSION['pk'];
                                    echo "<br>";
                                }
                            }
                        ?>
                        </div>

                            <div class="clear"></div>
                        </div>
                    </div>
                </div>
            </div>

            <?php if($attributes['event_a']['chat_client'] == 'chatra'): ?>
                <?php if(!empty($attributes['event_a']['chat_id'])): ?>

                    <script>
                        window.ChatraSetup = {
                            buttonPosition: window.innerWidth < 1024? // width threshold
                                'br': // chat button position on small screens
                                'br'  // chat button position on big screens
                        };
                    </script>

                    <!-- Chatra {literal} -->
                    <script>
                        (function(d, w, c) {
                            w.ChatraID = '<?php echo $attributes['event_a']['chat_id']; ?>';
                            var s = d.createElement('script');
                            w[c] = w[c] || function() {
                                (w[c].q = w[c].q || []).push(arguments);
                            };
                            s.async = true;
                            s.src = 'https://call.chatra.io/chatra.js';
                            if (d.head) d.head.appendChild(s);
                        })(document, window, 'Chatra');
                    </script>
                    <!-- /Chatra {/literal} -->

                    <?php if(isset($attributes['client_a']['name']) && $attributes['client_a']['name'] != ''): ?>
                        <script type="text/javascript">
                            Chatra('setIntegrationData', {
                                /* main properties */
                                name: '<?php echo htmlspecialchars_decode($attributes['client_a']['name']). " ({$attributes['client_a']['first_name']} {$attributes['client_a']['last_name']})"; ?>',
                                email: '<?php echo $attributes['client_a']['email']; ?>',
                                phone: '<?php echo $attributes['client_a']['phone']; ?>'
                                /* any number of custom properties */
                                /* 'What does he do': 'Goes to Oz with his friends' */
                            });
                        </script>
                    <?php endif; ?>
                <?php endif; ?>

            <?php elseif($attributes['event_a']['chat_client'] == 'hubspot'): ?>

                <?php if(!empty($attributes['event_a']['chat_id'])): ?>
                <?php
                    // https://knowledge.hubspot.com/reports/what-is-the-hs-scripts-embed-code-loading-on-my-website
                    $hubspot_script_url = '//js.hs-scripts.com/';
                ?>
                  <script type="text/javascript" id="hs-script-loader" async defer src="<?php echo $hubspot_script_url ?><?php echo $attributes['event_a']['chat_id'] ?>.js"></script>
                  <script>
                    var _hsq = window._hsq = window._hsq || [];
                    _hsq.push(["identify",{
                         email: "<?php echo $attributes['client_a']['email'] ?>",
                         firstName: "<?php echo $attributes['client_a']['first_name'] ?>",
                         lastName: "<?php echo $attributes['client_a']['last_name'] ?>"
                    }]);
                    _hsq.push(["trackPageView"]);
                </script>
                <?php endif; ?>

            <?php endif; ?>
        <?php endif; ?>
        <?php
        return ob_get_clean();
    }
}