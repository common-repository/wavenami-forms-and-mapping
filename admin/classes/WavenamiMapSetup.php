<?php

class WavenamiMapSetup {

    public static $key = 'wvnmi_map_setup';

    public static $settings = array();

    function __construct() {

        add_action( 'admin_init', array( &$this, '_add_maps_list' ) );

        self::$settings = $this->get_settings_options();
    }

    public static function get_settings_options() {

        // load the settings from the database
        $settings_options = (array) get_option( self::$key );

        return $settings_options;
    }

    function _add_maps_list()
    {
        add_settings_section('maps_list_section', 'Available Maps', [&$this, 'section_available_maps_list'], self::$key);
    }

    function section_available_maps_list()
    {
        echo $this->_generate_maps_list();
    }

    private function _pull_maps()
    {
        $account_information = get_option('wvnmi_account_information');
        $api_auth_key = (isset($account_information['privateAPIkey'])) ? $account_information['privateAPIkey'] . ':' : '';

        $headers = [
            'Authorization' => 'Basic ' . base64_encode($api_auth_key)
        ];

        $request_args = [
            'method'=>'GET',
            'headers'=>$headers
        ];

        if(isset($_SERVER['SERVER_ADDR'])) {
            $ip_addr = explode(".", sanitize_text_field($_SERVER['SERVER_ADDR']));
            if ( $ip_addr[0] == '192' &&  $ip_addr[1] == '168') {
                $request_url = "http://api.wavenami.net/v1/maps/list";
            } else {
                $request_url = "https://api.wavenami.com/v1/maps/list";
            }
        } else {
            $request_url = "https://api.wavenami.com/v1/maps/list";
        }

        //echo "<pre>";
        //print_r($headers);
        //print_r($request_url);
        //print_r($request_args);

        $responses = json_decode(wp_remote_retrieve_body(wp_remote_request($request_url, $request_args)), true);

        //print_r($responses);
        //echo "</pre>"; die;

        if(isset($responses['status'])){
            if($responses['status'] == '401'){
                $responses = [];
            }
        }

        return $responses;
    }

    private function _generate_maps_list()
    {
        $event_maps_a = $this->_pull_maps();

        ob_start();
        if($this->_count_array($event_maps_a) == 0):
            ?>
        <h2>Please read the help section on how to add your Wavenami API key and/or make sure that it's correct.</h2>
        <?php
        else:
        ?>
        These are available event maps you can add to pages via Shortcodes. Please read Setup Notes to see how to use them.
        <br>Important: Don't forget to select <strong>Page Attributes->Wavenami Template</strong> for the Page, or the form
            may not display correctly.
        <hr>
        <table class="wp-list-table widefat fixed striped users">
            <thead>
                <tr>
                    <th>Event</th>
                    <th>Map Name</th>
                    <th>Shortcode</th>
                </tr>
            </thead>
            <tbody>
                <?php if($this->_count_array($event_maps_a) > 0): ?>
                    <?php foreach($event_maps_a as $key => $map): ?>
                        <tr>
                            <td><?php echo $map['title']; ?></td>
                            <!-- td><?php // echo date("m/d/Y", strtotime($event['start_date'])); ?></td -->
                            <td><?php echo $map['map_name']; ?></td>
                            <td><input id="" size="45" name="" value='[wavenami_form map_key="<?php echo $map['map_code']; ?>"]' type="text"></td>
                        </tr>
                     <?php endforeach; ?>
                <?php endif; ?>
            </tbody>
        </table>
        <?php
         endif;
        return ob_get_clean();
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
}