<?php

include_once('WavenamiSettings.php');

class WavenamiMain
{
   /*
   * the constructor
   * Fired during plugins_loaded (very very early),
   * only actions and filters,
   *
   */
    function __construct() {

        $wavenami_settings = new WavenamiSettings();

        // Add shortcode support for widgets
    }
}