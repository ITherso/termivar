<?php
/**
 * Plugin Name: Termivar Generator Control
 * Description: Test-only switch that suppresses the public core generator.
 * Version: 1.0.0
 * License: GPL-2.0-or-later
 */

remove_action( 'wp_head', 'wp_generator' );
