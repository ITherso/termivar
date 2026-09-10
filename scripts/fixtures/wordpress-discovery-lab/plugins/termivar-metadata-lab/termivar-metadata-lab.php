<?php
/**
 * Plugin Name: Termivar Metadata Lab
 * Description: Harmless metadata-only fixture for Termivar acceptance.
 * Version: 2.3.4
 * Requires at least: 6.8
 * Requires PHP: 8.3
 * License: GPL-2.0-or-later
 */

add_action(
	'wp_enqueue_scripts',
	static function () {
		wp_enqueue_style(
			'termivar-metadata-lab',
			plugins_url( 'assets/lab.css', __FILE__ ),
			array(),
			'2.3.4'
		);
	}
);

add_action(
	'rest_api_init',
	static function () {
		register_rest_route(
			'termivar-lab/v1',
			'/status',
			array(
				'methods'             => 'GET',
				'callback'            => static function () {
					return new WP_REST_Response( array( 'status' => 'ok' ) );
				},
				'permission_callback' => '__return_true',
			)
		);
	}
);
