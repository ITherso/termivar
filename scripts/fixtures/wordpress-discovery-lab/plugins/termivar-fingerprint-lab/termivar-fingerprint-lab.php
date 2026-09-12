<?php
/**
 * Plugin Name: Termivar Fingerprint Lab
 * Description: Harmless page-conditional asset fixture for Termivar acceptance.
 * Version: 4.0.0
 * Requires at least: 6.8
 * Requires PHP: 8.3
 * License: GPL-2.0-or-later
 */

add_action(
	'wp_enqueue_scripts',
	static function () {
		if ( ! is_page( array( 'contact', 'gallery' ) ) ) {
			return;
		}

		$mode = get_option( 'termivar_fingerprint_lab_mode', 'two' );
		if ( 'common' === $mode ) {
			wp_enqueue_style(
				'termivar-fingerprint-common',
				plugins_url( 'assets/common.css', __FILE__ ),
				array(),
				'cache-42'
			);
			return;
		}

		wp_enqueue_script(
			'termivar-fingerprint-script',
			plugins_url( 'assets/fingerprint.js', __FILE__ ),
			array(),
			'cache-42',
			true
		);
		if ( 'one' !== $mode ) {
			wp_enqueue_style(
				'termivar-fingerprint-style',
				plugins_url( 'assets/fingerprint.css', __FILE__ ),
				array(),
				'cache-42'
			);
		}
	}
);
