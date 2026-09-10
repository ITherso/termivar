<?php
/**
 * Enqueue only the active child stylesheet. The parent stylesheet is left out
 * deliberately so Termivar can fetch it only from the bounded Template edge.
 *
 * @license GPL-2.0-or-later
 */
add_action(
	'wp_enqueue_scripts',
	static function () {
		wp_enqueue_style(
			'termivar-child',
			get_stylesheet_uri(),
			array(),
			'1.4.0'
		);
	}
);
