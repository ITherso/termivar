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

/**
 * Return the fixture route below the independently configured public home.
 *
 * The lab deliberately exercises `/`, `/blog/`, and a root home backed by a
 * `/cms/` core. The protected resource remains inside the selected application
 * rather than inheriting the core directory from `site_url()`.
 *
 * @param string $leaf Fixed task-owned route leaf.
 * @return string
 */
function termivar_fingerprint_lab_session_path( $leaf ) {
	$home_path = wp_parse_url( home_url( '/' ), PHP_URL_PATH );
	if ( ! is_string( $home_path ) ) {
		$home_path = '/';
	}

	return trailingslashit( $home_path ) . $leaf . '/';
}

/**
 * Serve two bounded, test-only supplied-session resources.
 *
 * WordPress performs the real logged-in-cookie validation. The controller sets
 * the expected low-privilege user before each run. A separate fixture switch
 * invalidates the health oracle after the protected page so Termivar can prove
 * that post-response session loss prevents WordPress nominations.
 */
add_action(
	'template_redirect',
	static function () {
		$request_path = wp_parse_url( $_SERVER['REQUEST_URI'] ?? '', PHP_URL_PATH );
		if ( ! is_string( $request_path ) ) {
			return;
		}

		$health_path = termivar_fingerprint_lab_session_path( 'termivar-session-health' );
		$member_path = termivar_fingerprint_lab_session_path( 'termivar-session-member' );
		if ( $request_path !== $health_path && $request_path !== $member_path ) {
			return;
		}

		$expected_login = get_option( 'termivar_session_expected_login', '' );
		$current_user   = wp_get_current_user();
		$healthy        = is_string( $expected_login )
			&& '' !== $expected_login
			&& is_user_logged_in()
			&& $current_user->exists()
			&& $current_user->user_login === $expected_login
			&& '1' !== get_option( 'termivar_session_forced_loss', '0' );

		nocache_headers();
		if ( $request_path === $health_path ) {
			status_header( 200 );
			header( 'Content-Type: application/json; charset=utf-8' );
			echo wp_json_encode( array( 'authenticated' => $healthy ) );
			exit;
		}

		if ( ! $healthy ) {
			status_header( 403 );
			header( 'Content-Type: text/plain; charset=utf-8' );
			echo 'session unavailable';
			exit;
		}

		$script = plugins_url( 'assets/fingerprint.js', __FILE__ );
		$style  = plugins_url( 'assets/fingerprint.css', __FILE__ );
		$body_marker = 'TERMIVAR-PRIVATE-SESSION-BODY-CANARY-UNKNOWN';
		if ( 'termivar-lab-alice' === $current_user->user_login ) {
			$body_marker = 'TERMIVAR-PRIVATE-SESSION-BODY-CANARY-ALICE';
		} elseif ( 'termivar-lab-bob' === $current_user->user_login ) {
			$body_marker = 'TERMIVAR-PRIVATE-SESSION-BODY-CANARY-BOB-CONTEXT';
		}
		status_header( 200 );
		header( 'Content-Type: text/html; charset=utf-8' );
		echo '<!doctype html><html><head>';
		echo '<script src="' . esc_url( $script ) . '?ver=private-page"></script>';
		echo '<link rel="stylesheet" href="' . esc_url( $style ) . '?ver=private-page">';
		echo '</head><body>' . esc_html( $body_marker ) . '</body></html>';
		if ( '1' === get_option( 'termivar_session_lose_after_resource', '0' ) ) {
			update_option( 'termivar_session_forced_loss', '1', false );
		}
		exit;
	},
	-100
);
