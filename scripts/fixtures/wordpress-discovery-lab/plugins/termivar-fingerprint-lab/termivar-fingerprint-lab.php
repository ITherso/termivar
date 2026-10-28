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
 * One task-owned V3-shaped form, not native wp-login.php compatibility.
 *
 * The controller privately provisions one low-privilege user's real WordPress
 * password, a genuine WP session token and a single-use CSRF value. A cookie is
 * released only after wp_authenticate verifies the submitted password. The
 * existing health route independently validates that cookie and principal.
 */
add_action(
	'template_redirect',
	static function () {
		$login_path = termivar_fingerprint_lab_session_path( 'termivar-session-login' );
		$request_path = wp_parse_url( $_SERVER['REQUEST_URI'] ?? '', PHP_URL_PATH );
		if ( $request_path !== $login_path ) {
			return;
		}
		nocache_headers();
		$method = $_SERVER['REQUEST_METHOD'] ?? '';
		if ( 'GET' === $method ) {
			$csrf = get_option( 'termivar_session_form_csrf', '' );
			if ( ! is_string( $csrf ) || ! preg_match( '/^[A-Za-z0-9_-]{32}$/D', $csrf ) ) {
				status_header( 503 );
				header( 'Content-Type: text/plain; charset=utf-8' );
				echo 'login unavailable';
				exit;
			}
			status_header( 200 );
			header( 'Content-Type: text/html; charset=utf-8' );
			echo '<!doctype html><html><body><form method="post" action="' . esc_attr( $login_path ) . '">';
			echo '<input type="hidden" name="csrf" value="' . esc_attr( $csrf ) . '">';
			echo '<input type="text" name="user"><input type="password" name="pass">';
			echo '</form></body></html>';
			exit;
		}
		if ( 'POST' !== $method ) {
			status_header( 405 );
			header( 'Content-Type: text/plain; charset=utf-8' );
			echo 'method unavailable';
			exit;
		}
		$csrf = get_option( 'termivar_session_form_csrf', '' );
		$token = get_option( 'termivar_session_form_token', '' );
		$login = get_option( 'termivar_session_form_login', '' );
		$user_id = get_option( 'termivar_session_form_user_id', 0 );
		$expiration = get_option( 'termivar_session_form_expiration', 0 );
		// A failed or ambiguous submission cannot reuse this fixture transaction.
		delete_option( 'termivar_session_form_csrf' );
		delete_option( 'termivar_session_form_token' );
		status_header( 200 );
		header( 'Content-Type: text/plain; charset=utf-8' );
		$keys = array_keys( $_POST );
		sort( $keys );
		if ( (int) ( $_SERVER['CONTENT_LENGTH'] ?? 0 ) > 16384
			|| array( 'csrf', 'pass', 'user' ) !== $keys
			|| ! is_string( $_POST['csrf'] ) || ! is_string( $_POST['user'] ) || ! is_string( $_POST['pass'] )
			|| ! is_string( $csrf ) || '' === $csrf || ! hash_equals( $csrf, wp_unslash( $_POST['csrf'] ) )
			|| strlen( $_POST['user'] ) > 256 || strlen( $_POST['pass'] ) > 256
			|| ! is_string( $token ) || ! preg_match( '/^[A-Za-z0-9]{43}$/D', $token )
			|| ! is_string( $login ) || (int) $expiration <= time() ) {
			echo 'login unavailable';
			exit;
		}
		$user = wp_authenticate( wp_unslash( $_POST['user'] ), wp_unslash( $_POST['pass'] ) );
		if ( is_wp_error( $user ) || ! ( $user instanceof WP_User ) || $user->user_login !== $login
			|| (int) $user->ID !== (int) $user_id || (int) $user_id <= 0
			|| ! in_array( 'subscriber', $user->roles, true ) ) {
			echo 'login unavailable';
			exit;
		}
		$cookie = wp_generate_auth_cookie( $user->ID, (int) $expiration, 'logged_in', $token );
		if ( ! is_string( $cookie ) || '' === $cookie ) {
			echo 'login unavailable';
			exit;
		}
		$home_path = wp_parse_url( home_url( '/' ), PHP_URL_PATH );
		$home_path = is_string( $home_path ) ? trailingslashit( $home_path ) : '/';
		header( 'Set-Cookie: ' . LOGGED_IN_COOKIE . '=' . $cookie . '; Path=' . $home_path . '; HttpOnly; SameSite=Lax', false );
		echo 'login submitted';
		exit;
	},
	-100
);

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
