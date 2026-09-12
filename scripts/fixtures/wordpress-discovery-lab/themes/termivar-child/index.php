<?php
/**
 * Test-only child theme template.
 *
 * @license GPL-2.0-or-later
 */
?><!doctype html>
<html <?php language_attributes(); ?>>
<head>
<meta charset="<?php bloginfo( 'charset' ); ?>">
<?php wp_head(); ?>
<?php
$termivar_home_path = wp_parse_url( home_url( '/' ), PHP_URL_PATH );
if ( '/blog/' === $termivar_home_path ) {
	// Same-origin sibling decoy: it is ordinary page content, not metadata
	// authority for the explicitly selected /blog/ application.
	echo '<link rel="stylesheet" href="/shop/wp-content/themes/termivar-child/assets/decoy.css">';
}
?>
</head>
<body <?php body_class(); ?>>
<main>
<h1>Termivar WordPress metadata discovery lab</h1>
<nav>
<a href="<?php echo esc_url( home_url( '/contact/' ) ); ?>">Contact</a>
<a href="<?php echo esc_url( home_url( '/gallery/' ) ); ?>">Gallery</a>
</nav>
<?php
if ( have_posts() ) {
	while ( have_posts() ) {
		the_post();
		the_content();
	}
}
?>
</main>
<img src="<?php echo esc_url( includes_url( 'images/blank.gif' ) ); ?>" alt="" width="1" height="1">
<?php wp_footer(); ?>
</body>
</html>
