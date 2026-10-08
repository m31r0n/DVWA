<?php

/*
 * Reflected XSS - patched.
 *
 * Blacklist filtering of tags is always incomplete (case changes, other tags,
 * event handlers...). The input is instead HTML encoded on output, so it is
 * displayed as text and never interpreted as markup.
 */

// Is there any input?
if( array_key_exists( "name", $_GET ) && is_string( $_GET[ 'name' ] ) && $_GET[ 'name' ] != NULL ) {
	// Get input
	$name = htmlspecialchars( $_GET[ 'name' ], ENT_QUOTES, 'UTF-8' );

	// Feedback for end user
	$html .= "<pre>Hello {$name}</pre>";
}

?>
