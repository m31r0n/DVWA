<?php

/*
 * File Inclusion - patched.
 *
 * Never pass user input to include(). Path filtering (stripping "../",
 * "http://", matching "file*") can always be bypassed, so the requested page
 * is checked against an explicit allowlist of the files this lab ships with.
 * Anything else falls back to the default page.
 */

// The page we wish to display
$file = isset( $_GET[ 'page' ] ) ? $_GET[ 'page' ] : null;

// Only allow include.php or file{1..3}.php
$configFileNames = [
	'include.php',
	'file1.php',
	'file2.php',
	'file3.php',
];

if( $file !== null && !in_array( $file, $configFileNames, true ) ) {
	// This isn't the page we want! Show the default page instead.
	$page[ 'body' ] .= "<div class=\"body_padded\"><div class=\"warning\">ERROR: File not found!</div></div>\n";
	$file = 'include.php';
}

?>
