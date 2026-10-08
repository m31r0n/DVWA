<?php

/*
 * Command Injection - patched.
 *
 * Blacklisting shell metacharacters is never complete, so the input is
 * validated against what it is supposed to be (an IP address) and is then
 * passed to the shell as a single, escaped argument.
 */

if( isset( $_POST[ 'Submit' ]  ) ) {
	// Get input
	$target = isset( $_REQUEST[ 'ip' ] ) ? trim( (string) $_REQUEST[ 'ip' ] ) : '';

	// Only accept a well-formed IPv4 / IPv6 address
	if( filter_var( $target, FILTER_VALIDATE_IP ) !== false ) {
		$arg = escapeshellarg( $target );

		// Determine OS and execute the ping command.
		if( stristr( php_uname( 's' ), 'Windows NT' ) ) {
			// Windows
			$cmd = shell_exec( 'ping  ' . $arg );
		}
		else {
			// *nix
			$cmd = shell_exec( 'ping  -c 4 ' . $arg );
		}

		// Feedback for the end user
		$html .= "<pre>" . htmlspecialchars( (string) $cmd, ENT_QUOTES, 'UTF-8' ) . "</pre>";
	}
	else {
		// Let the user know there was a mistake
		$html .= '<pre>ERROR: You have entered an invalid IP.</pre>';
	}
}

?>
