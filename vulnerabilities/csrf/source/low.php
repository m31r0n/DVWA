<?php

/*
 * CSRF - patched.
 *
 * A state changing action must not be triggerable by a forged cross-site
 * request:
 *  - it is only accepted as a POST (no more one-click GET links / <img> tags),
 *  - the request must carry the per-page anti-CSRF token,
 *  - the user must re-authenticate with their current password, which an
 *    attacker forging a request (or replaying a harvested token) does not know.
 */

if( isset( $_POST[ 'Change' ] ) ) {
	// Check Anti-CSRF token
	checkToken( isset( $_POST[ 'user_token' ] ) ? $_POST[ 'user_token' ] : '', isset( $_SESSION[ 'session_token' ] ) ? $_SESSION[ 'session_token' ] : null, 'index.php' );

	// Get input
	$pass_curr = isset( $_POST[ 'password_current' ] ) ? (string) $_POST[ 'password_current' ] : '';
	$pass_new  = isset( $_POST[ 'password_new' ] ) ? (string) $_POST[ 'password_new' ] : '';
	$pass_conf = isset( $_POST[ 'password_conf' ] ) ? (string) $_POST[ 'password_conf' ] : '';

	// Check that the current password is correct
	$current_user = dvwaCurrentUser();
	$pass_curr    = md5( $pass_curr );
	$data = $db->prepare( 'SELECT password FROM users WHERE user = (:user) AND password = (:password) LIMIT 1;' );
	$data->bindParam( ':user', $current_user, PDO::PARAM_STR );
	$data->bindParam( ':password', $pass_curr, PDO::PARAM_STR );
	$data->execute();

	// Do both new passwords match and does the current password match the user?
	if( ( $pass_new !== '' ) && ( $pass_new === $pass_conf ) && ( $data->rowCount() == 1 ) ) {
		$pass_new = md5( $pass_new );

		// Update database with new password
		$data = $db->prepare( 'UPDATE users SET password = (:password) WHERE user = (:user);' );
		$data->bindParam( ':password', $pass_new, PDO::PARAM_STR );
		$data->bindParam( ':user', $current_user, PDO::PARAM_STR );
		$data->execute();

		// Feedback for the user
		$html .= "<pre>Password Changed.</pre>";
	}
	else {
		// Issue with passwords matching
		$html .= "<pre>Passwords did not match or current password incorrect.</pre>";
	}
}

// Generate Anti-CSRF token
generateSessionToken();

?>
