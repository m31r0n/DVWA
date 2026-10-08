<?php

/*
 * Insecure CAPTCHA - patched.
 *
 * The result of the CAPTCHA check made in step 1 is kept on the server (in the
 * session), bound to the password the user asked for, and consumed by step 2.
 * Step 2 no longer trusts anything the client sends to claim the CAPTCHA was
 * solved, so jumping straight to step 2 (or forging a flag) does nothing.
 */

if( isset( $_POST[ 'Change' ] ) && isset( $_POST[ 'step' ] ) && ( $_POST[ 'step' ] == '1' ) ) {
	// Hide the CAPTCHA form
	$hide_form = true;

	// Get input
	$pass_new  = isset( $_POST[ 'password_new' ] ) ? (string) $_POST[ 'password_new' ] : '';
	$pass_conf = isset( $_POST[ 'password_conf' ] ) ? (string) $_POST[ 'password_conf' ] : '';

	// Check CAPTCHA from 3rd party
	$resp = recaptcha_check_answer(
		$_DVWA[ 'recaptcha_private_key'],
		isset( $_POST['g-recaptcha-response'] ) ? $_POST['g-recaptcha-response'] : ''
	);

	// Did the CAPTCHA fail?
	if( !$resp ) {
		// What happens when the CAPTCHA was entered incorrectly
		unset( $_SESSION[ 'captcha_passed' ] );
		$html     .= "<pre><br />The CAPTCHA was incorrect. Please try again.</pre>";
		$hide_form = false;
		return;
	}
	else {
		// CAPTCHA was correct. Do both new passwords match?
		if( $pass_new === $pass_conf ) {
			// Remember, server side, that this user solved the CAPTCHA for this password change
			$_SESSION[ 'captcha_passed' ] = array(
				'user' => dvwaCurrentUser(),
				'hash' => hash( 'sha256', $pass_new ),
				'time' => time(),
			);

			$safe_new  = htmlspecialchars( $pass_new, ENT_QUOTES, 'UTF-8' );
			$safe_conf = htmlspecialchars( $pass_conf, ENT_QUOTES, 'UTF-8' );

			// Show next stage for the user
			$html .= "
				<pre><br />You passed the CAPTCHA! Click the button to confirm your changes.<br /></pre>
				<form action=\"#\" method=\"POST\">
					<input type=\"hidden\" name=\"step\" value=\"2\" />
					<input type=\"hidden\" name=\"password_new\" value=\"{$safe_new}\" />
					<input type=\"hidden\" name=\"password_conf\" value=\"{$safe_conf}\" />
					<input type=\"submit\" name=\"Change\" value=\"Change\" />
				</form>";
		}
		else {
			// Both new passwords do not match.
			$html     .= "<pre>Both passwords must match.</pre>";
			$hide_form = false;
		}
	}
}

if( isset( $_POST[ 'Change' ] ) && isset( $_POST[ 'step' ] ) && ( $_POST[ 'step' ] == '2' ) ) {
	// Hide the CAPTCHA form
	$hide_form = true;

	// Get input
	$pass_new  = isset( $_POST[ 'password_new' ] ) ? (string) $_POST[ 'password_new' ] : '';
	$pass_conf = isset( $_POST[ 'password_conf' ] ) ? (string) $_POST[ 'password_conf' ] : '';

	// Did this user really pass the CAPTCHA (step 1) for this password, recently?
	$captcha = isset( $_SESSION[ 'captcha_passed' ] ) ? $_SESSION[ 'captcha_passed' ] : null;
	unset( $_SESSION[ 'captcha_passed' ] ); // single use

	if( !is_array( $captcha ) ||
		$captcha[ 'user' ] !== dvwaCurrentUser() ||
		!hash_equals( $captcha[ 'hash' ], hash( 'sha256', $pass_new ) ) ||
		( time() - $captcha[ 'time' ] ) > 300 ) {
		$html     .= "<pre><br />You have not passed the CAPTCHA.</pre>";
		$hide_form = false;
		return;
	}

	// Check to see if both password match
	if( $pass_new === $pass_conf ) {
		// They do!
		$pass_new = md5( $pass_new );

		// Update database
		$current_user = dvwaCurrentUser();
		$data = $db->prepare( 'UPDATE users SET password = (:password) WHERE user = (:user);' );
		$data->bindParam( ':password', $pass_new, PDO::PARAM_STR );
		$data->bindParam( ':user', $current_user, PDO::PARAM_STR );
		$data->execute();

		// Feedback for the end user
		$html .= "<pre>Password Changed.</pre>";
	}
	else {
		// Issue with the passwords matching
		$html .= "<pre>Passwords did not match.</pre>";
		$hide_form = false;
	}
}

?>
