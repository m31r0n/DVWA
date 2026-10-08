<?php

/*
 * Insecure CAPTCHA - patched.
 *
 * The developer back door (a hard-coded CAPTCHA response combined with a
 * specific User-Agent) has been removed: the only way through is a CAPTCHA
 * response that the reCAPTCHA service verifies. The anti-CSRF token is also
 * checked, and the database update is parameterised.
 */

if( isset( $_POST[ 'Change' ] ) ) {
	// Check Anti-CSRF token
	checkToken( isset( $_POST[ 'user_token' ] ) ? $_POST[ 'user_token' ] : '', isset( $_SESSION[ 'session_token' ] ) ? $_SESSION[ 'session_token' ] : null, 'index.php' );

	// Hide the CAPTCHA form
	$hide_form = true;

	// Get input
	$pass_new  = isset( $_POST[ 'password_new' ] ) ? (string) $_POST[ 'password_new' ] : '';
	$pass_conf = isset( $_POST[ 'password_conf' ] ) ? (string) $_POST[ 'password_conf' ] : '';

	// Check CAPTCHA from 3rd party - and nothing else
	$resp = recaptcha_check_answer(
		$_DVWA[ 'recaptcha_private_key' ],
		isset( $_POST['g-recaptcha-response'] ) ? $_POST['g-recaptcha-response'] : ''
	);

	if( $resp ) {
		// CAPTCHA was correct. Do both new passwords match?
		if ($pass_new === $pass_conf) {
			$pass_new = md5( $pass_new );

			// Update database
			$current_user = dvwaCurrentUser();
			$data = $db->prepare( 'UPDATE users SET password = (:password) WHERE user = (:user) LIMIT 1;' );
			$data->bindParam( ':password', $pass_new, PDO::PARAM_STR );
			$data->bindParam( ':user', $current_user, PDO::PARAM_STR );
			$data->execute();

			// Feedback for user
			$html .= "<pre>Password Changed.</pre>";

		} else {
			// Ops. Password mismatch
			$html     .= "<pre>Both passwords must match.</pre>";
			$hide_form = false;
		}

	} else {
		// What happens when the CAPTCHA was entered incorrectly
		$html     .= "<pre><br />The CAPTCHA was incorrect. Please try again.</pre>";
		$hide_form = false;
		return;
	}
}

// Generate Anti-CSRF token
generateSessionToken();

?>
