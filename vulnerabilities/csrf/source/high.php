<?php

/*
 * CSRF - patched.
 *
 * The anti-CSRF token alone is not enough: a token harvested from the page
 * (e.g. through XSS) can be replayed. Changing the password therefore also
 * requires the user's current password, which is never present in the page.
 * Requests are only accepted as POST (form or JSON).
 */

$change = false;
$request_type = "html";
$return_message = "Request Failed";

if ($_SERVER['REQUEST_METHOD'] == "POST") {
	if (array_key_exists ("CONTENT_TYPE", $_SERVER) && $_SERVER['CONTENT_TYPE'] == "application/json") {
		$data = json_decode(file_get_contents('php://input'), true);
		$request_type = "json";
		if (is_array($data) &&
			array_key_exists("HTTP_USER_TOKEN", $_SERVER) &&
			array_key_exists("password_new", $data) &&
			array_key_exists("password_conf", $data) &&
			array_key_exists("Change", $data)) {
			$token = (string) $_SERVER['HTTP_USER_TOKEN'];
			$pass_curr = array_key_exists("password_current", $data) ? (string) $data["password_current"] : '';
			$pass_new = (string) $data["password_new"];
			$pass_conf = (string) $data["password_conf"];
			$change = true;
		}
	} else {
		if (array_key_exists("password_new", $_POST) &&
			array_key_exists("password_conf", $_POST) &&
			array_key_exists("Change", $_POST)) {
			$token = array_key_exists("user_token", $_POST) ? (string) $_POST["user_token"] : '';
			$pass_curr = array_key_exists("password_current", $_POST) ? (string) $_POST["password_current"] : '';
			$pass_new = (string) $_POST["password_new"];
			$pass_conf = (string) $_POST["password_conf"];
			$change = true;
		}
	}
}

if ($change) {
	// Check Anti-CSRF token
	checkToken( $token, isset( $_SESSION[ 'session_token' ] ) ? $_SESSION[ 'session_token' ] : null, 'index.php' );

	// Check that the current password is correct
	$current_user = dvwaCurrentUser();
	$pass_curr    = md5( $pass_curr );
	$data = $db->prepare( 'SELECT password FROM users WHERE user = (:user) AND password = (:password) LIMIT 1;' );
	$data->bindParam( ':user', $current_user, PDO::PARAM_STR );
	$data->bindParam( ':password', $pass_curr, PDO::PARAM_STR );
	$data->execute();

	// Do the passwords match and was the current password correct?
	if( ( $pass_new !== '' ) && ( $pass_new === $pass_conf ) && ( $data->rowCount() == 1 ) ) {
		$pass_new = md5( $pass_new );

		// Update the database
		$data = $db->prepare( 'UPDATE users SET password = (:password) WHERE user = (:user);' );
		$data->bindParam( ':password', $pass_new, PDO::PARAM_STR );
		$data->bindParam( ':user', $current_user, PDO::PARAM_STR );
		$data->execute();

		// Feedback for the user
		$return_message = "Password Changed.";
	}
	else {
		// Issue with passwords matching
		$return_message = "Passwords did not match or current password incorrect.";
	}

	if ($request_type == "json") {
		generateSessionToken();
		header ("Content-Type: application/json");
		print json_encode (array("Message" =>$return_message));
		exit;
	} else {
		$html .= "<pre>" . $return_message . "</pre>";
	}
}

// Generate Anti-CSRF token
generateSessionToken();

?>
