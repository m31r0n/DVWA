<?php

/*
 * Cryptography - patched.
 *
 * XOR with a short, hard-coded, repeating key is an encoding, not encryption:
 * anybody holding the source (or one known plaintext) can read every message,
 * which is how the "Olifant" password leaked.
 *
 * - Messages are now protected with AES-256-GCM (authenticated encryption)
 *   under a random IV and a secret key that is not in the source code
 *   (DVWA_CRYPTO_SECRET, or a random per-session secret).
 * - The leaked password has been rotated. The new one is random, is never
 *   stored in clear (only a password_hash() of it is kept) and is only ever
 *   transmitted encrypted, under a key the message tool does not use.
 */

function crypto_low_key ($purpose) {
	$secret = getenv ('DVWA_CRYPTO_SECRET');
	if ($secret === false || $secret === '') {
		if (!isset ($_SESSION['dvwa_crypto_secret'])) {
			$_SESSION['dvwa_crypto_secret'] = bin2hex (random_bytes (32));
		}
		$secret = $_SESSION['dvwa_crypto_secret'];
	}
	return hash_hmac ('sha256', 'dvwa-crypto-low:' . $purpose, $secret, true);
}

function crypto_low_encrypt ($cleartext, $key) {
	$iv = random_bytes (12);
	$tag = '';
	$ciphertext = openssl_encrypt ($cleartext, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag);
	if ($ciphertext === false) {
		throw new Exception ("Encryption failed");
	}
	return base64_encode ($iv . $ciphertext . $tag);
}

function crypto_low_decrypt ($message, $key) {
	$raw = base64_decode ($message, true);
	if ($raw === false || strlen ($raw) < 28) {
		throw new Exception ("Message is not in the right format");
	}
	$iv = substr ($raw, 0, 12);
	$tag = substr ($raw, -16);
	$ciphertext = substr ($raw, 12, -16);
	$cleartext = openssl_decrypt ($ciphertext, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag);
	if ($cleartext === false) {
		throw new Exception ("Decryption failed - wrong key or the message has been tampered with");
	}
	return $cleartext;
}

$message_key = crypto_low_key ('messages');

// The rotated credential: random, only its hash is kept, only sent encrypted.
if (!isset ($_SESSION['crypto_low_password_hash']) || !isset ($_SESSION['crypto_low_intercepted'])) {
	$new_password = bin2hex (random_bytes (12));
	$_SESSION['crypto_low_password_hash'] = password_hash ($new_password, PASSWORD_DEFAULT);
	$_SESSION['crypto_low_intercepted'] = crypto_low_encrypt ("Your new password is " . $new_password, crypto_low_key ('transport'));
	unset ($new_password);
}

$errors = "";
$success = "";
$messages = "";
$encoded = null;
$encode_radio_selected = " checked='checked' ";
$decode_radio_selected = " ";
$message = "";

if ($_SERVER['REQUEST_METHOD'] == "POST") {
	try {
		if (array_key_exists ('message', $_POST) && is_string ($_POST['message'])) {
			$message = $_POST['message'];
			if (array_key_exists ('direction', $_POST) && $_POST['direction'] == "decode") {
				$encode_radio_selected = " ";
				$decode_radio_selected = " checked='checked' ";
				$encoded = crypto_low_decrypt (trim ($message), $message_key);
			} else {
				$encoded = crypto_low_encrypt ($message, $message_key);
			}
		}
		if (array_key_exists ('password', $_POST)) {
			$password = is_string ($_POST['password']) ? $_POST['password'] : '';
			if ($password !== '' && password_verify ($password, $_SESSION['crypto_low_password_hash'])) {
				$success = "Welcome back user";
			} else {
				$errors = "Login Failed";
			}
		}
	} catch(Exception $e) {
		$errors = $e->getMessage();
	}
}

$html = "
		<p>
		This system will allow you to exchange messages with your friends without anyone else being able to read them. Use the box below to encrypt and decrypt messages (AES-256-GCM).
		</p>
		<form name=\"xor\" method='post' action=\"" . htmlspecialchars ($_SERVER['PHP_SELF'], ENT_QUOTES, 'UTF-8') . "\">
			<p>
				<label for='message'>Message:</lable><br />
				<textarea style='width: 600px; height: 56px' id='message' name='message'>" . htmlentities ($message) . "</textarea>
			</p>
			<p>
				<input type='radio' value='encode' name='direction' id='direction_encode' " . $encode_radio_selected . "><label for='direction_encode'>Encode</label> or
				<input type='radio' value='decode' name='direction' id='direction_decode' " . $decode_radio_selected . "><label for='direction_decode'>Decode</label>
			</p>
			<p>
				<input type=\"submit\" value=\"Submit\">
			</p>
		</form>
";

if (!is_null ($encoded)) {
	$html .= "
			<p>
				<label for='encoded'>Message:</lable><br />
				<textarea readonly='readonly' style='width: 600px; height: 56px' id='encoded' name='encoded'>" . htmlentities ($encoded) . "</textarea>
			</p>";
}

$html .= "
		<hr>
		<p>
		You have intercepted the following message. It is now properly encrypted, so it should not be possible to read it or to log in below without the password.
		</p>
		<p>
		<textarea readonly='readonly' style='width: 600px; height: 28px' id='intercepted' name='intercepted'>" . htmlentities ($_SESSION['crypto_low_intercepted']) . "</textarea>
		</p>
";

if ($errors != "") {
	$html .= '<div class="warning">' . htmlentities ($errors) . '</div>';
}

if ($messages != "") {
	$html .= '<div class="nearly">' . $messages . '</div>';
}

if ($success != "") {
	$html .= '<div class="success">' . $success . '</div>';
}

$html .= "
		<form name=\"ecb\" method='post' action=\"" . htmlspecialchars ($_SERVER['PHP_SELF'], ENT_QUOTES, 'UTF-8') . "\">
			<p>
				<label for='password'>Password:</lable><br />
<input type='password' id='password' name='password'>
			</p>
			<p>
				<input type=\"submit\" value=\"Login\">
			</p>
		</form>
";
?>
