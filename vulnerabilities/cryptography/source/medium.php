<?php

/*
 * Cryptography - patched.
 *
 * ECB encrypts every 16 byte block independently, so blocks from different
 * tokens can be cut and pasted into a new valid token, and with a hard-coded
 * key anybody can simply mint their own token.
 *
 * Tokens are now encrypted with AES-256-GCM: a random IV per token and an
 * authentication tag, so any modified, spliced or forged token is rejected.
 * The key is not in the source code (DVWA_CRYPTO_SECRET, or a random
 * per-session secret), which also invalidates every token issued with the old
 * leaked key.
 */

function crypto_medium_key () {
	$secret = getenv ('DVWA_CRYPTO_SECRET');
	if ($secret === false || $secret === '') {
		if (!isset ($_SESSION['dvwa_crypto_secret'])) {
			$_SESSION['dvwa_crypto_secret'] = bin2hex (random_bytes (32));
		}
		$secret = $_SESSION['dvwa_crypto_secret'];
	}
	return hash_hmac ('sha256', 'dvwa-crypto-medium:tokens', $secret, true);
}

function encrypt ($cleartext, $key) {
	$iv = random_bytes (12);
	$tag = '';
	$e = openssl_encrypt ($cleartext, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag);
	if ($e === false) {
		throw new Exception ("Encryption failed");
	}
	return $iv . $e . $tag;
}

function decrypt ($token, $key) {
	if (strlen ($token) < 29) {
		throw new Exception ("Token is in wrong format");
	}
	$iv = substr ($token, 0, 12);
	$tag = substr ($token, -16);
	$ciphertext = substr ($token, 12, -16);
	$e = openssl_decrypt ($ciphertext, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag);
	if ($e === false) {
		throw new Exception ("Decryption failed");
	}
	return $e;
}

$key = crypto_medium_key ();

// The captured tokens, as issued by the fixed application
$captured_tokens = array (
	"sooty" => bin2hex (encrypt ('{"user":"sooty","ex":1723620672,"level":"admin","bio":"Izzy wizzy let' . "'" . 's get busy"}', $key)),
	"sweep" => bin2hex (encrypt ('{"user":"sweep","ex":1723620672,"level": "user","bio": "Squeeeeek"}', $key)),
	"soo"   => bin2hex (encrypt ('{"user" : "soo","ex":1823620672,"level": "user","bio": "I won The Weakest Link"}', $key)),
);

$errors = "";
$success = "";
$messages = "";

if ($_SERVER['REQUEST_METHOD'] == "POST") {
	try {
		if (!array_key_exists ('token', $_POST)) {
			throw new Exception ("No token passed");
		} else {
			$token = is_string ($_POST['token']) ? trim ($_POST['token']) : '';
			if (!ctype_xdigit ($token) || strlen ($token) % 2 != 0) {
				throw new Exception ("Token is in wrong format");
			} else {
				$decrypted = decrypt(hex2bin ($token), $key);

				$user = json_decode ($decrypted);
				if (!is_object ($user) || !isset ($user->user, $user->ex, $user->level)) {
					throw new Exception ("Could not decode JSON object.");
				}

				if ($user->user == "sweep" && $user->ex > time() && $user->level == "admin") {
					$success = "Welcome administrator Sweep";
				} else {
					$messages = "Login successful but not as the right user.";
				}
			}
		}
	} catch(Exception $e) {
		$errors = $e->getMessage();
	}
}

$html = "
		<p>
		You have managed to get hold of three session tokens for an application you think is using poor cryptography to protect its secrets:
		</p>
		<p>
		<strong>Sooty (admin), session expired</strong>
		</p>
		<p>
<textarea style='width: 600px; height: 56px'>" . $captured_tokens['sooty'] . "</textarea>
		</p>
		<p>
		<strong>Sweep (user), session expired</strong>
		</p>
		<p>
<textarea style='width: 600px; height: 56px'>" . $captured_tokens['sweep'] . "</textarea>
		</p>
		<p>
		<strong>Soo (user), session valid</strong>
		</p>
		<p>
<textarea style='width: 600px; height: 56px'>" . $captured_tokens['soo'] . "</textarea>
		</p>
		<p>
		Based on the documentation, you know the format of the token is:
		</p>
		<pre><code>{
    \"user\": \"example\",
    \"ex\": 1723620372,
    \"level\": \"user\",
    \"bio\": \"blah\"
}</code></pre>
<p>
You also spot this comment in the docs:
</p>
<blockquote><i>
To ensure your security, we use authenticated encryption (aes-256-gcm) throughout our application.
</i></blockquote>

		<hr>
		<p>
		Manipulate the session tokens you have captured to log in as Sweep with admin privileges.
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
		<form name=\"ecb\" method='post' action=\"" . $_SERVER['PHP_SELF'] . "\">
			<p>
				<label for='token'>Token:</lable><br />
<textarea style='width: 600px; height: 56px' id='token' name='token'></textarea>
			</p>
			<p>
				<input type=\"submit\" value=\"Submit\">
			</p>
		</form>
";
?>
