<?php

/*
 * CSP Bypass - patched.
 *
 * 'unsafe-inline' is removed and the nonce is now random for every response,
 * so an attacker cannot predict it. On top of that, user input is HTML
 * encoded, so it can never inject a <script> element in the first place.
 */

$nonce = base64_encode(random_bytes(16));
$headerCSP = "Content-Security-Policy: script-src 'self' 'nonce-" . $nonce . "'; object-src 'none'; base-uri 'self';";

header($headerCSP);

?>
<?php
if (isset ($_POST['include']) && is_string ($_POST['include'])) {
$page[ 'body' ] .= "
	" . htmlspecialchars($_POST['include'], ENT_QUOTES, 'UTF-8') . "
";
}
$page[ 'body' ] .= '
<form name="csp" method="POST">
	<p>Whatever you enter here gets displayed in the page, see if you can get an alert box to pop up.</p>
	<input size="50" type="text" name="include" value="" id="include" />
	<input type="submit" value="Include" />
</form>
';
