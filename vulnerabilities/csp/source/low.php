<?php

/*
 * CSP Bypass - patched.
 *
 * The policy no longer allow-lists third party hosts that serve user
 * controlled content (pastebin, CDNs hosting arbitrary packages...): scripts
 * may only come from this origin. The include box only accepts a same-origin
 * path, which is HTML encoded before it is placed in the page.
 */

$headerCSP = "Content-Security-Policy: script-src 'self'; object-src 'none'; base-uri 'self';";

header($headerCSP);

?>
<?php
if (isset ($_POST['include']) && is_string ($_POST['include']) && $_POST['include'] != "") {
	$include = $_POST['include'];

	// Only a local path is accepted: no scheme, no host, no protocol-relative URL
	$is_local = !preg_match('/[\x00-\x20\x7f]/', $include) &&
		strpos($include, chr(92)) === false &&
		!preg_match('/^[a-z][a-z0-9+.\-]*:/i', $include) &&
		substr($include, 0, 2) !== '//';

	if ($is_local) {
		$page[ 'body' ] .= "
	<script src='" . htmlspecialchars($include, ENT_QUOTES, 'UTF-8') . "'></script>
";
	} else {
		$page[ 'body' ] .= "
	<div class=\"warning\">Only scripts hosted on this server can be included.</div>
";
	}
}
$page[ 'body' ] .= '
<form name="csp" method="POST">
	<p>You can include scripts from this server, examine the Content Security Policy and enter a path to include here:</p>
	<input size="50" type="text" name="include" value="" id="include" />
	<input type="submit" value="Include" />
</form>
';
