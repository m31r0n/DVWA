<?php

/*
 * Open Redirect - patched.
 *
 * Only redirects to a location on this site are performed. The target must be
 * a relative URL or an absolute path: anything with a scheme (http:, https:,
 * javascript:...), a protocol-relative "//host" form, backslashes (which
 * browsers treat as slashes) or whitespace/control characters is refused.
 */

function dvwa_is_local_redirect ($target) {
	if (!is_string ($target) || $target === "") {
		return false;
	}
	// No whitespace, control characters or backslashes
	if (preg_match ('/[\x00-\x20\x7f]/', $target) || strpos ($target, chr (92)) !== false) {
		return false;
	}
	// No scheme
	if (preg_match ('/^[a-z][a-z0-9+.\-]*:/i', $target)) {
		return false;
	}
	// No protocol-relative URL
	if (substr ($target, 0, 2) === "//") {
		return false;
	}
	$parts = parse_url ($target);
	if ($parts === false || isset ($parts['scheme']) || isset ($parts['host'])) {
		return false;
	}
	return true;
}

if (array_key_exists ("redirect", $_GET) && $_GET['redirect'] != "") {
	if (dvwa_is_local_redirect ($_GET['redirect'])) {
		header ("location: " . $_GET['redirect']);
		exit;
	} else {
		http_response_code (400);
		?>
		<p>You can only redirect to pages on this site.</p>
		<?php
		exit;
	}
}

http_response_code (500);
?>
<p>Missing redirect target.</p>
<?php
exit;
?>
