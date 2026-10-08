<?php

/*
 * Weak Session IDs - patched.
 *
 * Session identifiers must be unguessable: no counters, no timestamps, no
 * hashes of predictable values. The value is 160 bits from a CSPRNG and the
 * cookie is flagged HttpOnly / SameSite (and Secure when served over HTTPS).
 */

$html = "";

if ($_SERVER['REQUEST_METHOD'] == "POST") {
	$cookie_value = bin2hex(random_bytes(20));
	$is_https = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off');
	setcookie("dvwaSession", $cookie_value, array(
		'expires'  => time() + 3600,
		'path'     => '/vulnerabilities/weak_id/',
		'secure'   => $is_https,
		'httponly' => true,
		'samesite' => 'Strict',
	));
}
?>
