<?php
header("Content-Type: application/json; charset=UTF-8");

// Only the callback used by the page is allowed - the callback must never be
// attacker controlled, otherwise this same-origin endpoint becomes a script
// gadget that bypasses the Content Security Policy.
$allowed_callbacks = array ("solveSum");

if (array_key_exists ("callback", $_GET) && is_string ($_GET['callback']) && in_array ($_GET['callback'], $allowed_callbacks, true)) {
	$callback = $_GET['callback'];
} else {
	http_response_code (400);
	return "";
}

$outp = array ("answer" => "15");

echo $callback . "(".json_encode($outp).")";
?>
