<?php
define( 'DVWA_WEB_PAGE_TO_ROOT', '../../' );
require_once DVWA_WEB_PAGE_TO_ROOT . 'dvwa/includes/dvwaPage.inc.php';

dvwaDatabaseConnect();

/*
This is an admin only function. The authorisation check is done here, on
the server, at every security level - hiding the menu entry or the page from
other users does not stop them from calling this endpoint directly.
*/
if (!dvwaIsLoggedIn() || dvwaCurrentUser() != "admin") {
	print json_encode (array ("result" => "fail", "error" => "Access denied"));
	exit;
}

$query  = "SELECT user_id, first_name, last_name FROM users";
$result = mysqli_query($GLOBALS["___mysqli_ston"],  $query );

$users = array();

while ($row = mysqli_fetch_row($result) ) { 
	// The data is inserted into the page as HTML by the client, so encode it
	$user_id = intval ($row[0]);
	$first_name = htmlspecialchars( (string) $row[1], ENT_QUOTES, 'UTF-8' );
	$surname = htmlspecialchars( (string) $row[2], ENT_QUOTES, 'UTF-8' );

	$user = array (
					"user_id" => $user_id,
					"first_name" => $first_name,
					"surname" => $surname
				);
	$users[] = $user;
}

print json_encode ($users);
exit;
?>
