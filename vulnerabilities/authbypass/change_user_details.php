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

if ($_SERVER['REQUEST_METHOD'] != "POST") {
	$result = array (
						"result" => "fail",
						"error" => "Only POST requests are accepted"
					);
	echo json_encode($result);
	exit;
}

$json = file_get_contents('php://input');
$data = json_decode($json);
if (!is_object ($data) ||
	!isset ($data->id) || !is_numeric ($data->id) ||
	!isset ($data->first_name) || !is_string ($data->first_name) || strlen ($data->first_name) > 15 ||
	!isset ($data->surname) || !is_string ($data->surname) || strlen ($data->surname) > 15) {
	$result = array (
						"result" => "fail",
						"error" => 'Invalid format, expecting "{id: {user ID}, first_name: "{first name}", surname: "{surname}"}'
					);
	echo json_encode($result);
	exit;
}

$id = intval ($data->id);
$first_name = $data->first_name;
$surname = $data->surname;

// Parameterised update
$stmt = $db->prepare( 'UPDATE users SET first_name = (:first_name), last_name = (:surname) WHERE user_id = (:id);' );
$stmt->bindParam( ':first_name', $first_name, PDO::PARAM_STR );
$stmt->bindParam( ':surname', $surname, PDO::PARAM_STR );
$stmt->bindParam( ':id', $id, PDO::PARAM_INT );
$stmt->execute();

print json_encode (array ("result" => "ok"));
exit;
?>
