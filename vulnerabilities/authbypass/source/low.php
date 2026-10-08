<?php
/*

Only the admin user is allowed to access this page. Hiding the menu entry
(see dvwaHtmlEcho in dvwa/includes/dvwaPage.inc.php) is not access control,
so the page itself checks the user, and so do the endpoints it calls:

* vulnerabilities/authbypass/get_user_data.php
* vulnerabilities/authbypass/change_user_details.php

*/

if (dvwaCurrentUser() != "admin") {
	http_response_code(403);
	print "Unauthorised";
	exit;
}
?>
