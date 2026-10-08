<?php

/*
 * SQL Injection (Blind) - patched.
 *
 * The user ID must be a plain integer and is passed to the database as a bound
 * parameter, so attacker supplied boolean/time conditions are never evaluated
 * by the database and there is no oracle left to query.
 */

if( isset( $_GET[ 'Submit' ] ) ) {
	// Get input
	$id = isset( $_GET[ 'id' ] ) ? $_GET[ 'id' ] : '';
	$exists = false;

	// Was a number entered?
	if( is_string( $id ) && preg_match( '/^\d{1,10}$/', $id ) ) {
		$id = intval( $id );

		switch ($_DVWA['SQLI_DB']) {
			case MYSQL:
				$data = $db->prepare( 'SELECT first_name, last_name FROM users WHERE user_id = (:id) LIMIT 1;' );
				$data->bindParam( ':id', $id, PDO::PARAM_INT );
				$data->execute();
				$exists = ( $data->rowCount() > 0 );
				break;
			case SQLITE:
				global $sqlite_db_connection;

				$stmt = $sqlite_db_connection->prepare( 'SELECT first_name, last_name FROM users WHERE user_id = :id LIMIT 1;' );
				$stmt->bindValue( ':id', $id, SQLITE3_INTEGER );
				$results = $stmt->execute();
				$exists = ( $results !== false ) && ( $results->fetchArray() !== false );
				break;
		}

		if ($exists) {
			// Feedback for end user
			$html .= '<pre>User ID exists in the database.</pre>';
		} else {
			// User wasn't found, so the page wasn't!
			header( $_SERVER[ 'SERVER_PROTOCOL' ] . ' 404 Not Found' );

			// Feedback for end user
			$html .= '<pre>User ID is MISSING from the database.</pre>';
		}
	}
	else {
		// Input validation error - the database is not queried at all
		$html .= '<pre>The User ID must be a number.</pre>';
	}
}

?>
