<?php

/*
 * SQL Injection - patched.
 *
 * The user ID is validated as a plain integer and passed to the database as a
 * bound parameter of a prepared statement, so it can never change the
 * structure of the query.
 */

if( isset( $_SESSION [ 'id' ] ) ) {
	// Get input (set through session-input.php)
	$id = $_SESSION[ 'id' ];

	// Was a number entered?
	if( is_string( $id ) && preg_match( '/^\d{1,10}$/', $id ) ) {
		$id = intval( $id );

		switch ($_DVWA['SQLI_DB']) {
			case MYSQL:
				$data = $db->prepare( 'SELECT first_name, last_name FROM users WHERE user_id = (:id) LIMIT 1;' );
				$data->bindParam( ':id', $id, PDO::PARAM_INT );
				$data->execute();

				// Get results
				while( $row = $data->fetch() ) {
					// Get values
					$first = htmlspecialchars( $row[ 'first_name' ], ENT_QUOTES, 'UTF-8' );
					$last  = htmlspecialchars( $row[ 'last_name' ], ENT_QUOTES, 'UTF-8' );

					// Feedback for end user
					$html .= "<pre>ID: {$id}<br />First name: {$first}<br />Surname: {$last}</pre>";
				}
				break;
			case SQLITE:
				global $sqlite_db_connection;

				$stmt = $sqlite_db_connection->prepare( 'SELECT first_name, last_name FROM users WHERE user_id = :id LIMIT 1;' );
				$stmt->bindValue( ':id', $id, SQLITE3_INTEGER );
				$results = $stmt->execute();

				if ($results) {
					while ($row = $results->fetchArray()) {
						// Get values
						$first = htmlspecialchars( $row[ 'first_name' ], ENT_QUOTES, 'UTF-8' );
						$last  = htmlspecialchars( $row[ 'last_name' ], ENT_QUOTES, 'UTF-8' );

						// Feedback for end user
						$html .= "<pre>ID: {$id}<br />First name: {$first}<br />Surname: {$last}</pre>";
					}
				}
				break;
		}
	}
	else {
		// Feedback for end user
		$html .= "<pre>The User ID must be a number.</pre>";
	}
}

?>
