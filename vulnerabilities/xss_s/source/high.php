<?php

/*
 * Stored XSS - patched.
 *
 * Guestbook entries are stored with a parameterised query and are HTML encoded
 * when they are rendered (see dvwaGuestbook() in dvwaPage.inc.php), so neither
 * the name nor the message can ever be interpreted as markup - whatever tag,
 * case or event handler is used.
 */

if( isset( $_POST[ 'btnSign' ] ) ) {
	// Get input
	$message = isset( $_POST[ 'mtxMessage' ] ) ? trim( (string) $_POST[ 'mtxMessage' ] ) : '';
	$name    = isset( $_POST[ 'txtName' ] ) ? trim( (string) $_POST[ 'txtName' ] ) : '';

	// Keep the values within the size of the database columns
	if( function_exists( 'mb_substr' ) ) {
		$message = mb_substr( $message, 0, 300, 'UTF-8' );
		$name    = mb_substr( $name, 0, 100, 'UTF-8' );
	}
	else {
		$message = substr( $message, 0, 300 );
		$name    = substr( $name, 0, 100 );
	}

	// Update database
	$data = $db->prepare( 'INSERT INTO guestbook ( comment, name ) VALUES ( :message, :name );' );
	$data->bindParam( ':message', $message, PDO::PARAM_STR );
	$data->bindParam( ':name', $name, PDO::PARAM_STR );
	$data->execute();
}

?>
