<?php

/*
 * File Upload - patched.
 *
 * - Only .jpg/.jpeg/.png extensions are accepted (allowlist).
 * - The real file type is detected server side (getimagesize) and must match
 *   the extension; the client supplied Content-Type is ignored.
 * - The image is re-encoded with GD, which strips any appended/embedded
 *   payload (polyglots), and saved under a random name with a safe extension.
 */

if( isset( $_POST[ 'Upload' ] ) ) {
	$allowed_types = array(
		'jpg'  => IMAGETYPE_JPEG,
		'jpeg' => IMAGETYPE_JPEG,
		'png'  => IMAGETYPE_PNG,
	);

	$uploaded_ok = isset( $_FILES[ 'uploaded' ] ) && is_array( $_FILES[ 'uploaded' ] ) &&
		isset( $_FILES[ 'uploaded' ][ 'error' ] ) && $_FILES[ 'uploaded' ][ 'error' ] === UPLOAD_ERR_OK;

	$valid = false;
	if( $uploaded_ok ) {
		// File information
		$uploaded_name = (string) $_FILES[ 'uploaded' ][ 'name' ];
		$uploaded_ext  = strtolower( pathinfo( $uploaded_name, PATHINFO_EXTENSION ) );
		$uploaded_size = (int) $_FILES[ 'uploaded' ][ 'size' ];
		$uploaded_tmp  = (string) $_FILES[ 'uploaded' ][ 'tmp_name' ];

		$image_info = is_uploaded_file( $uploaded_tmp ) ? @getimagesize( $uploaded_tmp ) : false;

		// Is it really an image of an allowed type, matching its extension?
		$valid = isset( $allowed_types[ $uploaded_ext ] ) &&
			( $uploaded_size > 0 ) && ( $uploaded_size < 100000 ) &&
			( $image_info !== false ) &&
			( $image_info[ 2 ] === $allowed_types[ $uploaded_ext ] );
	}

	if( $valid ) {
		// Re-encode the image to strip anything that is not image data
		if( $image_info[ 2 ] === IMAGETYPE_JPEG ) {
			$img = @imagecreatefromjpeg( $uploaded_tmp );
			$ext = 'jpg';
		}
		else {
			$img = @imagecreatefrompng( $uploaded_tmp );
			$ext = 'png';
		}

		// Where are we going to be writing to? Use a random name.
		$target_path = DVWA_WEB_PAGE_TO_ROOT . 'hackable/uploads/';
		$target_file = bin2hex( random_bytes( 16 ) ) . '.' . $ext;

		$saved = false;
		if( $img !== false ) {
			if( $ext === 'jpg' ) {
				$saved = imagejpeg( $img, $target_path . $target_file, 90 );
			}
			else {
				$saved = imagepng( $img, $target_path . $target_file, 9 );
			}
			unset( $img );
		}

		if( $saved ) {
			// Yes!
			$html .= "<pre><a href='{$target_path}{$target_file}'>{$target_path}{$target_file}</a> succesfully uploaded!</pre>";
		}
		else {
			// No
			$html .= '<pre>Your image was not uploaded.</pre>';
		}
	}
	else {
		// Invalid file
		$html .= '<pre>Your image was not uploaded. We can only accept JPEG or PNG images.</pre>';
	}
}

?>
