<?php
if (!defined('DVWA_WEB_PAGE_TO_ROOT')) {
    define('DVWA_WEB_PAGE_TO_ROOT', '../../../');
}

/*
 * Broken Access Control - patched.
 *
 * Who the requester is comes from the authenticated server-side session
 * (dvwaCurrentUser()), looked up in the database on every request - never from
 * a client controlled value such as a cookie, a hidden field or a "token" in
 * the query string. A user may only view their own profile.
 */

// Get current user's ID and role from the server side identity
$current_user = dvwaCurrentUser();
$stmt = mysqli_prepare($GLOBALS["___mysqli_ston"], "SELECT user_id, role FROM users WHERE user = ? LIMIT 1");
mysqli_stmt_bind_param($stmt, "s", $current_user);
mysqli_stmt_execute($stmt);
$result = mysqli_stmt_get_result($stmt);
$row = ($result && mysqli_num_rows($result) > 0) ? mysqli_fetch_assoc($result) : array('user_id' => 0, 'role' => '');
mysqli_stmt_close($stmt);
$current_user_id = intval($row['user_id']);
$role = (string) $row['role'];

$html = "";
if (isset($_GET['action']) && isset($_GET['user_id'])) {
    if (!is_string($_GET['user_id']) || !preg_match('/^\d{1,9}$/', $_GET['user_id'])) {
        $html .= "<p>Invalid user ID format. Please enter a number.</p>";
    } else {
        $id = intval($_GET['user_id']);

        // Check if user exists first
        $check_stmt = mysqli_prepare($GLOBALS["___mysqli_ston"], "SELECT user_id FROM users WHERE user_id = ? LIMIT 1");
        mysqli_stmt_bind_param($check_stmt, "i", $id);
        mysqli_stmt_execute($check_stmt);
        mysqli_stmt_store_result($check_stmt);
        $user_exists = (mysqli_stmt_num_rows($check_stmt) > 0);
        mysqli_stmt_close($check_stmt);

        if (!$user_exists) {
            $html .= "<p>No user found with ID: {$id}</p>";
        } else if ($current_user_id === 0 || $id !== $current_user_id) {
            $html .= "<p>Access denied. You can only view your own profile.</p>";
        } else {
            // Access granted - the requester is viewing their own profile
            $stmt = mysqli_prepare($GLOBALS["___mysqli_ston"], "SELECT first_name, last_name, user_id, avatar FROM users WHERE user_id = ? LIMIT 1");
            mysqli_stmt_bind_param($stmt, "i", $id);
            mysqli_stmt_execute($stmt);
            $result = mysqli_stmt_get_result($stmt);

            if ($result && mysqli_num_rows($result) > 0) {
                $row = mysqli_fetch_assoc($result);
                $html .= "
                    <div class=\"profile-info\">
                        <h3>User Profile</h3>
                        <p>User ID: " . htmlspecialchars((string) $row['user_id'], ENT_QUOTES, 'UTF-8') . "</p>
                        <p>Name: " . htmlspecialchars((string) $row['first_name'], ENT_QUOTES, 'UTF-8') . " " . htmlspecialchars((string) $row['last_name'], ENT_QUOTES, 'UTF-8') . "</p>
                        <p>Avatar: " . htmlspecialchars((string) $row['avatar'], ENT_QUOTES, 'UTF-8') . "</p>
                    </div>";
            }
            mysqli_stmt_close($stmt);
        }

        // Log access attempts
        try {
            mysqli_query($GLOBALS["___mysqli_ston"], "CREATE TABLE IF NOT EXISTS bac_log (
                id INT(6) UNSIGNED AUTO_INCREMENT PRIMARY KEY,
                user_id INT(6) NULL,
                target_id INT(6) NULL,
                ip_address VARCHAR(50) NULL,
                action VARCHAR(50) NULL,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )");

            // Log the address the request really came from (X-Forwarded-For is client controlled)
            $ip = substr((string) $_SERVER['REMOTE_ADDR'], 0, 50);
            $target_id = $user_exists ? $id : 0; // Use 0 for non-existent users
            $log_stmt = mysqli_prepare($GLOBALS["___mysqli_ston"], "INSERT INTO bac_log (user_id, target_id, ip_address) VALUES (?, ?, ?)");
            mysqli_stmt_bind_param($log_stmt, "iis", $current_user_id, $target_id, $ip);
            mysqli_stmt_execute($log_stmt);
            mysqli_stmt_close($log_stmt);
        } catch (Exception $e) {
            // Silently fail if logging doesn't work
        }
    }
}

// Show current user's role (from the database, not from a cookie) for context
$html .= "<div class='info-banner'>Current Role: " . htmlspecialchars($role !== '' ? $role : 'user', ENT_QUOTES, 'UTF-8') . "</div>";
?>
