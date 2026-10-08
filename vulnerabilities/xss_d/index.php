<?php

define( 'DVWA_WEB_PAGE_TO_ROOT', '../../' );
require_once DVWA_WEB_PAGE_TO_ROOT . 'dvwa/includes/dvwaPage.inc.php';

dvwaPageStartup( array( 'authenticated' ) );

$page = dvwaPageNewGrab();
$page[ 'title' ]   = 'Vulnerability: DOM Based Cross Site Scripting (XSS)' . $page[ 'title_separator' ].$page[ 'title' ];
$page[ 'page_id' ] = 'xss_d';
$page[ 'help_button' ]   = 'xss_d';
$page[ 'source_button' ] = 'xss_d';

dvwaDatabaseConnect();

$vulnerabilityFile = '';
switch( dvwaSecurityLevelGet() ) {
	case 'low':
		$vulnerabilityFile = 'low.php';
		break;
	case 'medium':
		$vulnerabilityFile = 'medium.php';
		break;
	case 'high':
		$vulnerabilityFile = 'high.php';
		break;
	default:
		$vulnerabilityFile = 'impossible.php';
		break;
}

require_once DVWA_WEB_PAGE_TO_ROOT . "vulnerabilities/xss_d/source/{$vulnerabilityFile}";

# The language chosen by the user is only ever handled as data: it is read
# with URLSearchParams and inserted with textContent / value, never written
# into the document as HTML (no document.write, no decoding into markup).

$page[ 'body' ] = <<<EOF
<div class="body_padded">
	<h1>Vulnerability: DOM Based Cross Site Scripting (XSS)</h1>

	<div class="vulnerable_code_area">
 
 		<p>Please choose a language:</p>

		<form name="XSS" method="GET">
			<select name="default" id="xss_d_default">
				<option value='English'>English</option>
				<option value='French'>French</option>
				<option value='Spanish'>Spanish</option>
				<option value='German'>German</option>
			</select>
			<input type="submit" value="Select" />
		</form>
		<script>
			(function () {
				var lang = new URLSearchParams(window.location.search).get("default");
				if (lang === null) {
					return;
				}
				var select = document.getElementById("xss_d_default");

				var separator = document.createElement("option");
				separator.value = "";
				separator.disabled = true;
				separator.textContent = "----";
				select.insertBefore(separator, select.firstChild);

				var chosen = document.createElement("option");
				chosen.value = lang;
				chosen.textContent = lang;
				select.insertBefore(chosen, select.firstChild);
				select.selectedIndex = 0;
			})();
		</script>
	</div>
EOF;

$page[ 'body' ] .= "
	<h2>More Information</h2>
	<ul>
		<li>" . dvwaExternalLinkUrlGet( 'https://owasp.org/www-community/attacks/xss/' ) . "</li>
		<li>" . dvwaExternalLinkUrlGet( 'https://owasp.org/www-community/attacks/DOM_Based_XSS' ) . "</li>
		<li>" . dvwaExternalLinkUrlGet( 'https://www.acunetix.com/blog/articles/dom-xss-explained/' ) . "</li>
	</ul>
</div>\n";

dvwaHtmlEcho( $page );

?>
