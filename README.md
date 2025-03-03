
Here are the exploitation steps for all the listed vulnerabilities, following the required format:

1. Vertical Privilege Escalation – Timetable Rule Edit Lacks Authorization

Instance:

The test team identified that the Timetable Rule Edit feature lacks proper authorization controls, allowing a low-privileged user to modify rules that should only be editable by high-privileged users.

Exploitation Steps:
	1.	Log in as a high-privileged user and navigate to the Timetable Rule Edit feature.
	2.	Capture the request while performing an edit action.
	3.	Log out and log in as a low-privileged user.
	4.	Using the low-privileged user’s session, replace the high-privileged user’s session details in the captured request.
	5.	Submit the modified request.
	6.	Observe that the request is successfully processed with a 200 OK response, confirming privilege escalation.

2. Use of Vulnerable AngularJS 1.5.5 (CVE-2024-21490, CVE-2024-8363, CVE-2024-8372)

Instance:

The application uses AngularJS 1.5.5, which has multiple known vulnerabilities (CVE-2024-21490, CVE-2024-8363, CVE-2024-8372).

Exploitation Steps:
	1.	Identify any user input fields that AngularJS renders dynamically.
	2.	Inject an XSS payload like:

{{constructor.constructor('alert(1)')()}}


	3.	Submit the payload and check if the JavaScript executes.
	4.	If successful, it confirms that the application is vulnerable to AngularJS sandbox bypass due to the outdated version.

3. Malicious File Upload

Instance:

The application allows file uploads in the Cycles > Upload File section without validating file content.

Exploitation Steps:
	1.	Navigate to Cycles > Upload File.
	2.	Choose a malicious file (e.g., a .php shell or .exe payload).
	3.	Upload the file and observe that it is accepted without restriction.
	4.	If the file is accessible via a public URL, attempt to execute it to confirm remote code execution (RCE).

4. Session Not Invalidating After Logout

Instance:

The application does not properly terminate sessions after logout, allowing old session tokens to remain valid.

Exploitation Steps:
	1.	Log in and capture a request containing valid session details (e.g., session_id or authentication cookie).
	2.	Log out of the application.
	3.	Replay the captured request using the old session token.
	4.	Observe that the request still succeeds, confirming the session was not invalidated.

5. Information Disclosure

Instance:

Sensitive information, including server details, API keys, and private IP addresses, was exposed in HTTP responses.

Exploitation Steps:
	1.	Inspect HTTP response headers and observe that server information is included.
	2.	Access the /envconfig.json endpoint and observe that the Pendo API key is disclosed.
	3.	Request the ihcm-loaded.js file and find that it reveals a private IP address.
	4.	These exposures can help an attacker in reconnaissance and further exploitation.

6. CSRF on Logout

Instance:

The application does not protect logout requests against Cross-Site Request Forgery (CSRF).

Exploitation Steps:
	1.	Log in and capture the logout request (e.g., GET /logout).
	2.	Craft a malicious CSRF link:

<img src="https://target.com/logout" style="display:none;">


	3.	Send the crafted link to a victim.
	4.	When the victim clicks the link, they are automatically logged out without their consent.

7. Inadequate Error Handling

Instance:

The application exposes API details in error messages when an invalid request is sent.

Exploitation Steps:
	1.	Send an invalid request to:

GET /timetables/999044/holidays?


	2.	Observe that the error response contains API details, exposing internal system information.

8. CSP Misconfiguration

Instance:

The Content Security Policy (CSP) is misconfigured and lacks critical security directives.

Exploitation Steps:
	1.	Inspect the application’s CSP header:

Content-Security-Policy: frame-ancestors 'self' https://indus.com;


	2.	Observe that essential directives like script-src and object-src are missing.
	3.	Inject an inline script <script>alert('XSS')</script> into an input field and see if it executes, indicating weak CSP enforcement.

9. Cookie Path Set to Root

Instance:

The application sets cookies with the Path=/, making them accessible across all pages.

Exploitation Steps:
	1.	Inspect the application’s cookies using browser dev tools (Application > Cookies).
	2.	Observe that sensitive cookies (e.g., session tokens) have Path=/.
	3.	Confirm that any subdirectory or script within the application can access these cookies, increasing the risk of unauthorized access.

10. Inadequate Input Validation

Instance:

The application does not properly filter special characters in comments/conversations.

Exploitation Steps:
	1.	Navigate to comments/conversations and enter the following payload:

<script>alert('XSS')</script>


	2.	Submit the comment and observe if the script executes.
	3.	If successful, confirm that the application does not sanitize user input.

11. Concurrent Login Allowed

Instance:

The application allows users to be logged in from multiple devices without restrictions.

Exploitation Steps:
	1.	Log in to the application from Browser A.
	2.	Log in to the same account from Browser B (or another device).
	3.	Observe that both sessions remain active without notification or session termination.

This structure follows the Instance First → Exploitation Steps format as required. Would you like any additional refinements or details?
