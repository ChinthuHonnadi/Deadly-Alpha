Issue Name: Vertical Privilege Escalation in Timetable Rules Edit Feature

Description:

The test team observed that the application is vulnerable to vertical privilege escalation.

Observation:

In the current scenario, it was observed that the timetable rules edit feature lacks proper authorization checks. A low-privileged user with “Watcher” access is able to edit the rules, which should only be allowed for higher-privileged users.

Risk Impact:

The attacker can modify timetable rules without proper authorization, which may disrupt schedules, manipulate data, or cause operational issues. This could lead to unauthorized changes that affect multiple users and compromise system integrity.

Severity: High

Recommendations:
 • Implement proper authorization checks to ensure that only authorized roles can edit timetable rules.
 • Enforce role-based access control (RBAC) to restrict actions based on user privileges.
 • Regularly review and test access controls to prevent privilege escalation vulnerabilities.

OWASP Top 10 2021 Mapping: A01:2021 – Broken Access Control

CVSS 3.0 Score: 7.5 (High) (CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)




Issue Name: Information Disclosure in HTTP Responses

Description:

The test team observed that sensitive information was included in HTTP responses.

Observation:

In the current scenario, it was observed that the server responses contained sensitive details such as server information, API keys, and private IP addresses. This information was exposed in HTTP headers, response bodies, or error messages, which could be accessed by attackers.

Risk Impact:

The attacker can gather sensitive details about the server and infrastructure, which may help in further attacks like server fingerprinting, API abuse, or internal network exploitation. Exposure of API keys can also lead to unauthorized access to backend services.

Severity: High

Recommendations:
 • Remove unnecessary information from HTTP headers and error messages.
 • Avoid exposing API keys or internal system details in client-facing responses.
 • Implement proper error handling to prevent stack traces or debug messages from being displayed.
 • Regularly review and sanitize responses to ensure no sensitive data is unintentionally exposed.

OWASP Top 10 2021 Mapping: A01:2021 – Broken Access Control

CVSS 3.0 Score: 7.3 (High) (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:L)




Issue Name: Use of Vulnerable Components

Description:

The test team observed that vulnerable software components are used in the application.

Observation:

In the current scenario, it was observed that the application is using AngularJS 1.5.5, which has known security vulnerabilities. This version is outdated and contains multiple security flaws that can be exploited by attackers.

CVE Link: [Provide relevant CVE link]

Risk Impact:

The attacker can exploit known vulnerabilities in outdated software components to compromise the application’s security. This may lead to cross-site scripting (XSS), remote code execution (RCE), or other attacks that affect the application’s integrity and user data.

Severity: High

Recommendations:
 • Upgrade AngularJS to the latest supported version or migrate to a more secure framework.
 • Regularly monitor and update third-party dependencies to patch known vulnerabilities.
 • Use software composition analysis (SCA) tools to identify and remediate insecure components.
 • Follow secure coding best practices to mitigate risks associated with outdated libraries.

OWASP Top 10 2021 Mapping: A06:2021 – Vulnerable and Outdated Components

CVSS 3.0 Score: 7.5 (High) (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N)




Issue Name: Inadequate Error Handling

Description:

The test team observed that the application has improper error handling, leading to sensitive information disclosure.

Observation:

In the current scenario, it was observed that the application exposes backend details in error messages.
When an invalid request was sent, the response included internal system information such as class names, framework details, and stack traces.

For example, the application returned the following error message:
“JSON value could not be converted indus.webapi v2 contract requests timetables path: $ | LineNumber: 0 | BytepositionLine: 1”

This indicates that the application is revealing internal API structures and implementation details, which can help an attacker understand the backend technology stack and identify potential weaknesses.

Risk Impact:

The attacker can gain insights into the application’s backend, including API structure, class names, and frameworks used. This can be leveraged to craft targeted attacks, such as exploiting deserialization vulnerabilities, injecting malformed data, or identifying unprotected endpoints.

Severity: Medium

Recommendations:
 • Implement generic error messages that do not expose internal system details.
 • Log detailed error messages on the server but only return user-friendly messages to clients.
 • Use centralized error handling to properly manage and sanitize error responses.
 • Regularly test and review error-handling mechanisms to prevent unintended data exposure.

OWASP Top 10 2021 Mapping: A01:2021 – Broken Access Control

CVSS 3.0 Score: 5.3 (Medium) (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)




Issue Name: Malicious File Upload

Description:

The test team observed that the application allows uploading of malicious files to the server.

Observation:

In the current scenario, it was observed that files containing malware were successfully uploaded to the server without any security restrictions. The application does not properly validate file types, scan for malicious content, or restrict executable files, allowing attackers to upload harmful files that could be used for further exploitation.

Risk Impact:

The attacker can upload malicious files, which may lead to remote code execution, server compromise, or malware distribution. This could allow unauthorized access, data theft, or further exploitation of system vulnerabilities.

Severity: Critical

Recommendations:
 • Implement strict file validation to allow only permitted file types and block executable or script-based files.
 • Use antivirus and malware scanning tools to detect and prevent malicious file uploads.
 • Restrict uploaded files from being executed on the server.
 • Store uploaded files in a secure directory with limited permissions.
 • Implement content-type verification and enforce file extension checks to prevent spoofing.

OWASP Top 10 2021 Mapping: A08:2021 – Software and Data Integrity Failures

CVSS 3.0 Score: 9.0 (Critical) (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H)





Issue Name: CSP Misconfiguration

Description:

The test team observed that the application has a misconfigured Content Security Policy (CSP).

Observation:

In the current scenario, it was observed that the application’s CSP includes the following directive:

Content-Security-Policy: frame-ancestors 'self' https://indus.com;

This configuration allows the application to be embedded in an iframe from https://indus.com, which may expose it to Clickjacking attacks if indus.com is compromised or allows user-controlled content. Additionally, the CSP lacks other security directives like default-src, script-src, and object-src, which are essential to prevent various client-side attacks such as Cross-Site Scripting (XSS).

Risk Impact:

The attacker can embed the application in an iframe on a malicious website and trick users into interacting with it unknowingly, leading to Clickjacking attacks. Additionally, the incomplete CSP configuration may fail to mitigate XSS or data injection risks effectively.

Severity: Medium

Recommendations:
 • Ensure that the frame-ancestors directive is restricted to only trusted domains or removed if framing is unnecessary.
 • Implement a strict CSP policy that includes default-src 'none'; script-src 'self'; object-src 'none' to reduce XSS risks.
 • Regularly review and test the CSP implementation to ensure it provides adequate protection.
 • Consider using sandbox and X-Frame-Options headers for additional Clickjacking protection.

OWASP Top 10 2021 Mapping: A05:2021 – Security Misconfiguration

CVSS 3.0 Score: 6.5 (Medium) (CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)





Issue Name: Cross-Site Request Forgery (CSRF) on Logout

Description:

The test team observed that the application is vulnerable to Cross-Site Request Forgery (CSRF) on the logout functionality.

Observation:

In the current scenario, it was observed that the logout request is initiated via a simple GET or POST request without requiring CSRF protection (such as a token). This allows an attacker to craft a malicious request that can automatically log out a user if they visit a compromised or attacker-controlled website.

For example, if the logout endpoint is:

GET /logout

or

POST /logout

An attacker can embed the following code on a malicious website:

<img src="https://target.com/logout" style="display:none;">

When a logged-in user visits the attacker’s page, their browser will automatically send the request, logging them out without their consent.

Risk Impact:

The attacker can force users to log out of their session without their knowledge, disrupting user experience and potentially aiding in session fixation or phishing attacks by forcing users to reauthenticate.

Severity: Low

Recommendations:
 • Implement CSRF protection by requiring a valid anti-CSRF token in logout requests.
 • Use SameSite=Strict or SameSite=Lax cookie attributes to prevent cross-site request execution.
 • Require user interaction, such as clicking a logout button, instead of allowing automatic logout via GET requests.
 • Implement proper session management controls to mitigate session-related attacks.

OWASP Top 10 2021 Mapping: A07:2021 – Identification and Authentication Failures

CVSS 3.0 Score: 3.1 (Low) (CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:L/A:N)






Issue Name: Session Not Destroying After Logout

Description:

The test team observed that user sessions are not properly invalidated after logout, allowing previously captured session cookies to remain valid.

Observation:

In the current scenario, the test team logged into the application, performed some actions, and captured a request containing the session cookie. After logging out, the team replayed the captured request with the old session cookie, and the server still processed the request successfully, returning a valid response as an authenticated user. This indicates that the session was not properly terminated on the server-side after logout.

Risk Impact:

The attacker can reuse stolen or intercepted session cookies even after the user logs out, maintaining unauthorized access to the account. This can lead to session hijacking, data exposure, and account takeovers, posing a significant security risk.

Severity: High

Recommendations:
 • Ensure that user sessions are completely invalidated on the server-side upon logout.
 • Implement session token revocation so that any further requests with the old session ID are rejected.
 • Use HttpOnly and Secure attributes for session cookies to prevent theft via JavaScript or insecure transmission.
 • Implement session expiration and automatic session invalidation after a period of inactivity.
 • Monitor and log session activities to detect and prevent session reuse attacks.

OWASP Top 10 2021 Mapping: A07:2021 – Identification and Authentication Failures

CVSS 3.0 Score: 7.5 (High) (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N)






Issue Name: Cookie Path Set to Root

Description:

The test team observed that the application sets cookies with the path attribute set to / (root), making them accessible across the entire application.

Observation:

In the current scenario, it was observed that session cookies and other sensitive authentication-related cookies were assigned the path /.
This means the cookie is accessible by all endpoints within the domain, increasing the risk of unauthorized access if any subdirectory or feature within the application is vulnerable to Cross-Site Scripting (XSS) or other security flaws.

Risk Impact:

The attacker can exploit a vulnerable endpoint or page within the application to access session cookies, potentially leading to session hijacking or privilege escalation. This increases the attack surface and makes it easier for an attacker to steal or manipulate cookies.

Severity: Medium

Recommendations:
 • Restrict the cookie path to only the necessary sections of the application instead of using / as the default.
 • Set HttpOnly, Secure, and SameSite=Strict attributes to prevent theft via JavaScript and ensure secure transmission.
 • Regularly review cookie configurations to minimize exposure and prevent unauthorized access.
 • If the cookie is used for authentication, consider implementing session binding techniques (e.g., IP-based or device fingerprinting validation).

OWASP Top 10 2021 Mapping: A07:2021 – Identification and Authentication Failures

CVSS 3.0 Score: 6.0 (Medium) (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N)





Here are the corresponding CWE (Common Weakness Enumeration) IDs for each of the vulnerabilities reported:
 1. Vertical Privilege Escalation in Timetable Rules Edit Feature
 • CWE-269: Improper Privilege Management
 2. Information Disclosure in HTTP Responses
 • CWE-200: Exposure of Sensitive Information to an Unauthorized Actor
 3. Use of Vulnerable Components (Outdated AngularJS 1.5.5)
 • CWE-1104: Use of Unmaintained Third-Party Components
 4. Inadequate Error Handling
 • CWE-209: Generation of Error Message Containing Sensitive Information
 5. Malicious File Upload
 • CWE-434: Unrestricted Upload of File with Dangerous Type
 6. CSP Misconfiguration
 • CWE-693: Protection Mechanism Failure
 • CWE-942: Permissive Cross-Domain Policy with Untrusted Domains
 7. Cross-Site Request Forgery (CSRF) on Logout
 • CWE-352: Cross-Site Request Forgery (CSRF)
 8. Session Not Destroying After Logout
 • CWE-613: Insufficient Session Expiration
 9. Cookie Path Set to Root
 • CWE-1275: Sensitive Cookie with Improper Path Attribute
