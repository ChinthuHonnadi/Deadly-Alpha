Issue Name: Vertical Privilege Escalation – Unauthorized CTC Approval by Employee Role

Description: The test team observed that the application allows an employee to approve CTC, which should only be allowed by HR Manager.

Observation:

In the current scenario, the test team found that a user with the role of Employee was able to approve CTC (Cost to Company) records using valid session identifiers. This functionality is intended to be accessed and executed only by users with HR Manager privileges. The team intercepted the request made during CTC approval and replayed it using an employee session token. The action succeeded, indicating a missing access control check on the server-side endpoint responsible for approval.

Risk Impact: The attacker can approve or manipulate sensitive HR records like CTC details without having the appropriate privileges. This can lead to data integrity issues, unauthorized actions on employee records, policy violations, and possible financial fraud.

Severity: Critical

Recommendations: It is recommended to:

Enforce strict server-side role-based access control (RBAC) checks before allowing any action such as CTC approval.

Do not rely on client-side role checks (e.g., hiding buttons) as a security mechanism.

Log all access control violations with sufficient user context for auditing and incident response.

Review all sensitive functions to ensure proper authorization logic is implemented.

Implement a central access control middleware to validate user roles and permissions.

OWASP Top 10 2021 Mapping: A01:2021 – Broken Access Control

CVSS 3.0 Score: 9.6 (Critical)
CVSS Vector: AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N

CWE: CWE-284 – Improper Access Control
---------------------------------
Issue Name: Metadata Exfiltration via Unfiltered Image Upload

Description: The test team observed that the application allows uploading image files with embedded metadata and malicious content without sanitization.

Observation:

In the current scenario, the test team uploaded a .jpg image as a profile picture. The image was embedded with geolocation metadata and a small XSS payload within the metadata fields (e.g., <script>alert('xss')</script> in EXIF comments). After successfully uploading the image, it was downloaded again and analyzed. The test team confirmed that neither the geolocation metadata nor the XSS payload was sanitized or stripped. This means sensitive data such as GPS coordinates remain embedded, and malicious code could be preserved or exposed during downstream processing.

Risk Impact: The attacker can embed malicious metadata into images and use the platform to store and distribute it. This could result in:

Exposure of user or device location (if taken from a mobile or GPS-enabled camera)

Injection points for XSS or other client-side attacks if image metadata is ever rendered in any downstream interface

Abuse by insider threats to leak internal geotagged documents or conduct surveillance

Severity: Medium

Recommendations: It is recommended to:

Strip all metadata (EXIF, IPTC, XMP) from user-uploaded images on the server side using tools like exiftool, ImageMagick, or jpegtran.

Validate uploaded content types and restrict file parsing to only image-related operations.

Do not rely on client-side preview or stripping — ensure server-side enforcement.

Scan uploaded files for embedded scripts or payloads if metadata is used in any downstream business logic.

Disable unnecessary image metadata fields if rendering is required for business purposes.

OWASP Top 10 2021 Mapping: A01:2021 – Broken Access Control
(Also partially touches A03:2021 – Injection if metadata is parsed or displayed)

CVSS 3.0 Score: 6.5 (Medium)
CVSS Vector: AV:N/AC:L/PR:L/UI:R/S:U/C:H/I:N/A:N

CWE: CWE-176 – Improper Handling of File Metadata
Also related: CWE-79 – Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')


-----------------------
Issue Name: Cross-Site Request Forgery (CSRF) on Logout Functionality

Description: The test team observed that the logout functionality is vulnerable to CSRF.

Observation:

In the current scenario, the test team crafted a malicious link targeting the logout endpoint. When this link was clicked by an authenticated user, the session gets terminated without the user’s knowledge or consent. 

Risk Impact: The attacker can force users to log out unexpectedly. This may lead to user annoyance or disruption, but it does not expose any sensitive data or allow unauthorized actions.

Severity: Low

Recommendations: It is recommended to:

Implement CSRF tokens on state-changing requests, including logout actions.

Enforce same-site cookie attributes (SameSite=Lax or Strict) to prevent cross-origin requests from carrying session cookies.

Use HTTP POST for logout requests instead of GET to make them less susceptible to CSRF.

Prompt users for confirmation on logout actions when feasible.

OWASP Top 10 2021 Mapping: A01:2021 – Broken Access Control

CVSS 3.0 Score: 3.1 (Low)
CVSS Vector: AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:L

CWE: CWE-352 – Cross-Site Request Forgery (CSRF)




-------------------------

Issue Name: Missing Rate Limiting

Description: The test team observed that the application does not enforce rate limiting.

Observation:

In the current scenario, the test team automated the submission of over 100 previous work experience entries along with image uploads using a low-privileged user account. These submissions were made within 10 seconds without encountering any server-side rate limits, throttling, or CAPTCHA validation.

Risk Impact: The attacker can flood the system with large volumes of data, leading to resource exhaustion, storage abuse, and database bloating. This can degrade application performance, affect availability, and make it difficult for administrators to review legitimate data.

Severity: Medium

Recommendations: It is recommended to:

Implement server-side rate limiting for endpoints that accept user input, especially those involving file uploads or database writes.

Enforce CAPTCHA or reCAPTCHA mechanisms to prevent automated abuse.

Apply per-user and per-IP submission throttling logic with exponential backoff.

Set reasonable limits on the number of entries a user can submit within a specific timeframe.

Log and monitor for bursty or abnormal submission patterns for detection.

OWASP Top 10 2021 Mapping: A07:2021 – Identification and Authentication Failures
(Also relates to A01:2021 – Broken Access Control if abuse impacts resource usage limits)

CVSS 3.0 Score: 5.3 (Medium)
CVSS Vector: AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:L


--------------------------




Issue Name: Improper Error Handling

Description: The test team observed that the application discloses sensitive error messages when accessing invalid URLs.

Observation:

In the current scenario, the test team accessed the endpoint GetEmployeePhoto.ashx with random or malformed query parameters (e.g., GetEmployeePhoto.ashx?randomtext). The application displayed a verbose error message containing internal implementation details such as .NET Framework version, ASP.NET version, and a full stack trace. 

Risk Impact: The attacker can collect detailed information about the application’s technology stack, which may help in crafting targeted attacks. Exposed stack traces can reveal class names, method calls, internal file paths, and framework versions, all of which assist in vulnerability research and exploitation planning.

Severity: Low

Recommendations: It is recommended to:

Disable detailed error messages in production by setting customErrors to RemoteOnly or On in web.config.

Use generic user-facing error pages and log technical details internally.

Regularly review and sanitize error responses from all public endpoints.

Ensure verbose stack traces and version disclosures are not accessible to unauthenticated users.

OWASP Top 10 2021 Mapping: A05:2021 – Security Misconfiguration

CVSS 3.0 Score: 3.7 (Low)
CVSS Vector: AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N

CWE: CWE-209 – Generation of Error Message Containing Sensitive Information

CWE: CWE-770 – Allocation of Resources Without Limits or Throttling


--------------------
Issue Name: Backend Server Information Disclosure via HTTP Response Header

Description: The test team observed that the application discloses backend server information through HTTP response headers.

Observation:

In the current scenario, the test team inspected the HTTP response headers from the application and found that the Server header was exposing backend web server type. 

Risk Impact: The attacker can gather details about the backend infrastructure, which may be used to identify known vulnerabilities, plan targeted exploits, or fingerprint the tech stack for further attacks.

Severity: Low

Recommendations: It is recommended to:

Suppress or remove the Server header from HTTP responses using server-level configuration (e.g., in IIS, set removeServerHeader to true).

Configure the web server to return minimal or generic information in headers (e.g., Server: Secure or omit entirely).

Regularly audit HTTP headers for unnecessary information disclosure.

OWASP Top 10 2021 Mapping: A05:2021 – Security Misconfiguration

CVSS 3.0 Score: 3.1 (Low)
CVSS Vector: AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N

CWE: CWE-200 – Exposure of Sensitive Information to an Unauthorized Actor






--------------------------
Issue Name: Malicious File Upload – PDF with Embedded Payloads

Description: The test team observed that the application allows uploading of malicious PDF files without proper validation or sanitization.

Observation:

In the current scenario, the test team uploaded a crafted PDF file containing embedded CSS-based payloads. When the uploaded PDF was later rendered by the application, a script execution popup was triggered, indicating that the embedded payload was not sanitized or blocked. Additionally, the application allowed the upload of PDF files containing known malware signatures.

Risk Impact: The attacker can upload malicious PDF files that, when accessed, may lead to execution of unauthorized code, client-side script injection, or malware delivery. This can result in phishing attacks, compromise of user devices, or unauthorized script execution in the rendering environment.

Severity: Medium

Recommendations: It is recommended to:

Implement server-side validation to check and sanitize uploaded PDF content.

Integrate antivirus/malware scanning (e.g., ClamAV, VirusTotal API) for all uploaded files before storing or rendering them.

Restrict allowed file types using MIME type and content-based verification, not just file extensions.

Disable PDF rendering in the browser where possible; provide download-only access.

Sanitize and flatten embedded content (scripts, media, annotations) in documents before serving them.

OWASP Top 10 2021 Mapping: A05:2021 – Security Misconfiguration
(Also relates to A03:2021 – Injection if script execution is possible)

CVSS 3.0 Score: 6.6 (Medium)
CVSS Vector: AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N

CWE: CWE-434 – Unrestricted Upload of File with Dangerous Type



--------------------------
Issue Name: Client-Side Validation Bypass on Previous Work Experience Dates

Description: The test team observed that client-side validation for work experience dates can be bypassed.

Observation:

In the current scenario, the test team found that while adding a previous work experience entry, the form restricted selecting an end date earlier than the start date through client-side controls. However, by intercepting and modifying the request, the test team was able to submit a record where the end date was before the start date. The server accepted the data without any validation, resulting in logically inconsistent entries being stored.

Risk Impact: The attacker can bypass client-side validation and inject invalid or inconsistent data into the application. This can affect reporting, data integrity, and downstream business logic.

Severity: Low

Recommendations: It is recommended to:

Implement server-side validation to ensure that end dates are always after start dates.

Avoid relying solely on client-side checks for enforcing business rules.

Sanitize and validate all incoming data before database storage.

OWASP Top 10 2021 Mapping: A01:2021 – Broken Access Control

CVSS 3.0 Score: 3.5 (Low)
CVSS Vector: AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N

CWE: CWE-20 – Improper Input Validation


----------------------------
Issue Name: Internal IP Address Disclosure in HTTP Response

Description: The test team observed that internal server IP addresses are being leaked in HTTP responses.

Observation:

In the current scenario, the test team submitted a malicious input to test for XSS, and the response body contained a message like “Potential XSS Request” followed by an internal IP address (10.202.19.171).

Risk Impact: The attacker can gather details about the internal network and infrastructure. This can aid in reconnaissance, internal IP mapping, or chaining with other attacks like SSRF, LFI, or misconfigured cloud storage access.

Severity: Low

Recommendations: It is recommended to:

Remove or sanitize debug/error messages before sending responses to the client.

Ensure that internal IP addresses and system messages are never exposed in production environments.

Handle invalid or malicious inputs with generic error messages.

Log internal details server-side only and never include them in the client response.

OWASP Top 10 2021 Mapping: A06:2021 – Vulnerable and Outdated Components
(Also partially A05:2021 – Security Misconfiguration)

CVSS 3.0 Score: 3.7 (Low)
CVSS Vector: AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N

CWE: CWE-200 – Exposure of Sensitive Information to an Unauthorized Actor
