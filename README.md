Vertical Privilege Escalation: Ensure access control is implemented across all endpoints based on user roles and permissions.
Vulnerable Software Components in Use: Evaluate the dependencies and upgrade to the latest stable version of software components.
Malicious File Upload: Implement strict file validation, allow only safe file types, and use malware scanning.
Rate Limiting Not Implemented: Enforce rate limiting to restrict excessive requests and prevent abuse.
Session Not Invalidating Upon Logout: Ensure sessions are completely destroyed on the server upon user logout.
Information Disclosure: Remove sensitive information from HTTP responses and restrict access to internal files.
CSRF on Logout: Implement anti-CSRF tokens and use the SameSite=Strict attribute for authentication cookies.
Inadequate Error Handling: Use generic error messages and avoid exposing internal system details in responses.
CSP Misconfiguration: Define a strict Content Security Policy (CSP) to mitigate XSS and data injection risks.
Cookie Path Set to Root: Restrict cookie scope to only necessary paths to minimize exposure.
Inadequate Input Validation: Enforce strict server-side input validation and sanitize user inputs to prevent injection attacks.
