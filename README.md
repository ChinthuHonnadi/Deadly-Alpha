In the current scenario, the test team observed that upon submitting a JavaScript payload in the "Name" input field, the payload was stored in the database. When the page was rendered, the injected JavaScript code executed, resulting in a stored XSS vulnerability.

It is recommended to:

Implement Output Encoding – Properly encode user-generated content before rendering it in the HTML response to prevent script execution. Use frameworks like OWASP's ESAPI or built-in encoding functions (htmlspecialchars() in PHP, HTMLEncode() in ASP.NET).

Use Content Security Policy (CSP) – Enforce a strong CSP header to restrict the execution of inline scripts and only allow trusted sources.

Validate and Sanitize User Input – Strip or escape potentially dangerous characters (<, >, ", ', /, \, &, ;, (, )) before storing user input in the database. Use libraries like DOMPurify for JavaScript-based applications.
