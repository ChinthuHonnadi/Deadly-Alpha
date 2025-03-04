Issue Name: No Rate Limiting on File Upload
Description:
The test team observed that the application does not enforce rate limiting.

Instance:
In the current scenario, It was observed that team was able to upload multiple files without restrictions. The application does not impose any limits on the number of uploads per user or enforce time-based restrictions.


Exploitation:
Navigate to the file upload section of the application.
Use Burp Suite Intruder to send multiple upload requests rapidly. 


Risk:
The attacker can exploit this flaw to:

Overload the server by continuously uploading files, leading to Denial of Service (DoS).
Bypass intended upload limits, consuming excessive storage and system resources.
Automate mass uploads of malicious files to spread malware or conduct further attacks


Rec:
Implement rate limiting to restrict the number of uploads per user within a defined timeframe.
Enforce upload quotas (e.g., max file uploads per hour/day per user).
Implement progressive delays or CAPTCHA after multiple uploads.
Monitor upload activity and apply account-based restrictions to detect abuse.


CWE-770: Allocation of Resources Without Limits or Throttling

OWASP Top 10 2021 Mapping: A04:2021 – Insecure Design

CVSS 3.0 Score: 7.5 (High) (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H)
