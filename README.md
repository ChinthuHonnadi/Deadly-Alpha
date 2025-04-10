✅ UPDATED ISSUE BREAKDOWN:
1. Vertical Privilege Escalation
CVSS v3.1: 8.8 (High)

Vector: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H

OWASP: A01:2021 – Broken Access Control

2. Broken Access Control
CVSS v3.1: 8.5 (High)

Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L

Rationale: Privileges are not required, but only partial integrity/availability compromise.

OWASP: A01:2021 – Broken Access Control

3. Metadata Exfiltration (No UI)
CVSS v3.1: 6.5 (Medium)

Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N

OWASP: A01 or A06

Rationale: No UI required now, so risk goes up — user just hits an endpoint and data leaks.

4. Improper Error Handling
CVSS v3.1: 3.7 (Low)

Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N

OWASP: A05 or A09

5. CSRF on Logout
CVSS v3.1: 3.1 (Low)

Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N

OWASP: A01

6. Internal IP Disclosure
CVSS v3.1: 3.1 (Low)

Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N

OWASP: A05 or A06

7. Client-Side Validation Bypass (Low)
CVSS v3.1: 3.7 (Low)

Vector: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N

OWASP: A04 or A01

Rationale: Only impacts integrity minimally, and attacker needs valid user access.

8. Server Info Disclosure in Headers
CVSS v3.1: 3.1 (Low)

Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N

OWASP: A05
