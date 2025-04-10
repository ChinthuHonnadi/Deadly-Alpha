Additionally, the test team, using a low-privileged Employee account, was able to access certain endpoints that should only be available to HR Managers. These endpoints returned sensitive information like new joiners’ personal details and a summary of employee claims. There were no server-side checks to confirm the user's role or permission, and the data was fully accessible using just an employee session.


Risk Impact: The attacker can perform unauthorized actions such as approving HR-related records like CTCs and viewing restricted data including onboarding information and financial claim summaries. This can lead to data integrity issues, internal data leaks, privacy violations, and misuse of sensitive organizational information.

Add endpoints ok?



The attacker can upload or extract images containing embedded metadata such as GPS coordinates, device details, timestamps, and user-identifying information, which are not sanitized by the application. This puts users at risk of unintentional exposure of sensitive data like location history or internal tool usage, especially when uploading images taken from mobile devices. Additionally, embedded script payloads or comments can persist within stored files, potentially enabling client-side attacks or downstream exploitation. This exposure increases the risk of targeted social engineering, privacy violations, metadata-based tracking
