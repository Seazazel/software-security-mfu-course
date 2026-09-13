# Weekly Quiz — Week 5 (Cross-Site Scripting)

**~10 min · in-class · 6 questions · low-stakes** (drop lowest). No devices / locked browser.

**Name:** Supichaya Rabiabnaweenurak  **Student ID:** 6631503118

## MCQ (5 × 1)
1. **Stored** XSS differs from **reflected** XSS because the payload is:
   a) encrypted  b) saved on the server and served to later victims  c) only in the URL  d) run on the server
   >- **ans** :  b) saved on the server and served to later victims

2. XSS code executes in:
   a) the database  b) the web server  c) the victim's browser  d) the proxy
   >- **ans** : c) the victim's browser

3. The primary defense against XSS is:
   a) input length limits  b) context-aware output encoding (+ CSP)  c) HTTPS  d) renaming parameters
   >- **ans** : b) context-aware output encoding (+ CSP)

4. The CWE id for XSS is:
   a) CWE-89  b) CWE-79  c) CWE-352  d) CWE-611
   >- **ans** : b) CWE-79

5. The `HttpOnly` cookie flag helps because it:
   a) encrypts the cookie  b) stops JavaScript from reading the cookie  c) blocks all cookies  d) sets SameSite
   >- **ans** : b) stops JavaScript from reading the cookie

## Short answer — 🔒 your own work (1 × 3)
6. Paste the XSS payload that **scored in this week's XSS Golf** and name the **sink** it reached (e.g., `innerHTML`, attribute, URL). Then paste your personal flag (`FLAG{...}`) captured from the challenge.
>- **ans** :  FLAG