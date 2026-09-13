# Weekly Quiz — Week 6 (Authentication & Access Control)

**~10 min · in-class · 6 questions · low-stakes** (drop lowest). No devices / locked browser.

**Name:** Supichaya Rabiabnaweenurak  **Student ID:** 6631503118

## MCQ (5 × 1)
1. **IDOR** (broken object-level authorization) is:
   a) a weak password  b) reaching another user's object by changing an id  c) an expired session  d) a missing cookie
   >- **ans** : b) reaching another user's object by changing an id

2. The JWT `alg: none` attack works when the server:
   a) uses HTTPS  b) accepts an unsigned token as valid  c) rotates keys  d) rejects expired tokens
   >- **ans** : b) accepts an unsigned token as valid

3. Access-control checks must be enforced:
   a) only in the UI  b) server-side, on every request  c) once at login  d) by the client
   >- **ans** : b) server-side, on every request

4. The OWASP 2025 category covering IDOR is:
   a) A01 Broken Access Control  b) A03 Injection  c) A07 Auth Failures  d) A02 Crypto Failures
   >- **ans** : a) A01 Broken Access Control

5. A password-reset token should be:
   a) the user's email  b) sequential  c) random, single-use, and expiring  d) the username reversed
   >- **ans** : c) random, single-use, and expiring


## Short answer — 🔒 your own work (1 × 3)
6. From the **IDOR Treasure Hunt**, which **object id** let you reach another user's data, and what **server-side check** would stop it? Then paste your **personal flag** (`FLAG{...}`) captured from the challenge.
>- **ans** :  FLAG