# Weekly Quiz — Week 2 (Secure SDLC, Tooling & Fuzzing)

**~10 min · 6 questions · low-stakes** (lowest scores dropped). Individual.

**Name:** Supichaya Rabiabnaweenurak  **Student ID:** 6631503118

## MCQ (5 × 1)
1. **SAST** analyzes:
   a) the running app  b) source code without running it  c) dependencies only  d) network traffic
   >- **ans** : b) source code without running it

2. The tool type that finds **hardcoded secrets** in code/history is:
   a) DAST  b) fuzzing  c) secret scanning  d) SCA
   >- **ans** : c) secret scanning

3. Coverage-guided **fuzzing** finds bugs by:
   a) reading comments  b) mutating inputs and watching for new paths/crashes  c) signing artifacts  d) scanning licenses
   >- **ans** : b) mutating inputs and watching for new paths/crashes

4. A **false positive** is:
   a) a real bug missed  b) a flagged finding that is not actually a bug  c) a crash  d) a CVE
   >- **ans** : b) a flagged finding that is not actually a bug

5. **SCA** checks:
   a) your source style  b) dependencies for known CVEs  c) the running UI  d) secrets
   >- **ans** : b) dependencies for known CVEs

## Short answer (1 × 3)
6. Name **one** bug SAST would catch that DAST would not — and one DAST would catch that SAST would not.
   >- SAST catch hardcoded credentials or unsafe SQL string concatenation leading to injection
   >- DAST would catch runtime issues only visible when the app runs
