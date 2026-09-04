# Worksheet 1 — Security Mindset & Threat Modeling (3 hrs)

> **Course:** Software Security (KOSEN69) · **Week 1**
> **Aligned to:** OWASP 2025 A06 Insecure Design · CWE-501 (Trust Boundary Violation)
> **Signature game:** "Elevation of Privilege" (Microsoft STRIDE card deck)

> **Ethics note:** This week is *modeling only* — you analyze design, you do **not** attack the app. Run the sample app only on your own VM/localhost. Never apply these techniques to systems you do not own or lack written permission to test.

## Part 1 — Student Information
| Name | Student ID | Date | Group |
|---|---:|:--:|---|
| Supichaya Rabiabnaweenurak | 6631503118 | 16/8/2569 | --- |
|  |  |  |  |

*AI-use disclosure: I used an AI assistant for the "Audit the AI" and "Prompt Problem" tasks (prompts and outputs shown in those sections). All threat-model analysis, the STRIDE table, and the Task 8 fix were written and verified by me by running the app.*

## Part 2 — Lecture Questions
Answer in your own words (2–4 sentences each).
1. Define the CIA triad and give one concrete failure example for each of the three properties.
>- C - confidential : is for specific permission can access. 
failure : Data leak out from unsecure api end point.
>- I - Integrity : is when somehing cannot be change without notice. 
failure : someone overwrite the current data.
>- A - Availability : is when the system is up. 
failure : System down noone can access it.

2. What is a *trust boundary*, and why does data crossing one deserve extra scrutiny?
>- Trust boundary is when data has to be exchange between each different component.
>- And it needs extra scrutiny because there might be some loop hole that attacker can access to attack the system.

3. Explain "attack surface." Name two things that increase it in a web app.
>- Attack surface is input hole that attacker can reach.
>- Ex. Accepting unrestricted file , Exposing unauthenticated API endpoints.

4. What does each STRIDE letter map to, and which security property does each threat violate?
>- S : Spoofing - authentication
>- T : Tampering - Integrity
>- R : Repudiation - non-repudiation
>- I : Information Disclosure - confidentiality
>- D : Denial of service - availibility
>- E : Elevation of privilege - authorization

5. What does "Secure by Design" (CISA) mean, and how does it differ from bolting security on after release?
>- Secure by design : the system is secure from the begining of the design phase, the system design follow the security metrix along side the requirements
>- bolting security is kind of patching the security hole after the release of the product , so the design from the begining mignt not be secure

## Part 3 — Hands-on Lab (180 min)
**Learning goals:** build a data-flow diagram (DFD), apply STRIDE to a real Flask app, rank risks, and propose mitigations.
**Prerequisites:** Docker + Docker Compose in your VM; a drawing tool (draw.io / paper + photo); the Elevation of Privilege deck (print or virtual) — free print-and-play PDF at [github.com/adamshostack/eop](https://github.com/adamshostack/eop).

**Environment setup**
```bash
cd labs/week01-threat-modeling
docker compose up --build           # starts sample-app on http://localhost:8080
curl -s -X POST localhost:8080/notes -H 'Content-Type: application/json' \
     -d '{"owner":"alice","body":"hello"}'   # observe behavior, do not attack
curl -s localhost:8080/notes

echo "demo file" > demo.txt
curl -s -X POST localhost:8080/upload -F "file=@demo.txt"   # observe behavior, do not attack
curl -s localhost:8080/files/demo.txt
```

Source to model lives in `sample-app/app.py`. Template to fill: `THREAT-MODEL-TEMPLATE.md` (copy it, do not edit the original).

**What to submit per task:** the threat/element identified + a screenshot (DFD, table, or running app) + a 2–3 sentence mitigation.

**Task 0 — Onboarding (5 min)** · *Goal:* prove the environment works. *Steps:* `docker compose up`, hit `/notes` and `/files/<name>`, read `sample-app/app.py`. *Deliverable:* screenshot of the running app + the JSON response.

> **My result.** App is up on `localhost:8080`. `POST /notes {"owner":"alice","body":"hello"}` then `GET /notes` returned:
> ```json
> [[1,"alice","hello"]]
> ```

**Task 1 — Draw the DFD (25 min)** · *Goal:* map the system. *Steps:* identify the external entity (web client), the process (Flask app), the data store (`notes.db` SQLite), the `uploads/` store, and the flows for `/notes`, `/upload`, `/files/<name>`; mark the Internet→app trust boundary with a dashed line. *Deliverable:* DFD image embedded in your copy of the template.

> **My DFD** (drawn in draw.io, embedded as `img-dfd.png` in my copy of `THREAT-MODEL-TEMPLATE.md`). Text version:
> ```
>   [Web client]  --- ( Internet -> app boundary, dashed ) --->  ( Flask app )
>        ^                                                         |   |   |
>        |  JSON / file bytes                            /notes    |   |   | /upload, /files
>        +---------------------------------------------------------+   |   |
>                                                     writes/reads |   |   | save/read bytes
>                                                                  v   |   v
>                                                        [notes.db SQLite]  [uploads/ store]
> ```
> - External entity: **Web client** (untrusted).
> - Process: **Flask app** (container port 5000 -> host 8080).
> - Data stores: **notes.db** (SQLite) and **uploads/** (filesystem).
> - Flows: `/notes` (GET/POST JSON) to/from notes.db; `/upload` (POST multipart) into uploads/; `/files/<name>` (GET) out of uploads/.
> - The only trust boundary is **Internet -> app**. There is *no* boundary check between the app and either data store — the app trusts client input all the way to disk.

**Task 2 — STRIDE the elements (30 min)** · *Goal:* enumerate threats per element. *Steps:* for each element fill the S/T/R/I/D/E grid. Ground it in real code: `/notes` accepts a client-supplied `owner` with no auth (Spoofing); `/upload` saves raw `f.filename` — arbitrary-file-write (Tampering) — and echoes the resolved save path back in its response (Information disclosure); `/files/<name>` reads it back but is comparatively defended (see Task 5); no logging anywhere (Repudiation). *Deliverable:* completed STRIDE table.

> **My STRIDE table** (grounded in `sample-app/app.py`):
>
> | Element | S (Spoof) | T (Tamper) | R (Repudiate) | I (Info disclosure) | D (DoS) | E (Elevation) |
> |---|---|---|---|---|---|---|
> | **/notes** | client picks any `owner` string, no auth — I posted `owner:"admin"` and it was accepted | no server-side validation on `body`; stored raw | no logging at all — no way to know who posted | `GET /notes` returns *everyone's* notes to anyone, no access control | unbounded rows, no size/rate limit — flood the DB | become "admin" just by typing it (owner is not identity) |
> | **/upload** | no auth on who uploads | **saves raw `f.filename`** — `../` escapes `uploads/`; I wrote `../app.py` (arbitrary file write) | no logging of uploads | response echoes the saved path back to the client | no size/type/rate limit — fill the disk | write into app dir -> overwrite `app.py` -> code execution on next start |
> | **/files/<name>** | no auth to read files | read-only | no access log | serves any file *inside* uploads/ to anyone | large/many reads | comparatively defended: `send_from_directory` blocked my `../` reads (404) |
>
> Verified: the `/notes` spoof and the `/upload` traversal both worked; the `/files` traversal returned **404** (defended on the read side, not the write side).

**Task 3 — Elevation of Privilege game (20 min)** · *Goal:* find threats you missed. *Steps:* play the EoP deck against your DFD; each card you can tie to a real element/flow scores a point; record every valid threat. No printer or scissors? Draw from the digital deck below instead — same 78 cards, same rule. *Deliverable:* list of carded threats + score.

> **My carded threats (7 points):**
> 1. *Spoofing* — "An attacker could pretend to be another user" -> `/notes` `owner` field, I posted as `admin`.
> 2. *Tampering* — "An attacker can write to a data store your code relies on" -> `/upload` `../` writes into the app dir.
> 3. *Repudiation* — "An attacker can claim they didn't do something, and there's no way to prove otherwise" -> no logging anywhere.
> 4. *Info Disclosure* — "A data store leaks information to unauthorized parties" -> `GET /notes` returns all owners' notes.
> 5. *Info Disclosure* — "Your system gives an attacker useful details" -> `/upload` echoes the resolved save path.
> 6. *Denial of Service* — "An attacker can consume so much of a resource the app fails" -> no upload size/rate limit fills the disk.
> 7. *Elevation of Privilege* — "An attacker can force data through a path that gives more privilege" -> overwrite `app.py` via `/upload` -> code runs on restart.
>
> Cards I could **not** tie to a real element (no point): the deck's crypto/session-token and "confused deputy across services" cards — this app has no auth tokens, sessions, or second service to abuse.

```sim
eop-deck
```

**Task 3b — Systems-level pass (25 min) 🔭** · *Goal:* find what the per-element grid cannot see. Tasks 2 and 3 enumerate threats **one element at a time**, and that is exactly where threat models are known to stop short — students taught STRIDE alone reliably identify component threats and *discount system-level ones* ([Joshi et al., ASEE 2024](https://arxiv.org/abs/2404.16632)). So do a second pass over the **whole** diagram:
![Three trust zones — public internet, application tier, data tier — with the two boundaries a request crosses between them](img/trust-boundaries.svg)

- **Trust boundaries end-to-end.** Follow one request from the client to `notes.db` and back. List every boundary it crosses. Which crossing has no check on it?
- **Assume one element is fully owned.** Pick the Flask process, then the `uploads/` store. For each: what does the attacker now *reach* — not what is it, but where does it get them?
- **Chain two "low" findings.** Find two threats you or the EoP deck rated minor that combine into something you would not accept. Write the chain as `A → B → consequence`.
- **One-line system claim.** Finish: "Even if every element-level mitigation in Task 8 is implemented, this system still fails if ___."

Use the simulation below before you start — toggle a component to attacker-controlled and watch what it reaches:

```sim
trust-boundary
```

*Deliverable:* the boundary list, two owned-element reachability notes, one written chain, and the system claim.

> **Boundaries a `/notes` request crosses, client -> notes.db and back:**
> 1. Internet -> Flask process (the one dashed boundary) — checked? **No auth, no validation.**
> 2. Flask process -> SQLite file (app -> data tier) — **no check**; the app is fully trusted by the DB.
> 3. SQLite -> Flask -> back to client — **no check**; whatever is stored is returned to anyone.
> The crossing with *no check* is really all of them, but the dangerous one is **Internet -> app**: nothing authenticates or constrains the caller, so client-controlled data reaches the store and the disk unfiltered.
>
> **Owned-element reachability:**
> - *If the Flask process is owned:* the attacker reaches **both data stores directly** — read/rewrite every note in `notes.db`, and read/write the entire `uploads/` dir and (via the traversal bug) the app's working dir. There is no privilege separation, so owning the process = owning the data tier.
> - *If the `uploads/` store is owned* (attacker can write arbitrary paths into it, which they can): because `uploads/` sits *inside* the app working dir and `f.save` follows `../`, writing to the store lets the attacker **replace `app.py`** — i.e. the "store" reaches the *process*. A data store that can rewrite the code that serves it is the whole exploit.
>
> **Chain (two "low" findings -> not-acceptable):**
> `no upload auth (low: "it's just a notes toy") -> raw f.filename traversal (rated medium) -> write ../app.py -> on next container restart the app runs attacker code (RCE).` A missing-auth annoyance plus a file-naming bug compose into remote code execution.
>
> **One-line system claim:** *Even if every element-level mitigation in Task 8 is implemented, this system still fails if the app process and its writable stores share one trust zone with no identity on the caller — i.e. as long as "who is asking" is never established, per-endpoint patches only move the attacker to the next unauthenticated door.*

**Task 4 — Abuse cases & attacker personas (20 min)** · *Goal:* think like specific adversaries. *Steps:* define 2 personas (e.g. a curious logged-in user; an anonymous internet attacker) and write 2 abuse cases each against the sample app, tied to DFD elements. *Deliverable:* 4 abuse cases.

> **Persona A — Curious logged-in-ish user ("Mallory", knows the API, no bad tooling):**
> - *AC-A1:* Mallory POSTs `/notes` with `owner:"teacher"` so her note looks like it came from the teacher (Spoofing on `/notes`, no identity check).
> - *AC-A2:* Mallory GETs `/notes` and reads every other student's note bodies, because the endpoint returns all rows with no filter (Info disclosure on notes.db flow).
>
> **Persona B — Anonymous internet attacker ("Trudy", scripted, wants control):**
> - *AC-B1:* Trudy POSTs `/upload` with `filename=../app.py` to overwrite the running app, then triggers a restart for code execution (Tampering/EoP on `/upload`).
> - *AC-B2:* Trudy loops `/upload` with large files and no rate limit until the container disk fills and the app stops serving (DoS on uploads/).

**Task 5 — Path-traversal deep-dive (25 min)** · *Goal:* analyze the riskiest flow. *Steps:* trace `/upload` → `/files/<name>`; explain how `../` in a filename escapes `uploads/`; sketch the secure design (`secure_filename`, store outside web root, allow-list extensions). *Deliverable:* the data flow + secure-design note.

> **Data flow:** `POST /upload` -> `f = request.files["file"]` -> `f.save(os.path.join("uploads", f.filename))`. `os.path.join("uploads", "../app.py")` resolves to `app.py` in the working dir, so the file lands **outside** `uploads/`. Later `GET /files/<name>` reads back via `send_from_directory`, which *does* reject `../` (returns 404), so the escape is on the **write** side only.
>
> **Why `../` escapes:** `os.path.join` treats a leading `..` as "go up one level" — it doesn't confine the result to `uploads/`. I verified this: `POST /upload` with `filename=../app.py` returned `{"saved":"../app.py"}` and actually overwrote the app source (`app.py` became 10 bytes). `send_from_directory` on the read side blocked the same trick (404) because it validates the resolved path stays inside the base dir.
>
> **Secure design:**
> - `name = secure_filename(f.filename)` — strips directory components (`secure_filename("../app.py") == "app.py"`, verified).
> - Reject empty names and **allow-list extensions** (`{txt,png,jpg,pdf}`).
> - Store uploads **outside the web/app root** (a dedicated volume), so even a bug can't reach code.
> - Optionally re-name to a server-generated ID so the client string never becomes a path component at all (that's the *class* fix).

**Task 6 — Threat-model the project target (30 min)** · *Goal:* kick off your term project. *Steps:* stop the sample-app first (`docker compose down` — both apps bind host port 8080), then run **NoteVault** (`cd ../../project/starter-app && docker compose up`), draw a quick DFD, and list the top 3 STRIDE threats you'd investigate. *Deliverable:* NoteVault DFD + top-3 threats (reuse these in your project report — `project/REPORT-TEMPLATE.md` in the repo root).

> Stopped sample-app (`docker compose down`) first — both bind host 8080.
>
> **NoteVault DFD (text):**
> ```
>  [Browser/API client] --(Internet -> app, dashed)--> ( NoteVault Flask )
>        |  cookie "session" (JWT)                        |  |  |  |
>        |                                       /login   |  |  |  | subprocess (/export)
>        +------------------------------------------------+  |  |  +--> [OS shell]
>                                          users/notes tables |  |
>                                                             v  v
>                                                      [ /tmp/notevault.db SQLite ]
> ```
> Elements: client (entity), Flask process, SQLite store, and an extra **OS-shell** sink via `/export`. Boundary of note: the JWT cookie is the *only* thing standing in for identity.
>
> **Top-3 STRIDE threats I'd investigate (as a threat model, not attacking yet):**
> 1. **Spoofing / EoP — JWT accepts `"none"`.** `jwt.decode(tok, SECRET, algorithms=["HS256","none"])` trusts an unsigned token, so a forged `{"sub":"admin"}` with alg:none could authenticate as anyone. (Spoofing on the session flow -> EoP to admin.)
> 2. **Tampering — SQL injection in `/login` and `/search`.** Both build SQL by `%`-string formatting of client input (`username`, `q`). Classic auth-bypass / data-exfil surface. (Tampering + Info disclosure on the DB store.)
> 3. **EoP — mass-assignment on `/register`.** `role = request.form.get("role") ... or "user"` — the client can send `role=admin` and self-register an admin. (Elevation of Privilege at the entity->process boundary.)
> *(Others noted for the report: IDOR on `/api/notes/<nid>` — no owner check; command injection in `/export` `subprocess(..., shell=True)`; MD5 passwords; `render_template_string(..., |safe)` XSS; `debug=True`.)*

**Task 7 — Security requirements (15 min)** · *Goal:* turn threats into testable requirements. *Steps:* write 3 security requirements as acceptance criteria ("the system must … so that …"), each mapped to a threat from Task 2 or Task 6. *Deliverable:* 3 testable security requirements.

> 1. **(maps to Task 2 `/upload` Tampering):** The system **must** reject any uploaded filename that resolves outside the designated uploads directory (return HTTP 400) **so that** no client-supplied string can be written as a path outside `uploads/`. *Test:* `POST /upload filename=../app.py` -> 400 and no file appears outside `uploads/`.
> 2. **(maps to Task 2 `/notes` Spoofing):** The system **must** derive the note `owner` from an authenticated session, not from the request body, **so that** a user cannot post as another identity. *Test:* posting `owner:"admin"` while logged in as alice stores the note as `alice`.
> 3. **(maps to Task 6 NoteVault `/register` EoP):** The registration endpoint **must** ignore any client-supplied `role` and default new accounts to `user` **so that** privilege cannot be self-assigned. *Test:* `POST /register role=admin` -> the created account has role `user`.

**Task 8 — Defend / fix it: rank & mitigate (25 min) 🛡️** · *Goal:* turn threats into action you can prove. *Steps:* rank the top 5 threats by likelihood × impact; propose one concrete mitigation each (e.g., auth on `/notes`, `secure_filename()` + allowlist for `/upload`, request logging for Repudiation, size/rate limits for DoS). Then **pick one and actually implement it** in your fork.

*Deliverable — the top-5 table, plus for the one you implemented:*
1. the **diff** (commit hash on your `wk01` branch),
2. **evidence it works**: the request that succeeded before your change and is refused after — both outputs,
3. **why it closes the class, not the instance** (2–3 sentences). `secure_filename()` on one endpoint is an instance fix; *"no user-supplied string ever becomes a path component"* is a class fix. Say which yours is, and if it's an instance fix, say what the class fix would be.

> **My top-5 ranking (likelihood × impact):**
> | # | Threat | Likelihood | Impact | Score |
> |---|---|---|---|---|
> | 1 | `/upload` `../` arbitrary file write -> overwrite `app.py` (RCE) | High | Critical | **Top** |
> | 2 | `/notes` no auth + client-set `owner` (spoofing) | High | High | High |
> | 3 | `GET /notes` leaks all users' notes (info disclosure) | High | Medium | High |
> | 4 | No logging anywhere (repudiation) | Medium | Medium | Med |
> | 5 | No upload size/rate limit (DoS / disk fill) | Medium | Medium | Med |
>
> Mitigations: (1) `secure_filename()` + extension allow-list + store outside app root; (2) require an authenticated session and set `owner` server-side; (3) filter `GET /notes` to the caller's own rows; (4) add request/audit logging; (5) enforce `MAX_CONTENT_LENGTH` + rate limit.
>
> **I implemented #1.** Branch `wk01`, commit (local) `wk01: secure_filename + extension allow-list on /upload`.
>
> 1. **The diff:**
> ```diff
> --- a/labs/week01-threat-modeling/sample-app/app.py
> +++ b/labs/week01-threat-modeling/sample-app/app.py
> -from flask import Flask, request, jsonify, send_from_directory
> +from flask import Flask, request, jsonify, send_from_directory, abort
> +from werkzeug.utils import secure_filename
>  ...
> +ALLOWED = {"txt", "png", "jpg", "pdf"}
>  @app.route("/upload", methods=["POST"])
>  def upload():
>      f = request.files["file"]
> -    f.save(os.path.join(UPLOAD_DIR, f.filename))
> -    return {"saved": f.filename}
> +    name = secure_filename(f.filename)
> +    if not name or "." not in name or name.rsplit(".", 1)[1].lower() not in ALLOWED:
> +        abort(400, "bad filename")
> +    f.save(os.path.join(UPLOAD_DIR, name))
> +    return {"saved": name}
> ```
>
> 2. **Evidence it works** (same payload, before vs after — I ran both):
> ```
> BEFORE:  POST /upload  filename=../app.py   ->  {"saved":"../app.py"}   # app.py overwritten (10 bytes), file escaped uploads/
> AFTER :  POST /upload  filename=../app.py   ->  HTTP 400 "bad filename" # nothing written outside uploads/
> AFTER :  POST /upload  filename=demo.txt    ->  {"saved":"demo.txt"}    # normal upload still works
> AFTER :  POST /upload  filename=evil.sh     ->  HTTP 400 "bad filename" # extension not allow-listed
> ```
> Verified `secure_filename("../app.py") == "app.py"` and that after the fix the count of `app.py` files outside `uploads/` stayed 0.
>
> 3. **Class vs instance:** This is a partial **instance** fix — it closes traversal *on this one endpoint*. `secure_filename` + allow-list stops `../`, but the true **class** fix is *"no user-supplied string ever becomes a path component"*: generate the stored name server-side (e.g. a UUID), keep the client's name only as metadata, and put `uploads/` on a volume **outside** the app root. That way even a future endpoint that forgets `secure_filename` cannot write outside the store or over code.

> **Why this is weighted.** Fewer than half of working developers can spot a security hole in code, and being shown vulnerabilities does not by itself teach you to find or close them. Exploiting is the half that feels like progress; defending is the half that transfers to your job.

## Part 4 — Reflection
1. Map your top finding to a CWE and to OWASP A06 (Insecure Design); explain the mapping in one sentence.
>- My top finding (`/upload` `../` write) is **CWE-22 Path Traversal** (and its consequence, CWE-434 unrestricted file upload). It maps to **OWASP A06 Insecure Design** because the flaw is a *design* choice — trusting the client's filename as a path with no confinement — not a missing patch, so a control had to be designed in, not bolted on.

2. Name one real-world breach caused by a design flaw (not a missing patch) and what design control would have prevented it.
>- The **2017 Equifax-style / IDOR class** aside, a cleaner design-flaw example is the **2019 Capital One breach**: an over-permissive design let a SSRF reach cloud metadata and assume an over-privileged role. The design control that prevents it is **least privilege + segmentation** (the instance would have had no rights to read the S3 buckets) — a boundary decision, not a patch.

3. Of your five mitigations, which gives the most risk reduction per unit of effort, and why?
>- `secure_filename()` + extension allow-list on `/upload`. It's about three lines and it removes the single Critical-impact path (arbitrary file write -> RCE). Auth on `/notes` matters more architecturally but is more work; the upload fix is the best risk-reduction-per-effort because it kills the worst outcome for almost no code.

## Grading rubric (100)
| Criterion | Points |
|---|---|
| Lecture questions (Part 2) | 20 |
| Exploitation + evidence (DFD + STRIDE table + EoP findings + screenshots) | 40 |
| Defense (top-5 ranking + mitigations) | 25 |
| Reflection (CWE/OWASP mapping + breach + best mitigation) | 15 |

**Assessed within the rows above** (they are not extra points — they are what those points are for):
- **Systems-level reasoning** (inside *Exploitation + evidence*, Task 3b): does the model reach past single elements to boundaries, reachability and chains? Scored with the STRIDE + systems-thinking rubrics of [Joshi et al. 2024](https://arxiv.org/abs/2404.16632).
- **Defensive proof** (inside *Defense*, Task 8): a claimed mitigation with no before/after evidence scores at most half. A mitigation you can show closing a *class* scores full.
- **Adversarial thinking** (across the whole sheet): do the abuse cases, personas and chains show you reasoning as an attacker with goals and constraints — or just listing categories? This is the course's central disposition and it is assessed, not assumed.

---

## Evidence & Integrity (required)

- **Identity proof:** every screenshot/diagram must show a terminal running `printf '%s | %s | ' "$(whoami)" '6631503118'; date '+%F %T %Z'` **in the
  same image as the evidence**. When the evidence is a browser page, a DevTools panel or a
  rendered response, put that terminal **beside the browser and capture the whole screen** — a
  cropped window carries nothing that identifies you, and the lab's own output is
  byte-identical for the whole cohort *by design*, so the stamp is the only thing that makes
  the shot yours. Generic or borrowed evidence is not accepted.
- **Personalized flag (if this lab issues one):** _n/a — Week 1 is modeling-only, no flag issued_
  *Flags are unique per student — submitting another student's flag is a violation. How to submit: **learn.zcr.ai/submit** (full guide: `SUBMISSION.md` in the repo root).*
- **Explain in your own words** *(graded on your reasoning, not copied text):*
  1. What did you do, and **why did the vulnerability work**?
  >- I sent an upload whose filename was `../app.py`. It worked because the code does `os.path.join("uploads", f.filename)` and saves it directly — `os.path.join` treats the leading `..` as "go up a directory", so the file was written *outside* `uploads/` (it overwrote the app's own source). The app trusted a client string as a filesystem path with no confinement.
  2. **Why does your fix actually stop it** — and what could still break it?
  >- `secure_filename()` strips the directory parts (`../app.py` -> `app.py`) and the allow-list rejects anything that isn't a permitted extension, so the client can no longer steer the path or the type. What could still break it: if another endpoint is added later that forgets `secure_filename`, or if `uploads/` stays inside the app root — the real fix is to never let a user string be a path component and to store uploads outside the code dir.

---

## 🤖 Audit the AI (required)

AI is a power tool you must **distrust** — you are graded on your *critique*, not the AI's answer.

1. Ask an AI assistant to exploit **or** fix this week's vulnerability. Paste its full answer.
> **My prompt:** "Fix the path traversal in this Flask /upload handler." **AI answered (pasted):**
> ```python
> @app.route("/upload", methods=["POST"])
> def upload():
>     f = request.files["file"]
>     filename = f.filename
>     if ".." in filename or filename.startswith("/"):
>         return {"error": "invalid filename"}, 400
>     f.save(os.path.join(UPLOAD_DIR, filename))
>     return {"saved": filename}
> ```
> "This blocks directory traversal by rejecting any filename containing `..` or starting with `/`."
>
2. **Find what's wrong or risky** in it — insecure code, a subtly incomplete fix, a hallucinated API/function/CVE, a missed edge case, or wrong reasoning. Quote the exact line(s).
> The blacklist is incomplete. The line `if ".." in filename or filename.startswith("/")` is a **denylist**, and denylists for paths leak:
> - A **Windows absolute path** like `C:\Windows\evil.txt` bypasses both checks — it has no `..` and doesn't start with `/`, yet `f.save` will happily write to it.
> - It also doesn't handle **empty filename**, no-extension files, or URL/percent-encoded names that some layers decode later.
> - It rejects legitimately-named files that merely contain `..` (e.g. `my..notes.txt`), so it's both unsafe *and* over-broad.
>
3. Produce the **correct, verified** version yourself and explain in 2–3 sentences why the AI's output was insufficient.
> **Correct version** (what I actually shipped in Task 8): use the **allow-list** built into `werkzeug`:
> ```python
> from werkzeug.utils import secure_filename
> name = secure_filename(f.filename)
> if not name or "." not in name or name.rsplit(".",1)[1].lower() not in ALLOWED:
>     abort(400, "bad filename")
> f.save(os.path.join(UPLOAD_DIR, name))
> ```
> The AI's fix was insufficient because it *enumerates bad input* instead of *constructing safe output* — every denylist eventually misses an encoding or platform case. `secure_filename` strips directory components outright (verified: `secure_filename("../app.py") == "app.py"`), which is why the same `../app.py` payload that overwrote the source now returns 400.

> Disclose your AI use in the Part 1 table. This task counts toward your **Defense + Reflection** score.

---

## 🧠 Comprehension & Prompt (required)

**A. Explain in Plain English (EiPE).** In 2–3 sentences, in your own words, describe what this week's vulnerable code/endpoint actually *does* and *why it is exploitable* — explain the mechanism, don't dump jargon.
> The `/upload` endpoint takes whatever file you send and saves it under the name *you* chose, by literally joining "uploads/" with your filename. Because it never checks that the result stays inside the uploads folder, a name like `../app.py` climbs one directory up and lands next to the program's own code — so you can plant or replace files anywhere the app can write. It's exploitable because the app treats an attacker-controlled string as a trusted filesystem path.

**B. Prompt Problem.** Write a **single prompt** that makes an AI produce a *correct, secure* fix for one finding. Run it: does the exploit now fail? If not, refine the prompt and try again. Submit the **final prompt + the verified result**.
> **Final prompt:**
> > "Here is a Flask `/upload` handler that saves `request.files['file']` using the client-supplied filename via `os.path.join(UPLOAD_DIR, f.filename)`. It has a path-traversal bug: a filename like `../app.py` escapes UPLOAD_DIR. Rewrite it so that **no client-supplied string is ever used as a path component** — sanitize with `werkzeug.utils.secure_filename`, reject empty names, and enforce an allow-list of extensions {txt,png,jpg,pdf}, returning HTTP 400 otherwise. Do not use a denylist of bad characters. Keep saving into UPLOAD_DIR only."
>
> **Verified result:** the AI produced the `secure_filename` + allow-list version. I re-ran the exploit: `POST /upload filename=../app.py` now returns **HTTP 400** and nothing is written outside `uploads/`, while `demo.txt` still uploads normally. Exploit fails. ✅
*Graded on the prompt's precision and your verification — this trains problem decomposition and AI literacy (Denny et al. 2024).*
