# Week 3 — Screenshot Guide for Windows `cmd.exe`

Every command below was run and verified on this machine in Command Prompt.

> **Why the worksheet command doesn't work as-is:** the worksheet's identity line
> `printf '%s | %s | ' "$(whoami)" '6631503118'; date '+%F %T %Z'` is **bash** syntax.
> `printf`, `$(...)` and `date '+%F'` do **not** exist in `cmd.exe`. Use the cmd
> equivalent below — it produces the same `whoami | studentID | timestamp` stamp.

---

## 0. One-time setup

Open **Command Prompt** (press `Win`, type `cmd`, Enter), then:

```cmd
cd /d "D:\Uni work2\software-security-mfu-course\labs\week03-cryptography"
pip install pycryptodome argon2-cffi
```

Verify tools (optional):
```cmd
python --version
where hashcat
```

---

## 1. The identity stamp (cmd version)

This is the line that must appear **in the same window** as every piece of evidence:

```cmd
echo %USERNAME% ^| 6631503118 ^| %DATE% %TIME%
```

- The `^|` escapes the pipe character so cmd prints a literal `|`.
- Output looks like: `User | 6631503118 | Fri 09/04/2026 16:37:43.76`

The rule: **run the stamp, then immediately run the task command, then screenshot** — so
the stamp and the task output are visible together in one image.

---

## 2. How to take the screenshot

1. Make the cmd window tall enough that the stamp **and** the output both fit on screen.
2. Press **`Win` + `Shift` + `S`** → drag a box around the whole cmd window (stamp + output).
   *(Or `Alt` + `PrtScn` to grab the active window.)*
3. Paste (`Ctrl`+`V`) into the worksheet, or save it as a PNG and reference it.

> Tip: for commands with long output (hashcat), use the short `--show` form below so the
> stamp never scrolls off the top.

---

## 3. Per-task commands

For each task: paste the **stamp line first**, then the task command(s), then screenshot.

### Task 0 — see the misuse output
```cmd
echo %USERNAME% ^| 6631503118 ^| %DATE% %TIME%
python vulnerable_crypto.py
```

### Task 1 — crack the MD5 hashes (hashcat)
`hashes_clean.txt` (comments already stripped) sits in the lab folder. hashcat must run
from its own install dir. Do the crack once, then screenshot the short `--show` output:

```cmd
cd /d C:\hashcat
hashcat.exe -m 0 -a 0 "D:\Uni work2\software-security-mfu-course\labs\week03-cryptography\hashes_clean.txt" "D:\Uni work2\software-security-mfu-course\labs\week03-cryptography\rockyou.txt" --backend-ignore-cuda
```
Then, for the screenshot (stamp + results on one screen):
```cmd
echo %USERNAME% ^| 6631503118 ^| %DATE% %TIME%
hashcat.exe -m 0 "D:\Uni work2\software-security-mfu-course\labs\week03-cryptography\hashes_clean.txt" --show
```
*(`--backend-ignore-cuda` avoids this laptop's CUDA/driver mismatch and uses the OpenCL
backend; drop it if your GPU works. If hashcat says "All hashes found in potfile", the
`--show` step is all you need.)*

### Task 2 — ECB block repeat
```cmd
echo %USERNAME% ^| 6631503118 ^| %DATE% %TIME%
python -c "from vulnerable_crypto import encrypt_ecb; h=encrypt_ecb(b'A'*16+b'A'*16).hex(); print('block1', h[0:32]); print('block2', h[32:64]); print('identical', h[0:32]==h[32:64])"
```

### Task 3 — predictable token
```cmd
echo %USERNAME% ^| 6631503118 ^| %DATE% %TIME%
python -c "from vulnerable_crypto import reset_token; print([reset_token() for _ in range(8)])"
```

### Task 4 — hardcoded key (findstr = cmd's grep)
```cmd
echo %USERNAME% ^| 6631503118 ^| %DATE% %TIME%
findstr /n "HARDCODED_KEY" vulnerable_crypto.py
```

### Task 5 — crack NoteVault's seeded hashes
Generate the two MD5 digests from the project's `seed()`, then crack them:
```cmd
echo %USERNAME% ^| 6631503118 ^| %DATE% %TIME%
python -c "import hashlib; [print(hashlib.md5(p.encode()).hexdigest()) for p in ('alicepw','admin123')]" > notevault_hashes.txt
type notevault_hashes.txt
cd /d C:\hashcat
hashcat.exe -m 0 -a 0 "D:\Uni work2\software-security-mfu-course\labs\week03-cryptography\notevault_hashes.txt" "D:\Uni work2\software-security-mfu-course\labs\week03-cryptography\rockyou.txt" --backend-ignore-cuda
hashcat.exe -m 0 -a 6 "D:\Uni work2\software-security-mfu-course\labs\week03-cryptography\notevault_hashes.txt" "D:\Uni work2\software-security-mfu-course\labs\week03-cryptography\rockyou.txt" pw --backend-ignore-cuda
hashcat.exe -m 0 "D:\Uni work2\software-security-mfu-course\labs\week03-cryptography\notevault_hashes.txt" --show
```
*(admin123 falls straight from rockyou; alicepw needs the hybrid `-a 6 ... pw` run — it
appends the literal `pw` to each wordlist word.)*

### Task 6 — argon2id migration + rehash-on-login
Uses `task6_migration.py` (the code is in the worksheet). If you don't have the file, copy
the Task 6 code block from the worksheet into `task6_migration.py` first, then:
```cmd
echo %USERNAME% ^| 6631503118 ^| %DATE% %TIME%
python task6_migration.py
```

### Task 7 — AES-GCM round-trip + tamper
Set the key in the env first. **At the cmd prompt use a single `%i`** (in a `.bat` file it
must be `%%i`):
```cmd
for /f %i in ('python -c "import os;print(os.urandom(32).hex())"') do set ENC_KEY_HEX=%i
echo %USERNAME% ^| 6631503118 ^| %DATE% %TIME%
python task7_gcm.py
```
*(Copy the Task 7 code block from the worksheet into `task7_gcm.py` if you don't have it.)*

### Task 8 — read a real TLS cert (openssl)
`openssl` isn't on the cmd PATH — it ships with Git. `cmd` has no `tee`, so save to a file:
```cmd
set OSSL="C:\Program Files\Git\mingw64\bin\openssl.exe"
echo %USERNAME% ^| 6631503118 ^| %DATE% %TIME%
%OSSL% s_client -connect example.com:443 -servername example.com < nul > tls.txt 2>nul
type tls.txt | %OSSL% x509 -noout -issuer -subject -dates
findstr /C:"Protocol" /C:"New," tls.txt
```

### Task 9 — run the fixed skeleton
```cmd
for /f %i in ('python -c "import os;print(os.urandom(32).hex())"') do set ENC_KEY_HEX=%i
echo %USERNAME% ^| 6631503118 ^| %DATE% %TIME%
python solution_skeleton.py
```

---

## Quick gotcha list

| Bash (worksheet) | cmd.exe equivalent |
|---|---|
| `printf ...; date '+%F %T %Z'` | `echo %USERNAME% ^| 6631503118 ^| %DATE% %TIME%` |
| `grep -n X file` | `findstr /n "X" file` |
| `cmd \| tee f` then read | `cmd > f` then `type f` |
| `< /dev/null` | `< nul` |
| `export VAR=val` | `set VAR=val` |
| `$(cmd)` capture | `for /f %i in ('cmd') do set VAR=%i` (`%%i` inside a `.bat`) |
| `openssl ...` | `"C:\Program Files\Git\mingw64\bin\openssl.exe" ...` |

> If any of this is fiddly, the simplest path is to run the **original bash commands** in
> **Git Bash** (right-click in the folder → "Git Bash Here"), where the worksheet's
> `printf ... date '+%F %T %Z'` stamp works verbatim.
