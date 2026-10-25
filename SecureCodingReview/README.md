# Secure Coding Review (Python)

A small, reproducible secure-code-review demonstration for the CodeAlpha Cyber Security Internship. It compares an intentionally vulnerable example with a safer implementation and includes a findings report and unit tests.

## Scope

- SQL injection caused by unsafe SQL string construction
- Plaintext password storage and comparison
- Input validation for usernames
- Safer password storage using a per-password random salt and PBKDF2-HMAC-SHA256
- Regression tests for the safer implementation

This is an educational code-review sample, not a production-ready authentication service. It does not implement sessions, MFA, account lockout/rate limiting, password reset, or deployment hardening.

## Project files

- `vulnerable_sample.py` — intentionally insecure code for review; do not use in production.
- `secure_sample.py` — safer SQLite example using parameterized queries and salted password hashes.
- `findings_report.md` — findings, impact, severity, and remediation.
- `tests/test_secure_sample.py` — regression tests for the safer implementation.

## Requirements

Python 3.10+; standard library only.

## Run tests

From this folder:

```powershell
python -m unittest discover -s tests -v
```

## Run the demonstration

```powershell
python secure_sample.py
```

The demo creates a temporary SQLite database, adds a sample account, verifies the correct password, and rejects an incorrect password. It does not start a network service or contact external systems.

## Safety

The vulnerable file is included only so reviewers can see and discuss the flaws. Use synthetic data only. Never deploy the vulnerable sample or reuse its insecure patterns.
