# Task 3 — Secure Coding Review

Educational Python project showing insecure coding patterns and safer alternatives.

## Contents
- `vulnerable_sample.py`: intentionally unsafe examples for learning only.
- `secure_sample.py`: safer SQLite query, password hashing, and username validation.
- `tests/test_secure_sample.py`: six automated unit tests.
- `findings_report.md`: findings, impact, severity, and recommendations.
- `evidence/README.md`: guidance for adding genuine screenshots.

## Run
From this folder:

```bash
python -m unittest discover -s tests -v
python secure_sample.py
```

This is an educational demo, not a production authentication system or full security audit.