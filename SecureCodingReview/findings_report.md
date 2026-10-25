# Secure Coding Review Report

## Overview
Target: educational Python/SQLite account-handling example. Review type: manual source review and regression tests. This is not an audit of a deployed production application.

## Findings summary
| ID | Finding | Severity | Remediation status |
|---|---|---|---|
| SCR-01 | SQL injection risk from string-formatted SQL | High | Fixed in safer sample |
| SCR-02 | Plaintext password storage/comparison assumption | High | Fixed in safer sample |
| SCR-03 | Missing username input validation | Medium | Fixed in safer sample |

Severity is a qualitative training assessment, not a formal CVSS score.

## SCR-01 — SQL injection risk
**Evidence:** vulnerable_sample.py inserts username into SQL using an f-string.  
**Impact:** crafted input may alter query logic depending on database context.  
**Fix:** parameterized SQL with placeholders; secure_sample.py uses `WHERE username = ?`.  
**Validation:** test input containing SQL metacharacters is treated as a literal username.

## SCR-02 — Plaintext password assumption
**Evidence:** vulnerable_sample.py compares a stored string directly to a supplied password.  
**Impact:** a database disclosure could expose passwords for reuse elsewhere.  
**Fix:** per-password random salt, PBKDF2-HMAC-SHA256 and constant-time comparison in the safer example. Production applications should use maintained framework/library guidance and tune a modern password hash appropriately.  
**Validation:** tests verify correct and incorrect passwords and confirm plaintext is not stored.

## SCR-03 — Missing username validation
**Evidence:** vulnerable function accepts arbitrary strings.  
**Impact:** malformed input may cause inconsistent behavior and compound other weaknesses.  
**Fix:** allow only a documented 3–32 character username format before database access.  
**Validation:** tests cover invalid usernames.

## Limitations
This example is not production-ready: it lacks sessions, MFA, rate limiting, password reset, and deployment hardening. Add those controls and follow your framework's security guidance before using real accounts.

## Conclusion
Parameterized queries, salted password hashing, input validation and regression tests reduce the demonstrated risks in this educational example.
