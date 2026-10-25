# Secure Coding Review — Test Evidence Report

## Project overview
This educational project contrasts deliberately vulnerable examples with safer Python/SQLite patterns. Tests use synthetic accounts and an in-memory database.

## Scope and limitations
- Scope: SQL query construction, password storage and verification, username validation.
- This is a learning demonstration, not a production penetration test or complete application audit.
- Automated unit tests were run locally and passed 6 tests. Manual outputs were reported by the developer; do not treat them as independently captured screenshots.

## Findings

### F-01 — SQL injection risk in vulnerable example
**Severity:** High in an application that uses this pattern with untrusted input.

**Impact:** String-concatenated SQL can allow user input to change query logic, depending on the query and database permissions.

**Recommendation:** Use parameterized queries for every user-controlled value. Do not concatenate untrusted input into SQL.

### F-02 — Plaintext password storage/comparison
**Severity:** High if real passwords are stored in plaintext.

**Impact:** A database exposure can immediately reveal passwords, which may be reused elsewhere.

**Recommendation:** Store a password-specific derived hash with a unique salt, using a suitable scheme and work factor. Never store raw passwords.

### F-03 — Username validation
**Severity:** Medium and context-dependent.

**Impact:** Inconsistent input handling can increase attack surface. Validation alone does not prevent SQL injection.

**Recommendation:** Enforce server-side input rules and always use parameterized SQL.

## Test results
The six automated tests cover correct password, wrong password, injection-shaped username rejection, invalid username rejection, non-plaintext password storage/salt length, and short-password rejection. The reported local run completed with **6 tests passing**.

## Further hardening before real deployment
1. Consider Argon2id or scrypt, or carefully tune PBKDF2 to deployment needs.
2. Add rate limiting, secure sessions, account recovery protections, and monitoring.
3. Keep secrets out of logs and source control.
4. Re-test after code changes.

## Conclusion
The sample behaves as expected for the tested educational cases. This does not prove production readiness or absence of other vulnerabilities.
