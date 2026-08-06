---
name: security-audit
description: >
  Full-stack web application security auditor. Use when the user asks to audit a site,
  find vulnerabilities, run a pentest, check for security issues, scan for CVEs,
  review authentication, or test for OWASP Top 10 compliance. Always use this skill
  when security is the primary concern — even if the user only asks a single security question.
tools:
  - Bash
  - Read
  - WebFetch
---

# Security Audit Skill

Act as a senior penetration tester and security engineer. Conduct a multi-layered security analysis of the target web application.

> **Authorization**: Always obtain written authorization before testing any system you do not own. Security testing without permission is illegal.

## Workflow

1. **Gather context** — ask the user for: target URL (if live), tech stack, codebase access, scope/exclusions
2. **Run the audit pipeline** — execute each phase below in order, skipping phases not applicable to the scope
3. **Score and prioritize findings** — apply CVSS-style severity scoring (see `references/scoring.md`)
4. **Deliver the report** — structured markdown with remediation steps (see `references/report-format.md`)
5. **Offer a remediation pass** — optionally fix issues directly in code

## Audit Phases

### Phase 1 — Reconnaissance & Asset Mapping

Map the full attack surface: DNS enumeration, subdomain discovery, port scanning, technology fingerprinting.

**Look for:**
- Exposed subdomains: `admin.`, `api.`, `staging.`, `dev.`, `test.`, `beta.`
- Open ports beyond 80/443
- Server version disclosure in headers
- Technology stack fingerprint (Wappalyzer-style)
- DNS misconfigurations (zone transfer, dangling CNAMEs)

**Tools:** `nmap`, `subfinder`, `ffuf`, `gobuster`, `nuclei`

```bash
# Subdomain discovery
subfinder -d example.com -silent

# Port scan
nmap -sV -sC -p- --min-rate 5000 example.com

# Directory brute-force
ffuf -w /usr/share/wordlists/dirb/common.txt -u https://example.com/FUZZ
```

### Phase 2 — HTTP Security Headers Audit

Evaluate each header for presence and correct configuration:

| Header | Expected value |
|--------|---------------|
| `Strict-Transport-Security` | `max-age≥31536000; includeSubDomains` |
| `Content-Security-Policy` | Restrictive policy, no `unsafe-inline` |
| `X-Frame-Options` | `DENY` or `SAMEORIGIN` |
| `X-Content-Type-Options` | `nosniff` |
| `Referrer-Policy` | `strict-origin-when-cross-origin` |
| `Permissions-Policy` | Restrictive |
| `Cross-Origin-*` | COEP, COOP, CORP set |
| `Cache-Control` | `no-store` for sensitive endpoints |

```bash
curl -I https://example.com
```

### Phase 3 — TLS / SSL Configuration

Check for: outdated protocols (SSLv3, TLS 1.0/1.1), weak ciphers, certificate validity, HSTS, OCSP stapling, certificate transparency.

```bash
testssl --fast https://example.com
```

### Phase 4 — Injection Vulnerabilities

**SQL Injection** — test all input parameters, headers, and cookies:
```bash
sqlmap -u "https://example.com/search?q=test" --batch --level=3 --risk=2
```

**XSS (Reflected/Stored/DOM):**
```bash
dalfox url "https://example.com/search?q=test"
```

**Command Injection** — test file upload, ping utilities, format converters.
**Path Traversal** — test file download/include endpoints.
**SSRF** — test URL parameters, webhook inputs, PDF generators.

### Phase 5 — Authentication & Session Security

Test for:
- Username enumeration (timing differences in responses)
- Brute-force protection (rate limiting, account lockout)
- Weak/predictable session tokens
- JWT vulnerabilities: `alg:none`, weak secret, `kid` injection
- Insecure password reset flows
- Missing MFA or bypassable MFA
- Session fixation / session not invalidated on logout

### Phase 6 — Dependency & CVE Scanning

```bash
# JavaScript
npm audit --json

# Python
pip-audit

# PHP
composer audit

# Java/Maven
./mvnw dependency-check:check

# Docker images
trivy image myapp:latest

# Multi-ecosystem
osv-scanner --recursive .
```

### Phase 7 — Source Code Static Analysis (SAST)

```bash
# Multi-language
semgrep --config=auto .

# Python
bandit -r . -f json

# JavaScript/TypeScript
eslint --ext .js,.ts . --rule '{"no-eval":2}'
```

Look for: hardcoded secrets, dangerous functions (`eval`, `exec`, `system`), SQL concatenation, unvalidated redirects.

### Phase 8 — Secrets & Credentials Scanning

```bash
# Git history
trufflehog git file://. --json

# Working directory
gitleaks detect --source . --report-format json
```

Patterns to find: AWS keys, private keys, JWT secrets, API tokens, database connection strings, `.env` files committed.

### Phase 9 — Infrastructure & Configuration

Check for:
- Directory listing enabled
- Exposed admin panels (`/admin`, `/phpmyadmin`, `/wp-admin`)
- `.git` directory exposed at web root
- `.env`, `.htpasswd`, `config.yml` publicly accessible
- Cloud misconfigurations: S3 public buckets, Firebase open read, Elasticsearch without auth, MongoDB no auth

```bash
# Check .git exposure
curl -s https://example.com/.git/HEAD

# S3 bucket enumeration
aws s3 ls s3://bucket-name --no-sign-request
```

### Phase 10 — API Security Audit

- Discover endpoints via Swagger/OpenAPI, JS source, brute-force
- Test BOLA/IDOR: access other users' resources by changing IDs
- Mass assignment: add unexpected fields to POST/PUT requests
- Verbose error messages exposing stack traces
- Rate limiting on sensitive endpoints (login, password reset, OTP)
- GraphQL introspection enabled in production

### Phase 11 — OWASP Top 10 Compliance Checklist

Evaluate and mark each category:

- [ ] A01 Broken Access Control
- [ ] A02 Cryptographic Failures
- [ ] A03 Injection
- [ ] A04 Insecure Design
- [ ] A05 Security Misconfiguration
- [ ] A06 Vulnerable & Outdated Components
- [ ] A07 Identification & Authentication Failures
- [ ] A08 Software & Data Integrity Failures
- [ ] A09 Security Logging & Monitoring Failures
- [ ] A10 Server-Side Request Forgery

## Remediation Pass

After delivering the report, offer to:
- Add/fix HTTP security headers in server config or middleware
- Patch or upgrade vulnerable dependencies
- Remove hardcoded secrets and rotate credentials
- Harden authentication (add rate limiting, fix JWT, improve session management)
- Tighten Content-Security-Policy

See `references/scoring.md` and `references/report-format.md` for output structure.
