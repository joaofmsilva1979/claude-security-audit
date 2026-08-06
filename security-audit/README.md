# Security Audit Plugin

Two complementary security audit skills for Claude Code:

| Skill | Purpose | Target |
|-------|---------|--------|
| **local-audit** | Scan your own codebases for secrets, dangerous code, CVEs, and Claude plugin risks | Local repos and `~/.claude` config |
| **security-audit** | Full 11-phase web app pentest (recon → OWASP Top 10) | Remote web applications |

---

## local-audit

Audit your own code before pushing. Covers:

- **Secrets scan** — git history + working tree (trufflehog, gitleaks, grep patterns)
- **SAST** — dangerous function calls, SQL injection, XSS, eval (semgrep, bandit)
- **Dependency CVEs** — pip-audit, npm audit, osv-scanner, cargo audit
- **Claude plugin audit** — plugin manifests, MCP server config, stored credentials
- **Certificate generator** — produces `~/Desktop/security-certificate-YYYY-MM-DD.md` when you're clean

### Trigger phrases
> "audit my repos", "check for secrets", "scan my code", "dependency vulnerabilities",
> "is my .env committed", "check my Claude plugins", "generate a security certificate"

### Required tools
```bash
brew install trufflehog gitleaks semgrep
pip install bandit pip-audit
go install github.com/google/osv-scanner/cmd/osv-scanner@latest
```

---

## security-audit

11-phase web application pentest for targets you own or have authorization to test.
Covers: recon, headers, TLS, injection (SQLi/XSS/SSRF/RCE), authentication, dependencies,
SAST, secrets, infrastructure misconfigs, API security, OWASP Top 10.

### Trigger phrases
> "audit https://example.com", "pentest our staging site", "find vulnerabilities",
> "OWASP Top 10 compliance check"

### Required tools
```bash
brew install nmap testssl trufflehog gitleaks trivy
pip install sqlmap semgrep pip-audit
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/ffuf/ffuf/v2@latest
go install github.com/hahwul/dalfox/v2@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/google/osv-scanner/cmd/osv-scanner@latest
```

---

## Legal Notice

Always obtain **written authorization** before testing any system you do not own.
Unauthorized security testing is illegal in most jurisdictions.

The `local-audit` skill is designed for code you own. The `security-audit` skill
is for targets you have explicit written permission to test.
