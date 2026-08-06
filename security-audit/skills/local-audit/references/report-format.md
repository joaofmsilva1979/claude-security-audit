# Local Audit Report Format

## Full Report Template

```markdown
# Security Audit Report — {Project Name}

**Date:** {YYYY-MM-DD}  
**Audited by:** Claude Code (local-audit skill)  
**Overall risk:** {Critical / High / Medium / Low / Clean}  
**Findings:** {N} Critical · {N} High · {N} Medium · {N} Low · {N} Info

---

## Executive Summary

{2–3 sentences covering the most important issues and the overall security posture.
If clean: "No critical or high severity issues were found. The project follows secure
practices for credential handling and dependency management."}

---

## Findings

### [CRITICAL/HIGH/MEDIUM/LOW/INFO] {Title}

- **Phase**: Secrets / SAST / Dependencies / Claude Config
- **Location**: `path/to/file.py:42` or `~/.claude/settings.json`
- **Description**: What the issue is and why it matters.
- **Evidence**:
  ```
  exact line, tool output excerpt, or snippet
  ```
- **Impact**: What an attacker or accident could cause if this is exploited.
- **Fix**:
  ```python
  # Before
  os.system(f"say {text}")

  # After — use subprocess.run with a list; no shell expansion
  subprocess.run(["say", text], check=True)
  ```
- **References**: CWE link, OWASP reference, or tool rule ID

---

## Remediation Applied

List any fixes made during this audit session:

- [ ] `path/to/file.py`: replaced `os.system()` with `subprocess.run()`
- [ ] `.gitignore`: added `.env` entry
- [ ] `requirements.txt`: upgraded `requests` from 2.28 to 2.32

---

## Appendix

### Tool versions used
- semgrep: {version}
- bandit: {version}
- gitleaks: {version}
- pip-audit: {version}

### Raw tool output
{paste full JSON output from tools here if needed for evidence}
```

---

## Certificate

After delivering the report, if all Critical and High findings are resolved, generate
the certificate:

```bash
python scripts/generate_certificate.py \
  --project "my-project" \
  --findings "0 Critical, 0 High, 2 Medium, 1 Low, 3 Info" \
  --output ~/Desktop
```

The certificate file is saved as `~/Desktop/security-certificate-YYYY-MM-DD.md`.
It is valid for 30 days or until the next significant commit.
