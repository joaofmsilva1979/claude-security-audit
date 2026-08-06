# Report Format

Each finding must include all of the following fields:

```markdown
## [SEVERITY] Finding Title

- **Category**: e.g. Injection / Broken Access Control / Misconfiguration
- **Affected component**: URL, file path, or endpoint
- **CVSS Score**: e.g. 8.1
- **Description**: What the vulnerability is and why it matters
- **Evidence**: Request/response, screenshot, code snippet, or tool output
- **Impact**: What an attacker could do if exploited
- **Remediation**: Step-by-step fix with code examples where applicable
- **References**: CVE, CWE, OWASP link, or vendor advisory
```

## Executive Summary

Open the report with:
1. Overall risk rating (Critical / High / Medium / Low)
2. Number of findings per severity
3. 2–3 sentence summary of the most critical issues

## Appendix

Include raw tool output, full request/response captures, and environment details.
