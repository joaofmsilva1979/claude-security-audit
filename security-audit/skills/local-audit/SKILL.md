---
name: local-audit
description: >
  Mac developer local security auditor. Use this skill whenever the user wants to
  scan their own code, git repos, or Claude Code environment for security issues —
  even if they only mention one concern. Trigger on: "audit my repos", "scan my code
  for secrets", "check for hardcoded credentials", "dependency vulnerabilities",
  "is my .env committed", "SAST scan", "check my Claude plugins", "security check
  before pushing", "generate a security certificate", "check for os.system calls",
  "am I leaking API keys", "prompt injection", "MCP security", "check my AI code".
  Covers the full local audit pipeline: secrets scan → SAST → dependency CVEs →
  Claude plugin audit → LLM/AI attack surfaces → report + optional certificate.
  Do NOT use for auditing live web apps or remote targets — use the security-audit
  skill for that instead.
allowed-tools:
  - Bash
  - Read
  - Write
---

# Local Mac Security Audit

Act as a staff security engineer auditing code the user owns and wants to harden before shipping. This is not a pentest of a remote target — it's an inward-looking audit of local repos and developer tooling.

> For auditing live web apps or remote targets, use the **security-audit** skill instead.

## Workflow

1. **Discover scope** — ask what to audit or default to the current directory + any git repos mentioned
2. **Run phases 1–5** in order; skip phases that don't apply (e.g. no `package.json` → skip npm audit; no AI/LLM code → skip phase 5)
3. **Score findings** using the severity guide below
4. **Deliver the report** — see `references/report-format.md`
5. **Offer a remediation pass** — fix issues directly in code where safe to do so
6. **Offer a certificate** — if all critical/high findings are resolved

---

## Phase 1 — Secrets & Credentials Scan

The goal is to catch real credentials before they leave the machine.

### Git history
```bash
# Scan every commit in history (catches secrets that were deleted but still live in git objects)
trufflehog git file://. --json 2>/dev/null \
  | jq -r '"\(.SourceMetadata.Data.Git.file // "unknown") [\(.DetectorName)]: \(.Raw[0:60])..."' \
  | head -30

# gitleaks as a second opinion
gitleaks detect --source . --report-format json --report-path /tmp/gitleaks-report.json --no-banner 2>/dev/null
cat /tmp/gitleaks-report.json 2>/dev/null | jq -r '.[] | "\(.File):\(.StartLine) [\(.RuleID)]: \(.Secret[0:40])..."' | head -30
```

### Working tree
```bash
# CRITICAL: .env files still tracked by git (gitignore does NOT retroactively untrack committed files)
git ls-files 2>/dev/null | grep -E '^\.env$|/\.env$|^\.env\.' | while read f; do
  echo "CRITICAL: $f is tracked — run: git rm --cached $f && git commit -m 'untrack $f'"
done

# LOW: .env files that exist locally but aren't in .gitignore yet
for f in .env .env.local .env.production .env.staging; do
  if [ -f "$f" ] && ! git ls-files --error-unmatch "$f" >/dev/null 2>&1; then
    git check-ignore -q "$f" 2>/dev/null || echo "LOW: $f exists but is not in .gitignore"
  fi
done

# Hardcoded secrets in source files (case-insensitive — catches STRIPE_KEY, AWS_SECRET_KEY, etc.)
grep -rni \
  --include="*.py" --include="*.js" --include="*.ts" \
  --include="*.rb" --include="*.go" --include="*.sh" \
  --exclude-dir=.git --exclude-dir=node_modules --exclude-dir=__pycache__ \
  -E '(api[_-]?key|secret[_-]?key|stripe[_-]?key|auth[_-]?token|password|access[_-]?key|aws[_-]?secret|private[_-]?key)\s*[=:]\s*["'"'"'][^"'"'"']{8,}["'"'"']' \
  . 2>/dev/null | head -30
```

**Severity mapping:**
| Finding | Severity |
|---------|----------|
| Real credential committed to git history | Critical |
| `.env` file tracked by git | Critical |
| Hardcoded API key/token in source | High |
| `.env` not in `.gitignore` | Low |
| `.env.example` with real-looking values | Medium |

---

## Phase 2 — Static Code Analysis (SAST)

Look for dangerous patterns that make it easy for attackers (or accidents) to cause harm.

### All languages — semgrep
```bash
semgrep --config=auto --json --quiet . 2>/dev/null \
  | jq -r '.results[] | "\(.path):\(.start.line) [\(.extra.severity)] \(.check_id): \(.extra.message)"' \
  | head -40
```

### Python
```bash
# bandit: Python-native security linter
bandit -r . -f json -q 2>/dev/null \
  | jq -r '.results[] | "\(.filename):\(.line_number) [\(.issue_severity)/\(.issue_confidence)] \(.issue_text)"' \
  | head -30

# Dangerous shell execution (specific patterns bandit sometimes misses)
grep -rn --include="*.py" --exclude-dir=.git \
  -E 'os\.system\s*\(' . | head -20
grep -rn --include="*.py" --exclude-dir=.git \
  -E 'subprocess\.(call|run|Popen)\s*\([^,)]*,?\s*shell\s*=\s*True' . | head -20
grep -rn --include="*.py" --exclude-dir=.git \
  -E '\beval\s*\(|\bexec\s*\(' . | head -20

# SQL injection: execute() calls with inline strings or f-strings (parameterized queries use a tuple second arg)
grep -rn --include="*.py" --exclude-dir=.git \
  -E 'execute\s*\(\s*f?["\x27]' . | head -10
```

### JavaScript / TypeScript
```bash
grep -rn --include="*.js" --include="*.ts" --include="*.jsx" --include="*.tsx" \
  --exclude-dir=.git --exclude-dir=node_modules \
  -E '\beval\s*\(|\bdocument\.write\s*\(|\.innerHTML\s*=|dangerouslySetInnerHTML' \
  . | head -20
```

**Key patterns and why they matter:**
- `os.system()` — passes a string to the shell; any user-controlled content = command injection. Prefer `subprocess.run([...])` with a list (no shell expansion).
- `shell=True` in subprocess — same risk as `os.system`. Use lists instead.
- `eval()`/`exec()` on untrusted data — arbitrary code execution.
- Raw SQL string concatenation — SQL injection.
- `innerHTML =` with user data — XSS.

---

## Phase 3 — Dependency Vulnerability Audit

Third-party packages are the most common source of supply-chain risk.

```bash
# Python — pip-audit (reads requirements.txt, pyproject.toml, or active venv)
if ls requirements*.txt pyproject.toml setup.py setup.cfg 2>/dev/null | head -1 | grep -q .; then
  pip-audit --format json 2>/dev/null \
    | jq -r '.dependencies[] | select(.vulns | length > 0) | "\(.name) \(.version): \([.vulns[].id] | join(", ")) → fix: \([.vulns[].fix_versions[0] // "no fix"] | join(", "))"'
fi

# Node.js — npm audit
if [ -f package.json ]; then
  npm audit --json 2>/dev/null \
    | jq -r '.vulnerabilities | to_entries[] | "\(.key) [\(.value.severity)]: \(.value.via[0].title // .value.via[0] // "transitive")"' \
    | head -30
fi

# Rust — cargo audit
if [ -f Cargo.toml ]; then
  cargo audit 2>/dev/null | grep -E 'error|warning|ID:' | head -20
fi

# Multi-ecosystem OSV scanner (most thorough; catches Python/npm/Go/Rust/Maven)
osv-scanner --recursive . 2>/dev/null | head -50
```

**Severity mapping:**
| Finding | Severity |
|---------|----------|
| CVE with CVSS ≥ 9 or known public exploit | Critical |
| CVE with CVSS 7–8.9 | High |
| CVE with CVSS 4–6.9 | Medium |
| CVE with CVSS < 4 | Low |
| Outdated package, no CVE | Info |

---

## Phase 4 — Claude Code Config & Plugin Audit

Claude Code's configuration and installed plugins run with broad filesystem access; a malicious or misconfigured plugin is a supply-chain risk.

```bash
# Installed plugins
echo "=== Installed plugins ==="
ls ~/.claude/plugins/cache/ 2>/dev/null || echo "(none)"

# Plugin manifests — look for unusual tool permissions
echo "=== Plugin manifests ==="
find ~/.claude/plugins -name "plugin.json" 2>/dev/null -exec sh -c 'echo "--- $1 ---"; cat "$1"' _ {} \;

# MCP server config
echo "=== MCP servers ==="
cat ~/.claude/settings.json 2>/dev/null | jq '.mcpServers // "none"'

# Secrets stored in Claude config (should use env vars or Keychain instead)
echo "=== Potential secrets in Claude config ==="
grep -r --include="*.json" \
  -E '"(api_key|apikey|secret|password|token|auth)"\s*:\s*"[^"]{8,}"' \
  ~/.claude/ 2>/dev/null | grep -v '"type"' | head -10
```

**What to flag:**
| Finding | Severity |
|---------|----------|
| API key/token stored in `settings.json` | High |
| MCP server pointing to a remote, non-localhost URL (unknown author) | Medium |
| Plugin requesting `Bash` tool with no clear justification | Medium |
| Unknown plugin not from a recognized publisher | Info |

---

## Phase 5 — LLM & AI Attack Surfaces

For codebases that use LLMs, MCP servers, or RAG pipelines. Skip if no AI components are present.

### Prompt injection — user input into system prompts
```bash
# Python: f-strings or concat with user-controlled vars passed to LLM calls
grep -rn --include="*.py" --exclude-dir=.git --exclude-dir=__pycache__ \
  -E 'f["\x27].*\{.*(user|request|query|message|input|prompt|body)' . | head -20

# JS/TS: template literals with user data near LLM calls
grep -rn --include="*.ts" --include="*.js" --include="*.tsx" \
  --exclude-dir=.git --exclude-dir=node_modules \
  -E '`.*\$\{.*(user|request|query|message|input|prompt|body)' . | head -20

# Direct string concat into messages/system_prompt arrays
grep -rn --include="*.py" --include="*.ts" --include="*.js" \
  --exclude-dir=.git --exclude-dir=node_modules \
  -E '(system_prompt|messages)\s*(\+|\.append|\.push).*\+' . | head -20
```

### Tool calling without human approval gate
```bash
# LLM tool definitions that can write, delete, or send without a confirm step
grep -rn --include="*.py" --include="*.ts" --include="*.js" \
  --exclude-dir=.git --exclude-dir=node_modules \
  -E '"(name|function)"\s*:\s*"(send_email|send_message|delete|write_file|execute_sql|run_command|shell)' \
  . | head -20
```

### RAG pipelines — external URL fetch into prompt context
```bash
# Fetching external URLs and piping raw content into prompts (indirect injection vector)
grep -rn --include="*.py" --exclude-dir=.git \
  -E '(requests\.get|httpx\.get|urllib).*\n?.*(prompt|message|context|system)' . | head -10

grep -rn --include="*.ts" --include="*.js" --exclude-dir=.git --exclude-dir=node_modules \
  -E '(fetch|axios\.get)\(' . | head -10
```

### MCP server scope audit
```bash
# List all configured MCP servers with their commands/URLs
echo "=== MCP servers (check for non-standard orgs or local paths) ==="
cat ~/.claude/settings.json 2>/dev/null \
  | jq -r '.mcpServers // {} | to_entries[] | "\(.key): \(.value.command // .value.url // "?")"'

# Flag any MCP server with filesystem write or shell exec capability
cat ~/.claude/settings.json 2>/dev/null \
  | jq -r '.mcpServers // {} | to_entries[] | select(.value.command | strings | test("npx|node|python|sh|bash")) | "REVIEW: \(.key) → \(.value.command)"'
```

### Browser-leaked secrets (React / Next.js / Expo)
```bash
# NEXT_PUBLIC_, VITE_, REACT_APP_ prefix = shipped to every visitor's browser
grep -rn --include="*.env*" --include="*.ts" --include="*.js" --include="*.tsx" \
  --exclude-dir=.git --exclude-dir=node_modules \
  -E '(NEXT_PUBLIC_|VITE_|REACT_APP_)(SECRET|KEY|TOKEN|PASSWORD|SERVICE_ROLE|PRIVATE)' \
  . | head -20
```

**What to flag:**
| Finding | Severity |
|---------|----------|
| User input directly concatenated into system prompt | High |
| LLM tool that writes to DB / sends messages without human gate | High |
| RAG pipeline fetching external URL without sanitization | Medium |
| MCP server installed from random GitHub repo (not `@modelcontextprotocol/*` or known org) | Medium |
| MCP server with `filesystem write` or `shell exec` scope | Medium |
| `NEXT_PUBLIC_`/`VITE_`/`REACT_APP_` prefix on a real secret | Critical |

---

## Severity Guide

| Severity | Meaning | SLA |
|----------|---------|-----|
| Critical | Exploitable right now, or credential actively exposed | Fix before next commit |
| High | High-probability impact if reached | Fix today |
| Medium | Real risk, needs context to exploit | Fix this sprint |
| Low | Minor hardening gap | Fix next release |
| Info | Best practice improvement | Backlog |

---

## Remediation Pass

After delivering findings, offer to fix issues directly:

- Replace `os.system()` calls with `subprocess.run([...], check=True)`
- Remove `shell=True` from subprocess calls
- Add `.env` and secret files to `.gitignore`
- Rotate any committed credentials (guide the user — Claude cannot do this for them)
- Upgrade vulnerable packages (`pip install --upgrade <pkg>` / `npm update <pkg>`)
- Remove hardcoded secrets and replace with environment variable lookups

---

## Certificate Generation

When all critical and high findings are resolved (or none were found), offer to generate a security certificate:

```bash
CERT_SCRIPT=$(find ~/.claude/plugins -name "generate_certificate.py" 2>/dev/null | head -1)
python3 "$CERT_SCRIPT" \
  --project "<project-name>" \
  --findings "X Critical, X High, X Medium, X Low, X Info" \
  --output ~/Desktop
```

See `references/report-format.md` for the full report and certificate structure.
