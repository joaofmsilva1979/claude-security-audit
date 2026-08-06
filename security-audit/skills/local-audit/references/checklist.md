# Local Security Audit Checklist

Use this as a quick-reference checklist during an audit session.

## Phase 1 — Secrets & Credentials

- [ ] Ran `trufflehog git` on full git history
- [ ] Ran `gitleaks detect` on working tree
- [ ] Checked for `.env` files tracked by git (`git ls-files | grep .env`)
- [ ] Verified `.env` is in `.gitignore`
- [ ] Grep'd source files for hardcoded credential patterns
- [ ] Checked `.env.example` for real values

## Phase 2 — SAST

- [ ] Ran `semgrep --config=auto`
- [ ] Ran `bandit -r .` (Python projects)
- [ ] Grepped for `os.system()` calls
- [ ] Grepped for `subprocess` calls with `shell=True`
- [ ] Grepped for `eval()`/`exec()` usage
- [ ] Checked for SQL string concatenation
- [ ] Checked for `innerHTML =` / `dangerouslySetInnerHTML` (JS/TS)

## Phase 3 — Dependencies

- [ ] Ran `pip-audit` (Python)
- [ ] Ran `npm audit` (Node.js)
- [ ] Ran `cargo audit` (Rust)
- [ ] Ran `osv-scanner --recursive .` (multi-ecosystem sweep)

## Phase 4 — Claude Code Config

- [ ] Listed installed plugins (`~/.claude/plugins/cache/`)
- [ ] Reviewed plugin manifests for unusual tool permissions
- [ ] Checked MCP server configurations
- [ ] Grepped Claude config for stored secrets

## Remediation Verification

- [ ] All Critical findings fixed or accepted with documented reason
- [ ] All High findings fixed or accepted with documented reason
- [ ] Fixed files re-scanned to confirm remediation
- [ ] Credentials that were exposed → rotated (remind user — Claude cannot do this)

## Certificate Conditions

- [ ] 0 unresolved Critical findings
- [ ] 0 unresolved High findings
- → Ready to generate certificate
