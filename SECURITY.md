# Security Policy

## Reporting Security Vulnerabilities

**Please do NOT open public GitHub issues for security vulnerabilities.**

If you discover a security vulnerability in firstsignal, please report it responsibly by emailing:

📧 **security@autoshiftops.com**

Include the following information:
- Description of the vulnerability
- Steps to reproduce (if applicable)
- Potential impact
- Suggested remediation (if any)

## Security Considerations

### What firstsignal does
- Reads logs through `journalctl`, `docker logs` or `podman logs`, `kubectl logs`, a file you name, or a support bundle (`archive`)
- Runs those tools with a fixed argument list and no shell; values that look like options are rejected
- Masks secrets in every output by default (terminal, Markdown, JSON, HTML, the ticket note, the AI payload): passwords, tokens and keys, credentials in URLs, `Authorization` headers at any length, whole private-key blocks, emails, and long random-looking tokens found by an entropy check. In `archive` mode IP addresses are masked too
- Writes `report.md` and `report.json` (plus `report.html` with `--html`, and `ticket-note.md` for `archive` runs) to the directory you choose
- Keeps incident history in one local file (`~/.firstsignal/history.jsonl`, mode 0600) holding pattern names, counts, targets, times and your notes, never log text
- Sends nothing over the network unless you pass `--ai`

### Support bundles (`archive`)
A bundle is treated as untrusted input:
- Nothing is extracted to disk; members are read in memory in bounded chunks
- Absolute paths, `..`, control characters in names, links, encrypted members and members with a suspicious compression ratio are skipped and listed in the report
- Reading stops at 1 GB unpacked (`--max-total-mb`) or 10,000 entries; nested archives are opened one level deep only

### What `--ai` sends
- Only the redacted findings summary: counts, order of appearance, up to two redacted example lines per finding, and the top repeating lines
- Never the raw log, and never anything when `--no-redact` is set
- To the provider you configure with your own key, over HTTPS (plain HTTP is accepted for localhost only, for local models)
- Redaction uses known secret shapes plus an entropy check, and still cannot guarantee that every secret is caught. Review what your logs contain before enabling `--ai` or sharing a report outside your team

### What firstsignal does not do
- Change anything: no restarts, deletes, scaling or config edits. Suggested commands are read-only and are printed, never run
- Execute or act on anything a model returns
- Store credentials. API keys are read from environment variables only

## Supported Python Versions

- Python 3.10, 3.11, 3.12 and 3.13
