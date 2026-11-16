# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed
- Wording: reports say "earliest observed matching signature" and that order in the logs is a lead, not proof of cause. Nothing outside the labelled AI hypothesis claims a root cause
- `slow` is now titled "Slowness reported": the log says something was slow, which is not a latency measurement
- `permission` is now titled "Access denied", with advice that covers files, roles, database users and HTTP 403

### Fixed
- PostgreSQL rejected sessions (`FATAL:  password authentication failed`, no `pg_hba.conf` entry, unknown role or database) are no longer reported as crashes. New `postgres` rule `pg_connection_rejected` reports them instead; `PANIC` is still a crash
- "non-fatal" is no longer reported as a crash
- Pod eviction is only reported with Kubernetes phrasing; cache and session evictions no longer count
- "slow query log enabled" and similar settings lines are no longer reported as slowness
- Naming a pattern pack twice no longer counts every match twice

### Added
- Multi-line stack traces are one event: Java (frames, `Caused by:`, `... N more`, the exception printed after the log message), Python (including chained tracebacks), Go panics and Node errors. Counts are no longer inflated by frames, and the example shows the log line plus the exception's type and message (Java's deepest cause, Python's final line). `stats.events` and `stats.multiline_events` report how lines were grouped
- Timestamps in more formats are understood, so findings order correctly in time across files: nginx error log and Go (`2026/11/14 09:41:25`), syslog and journalctl (`Nov 14 09:41:25`; the year is inferred), Apache and nginx access logs (`[14/Nov/2026:09:41:25 +0000]`) and JSON epoch seconds or milliseconds. ISO times with any fraction length, comma fractions and `+0100` offsets now parse on Python 3.10 too
- `firstsignal archive BUNDLE`: analyze every log file in a customer support bundle (.zip, .tar, .tar.gz, .tgz) without extracting it. Findings cite `file:line`, are ordered by time across files, and a redacted `ticket-note.md` is written for the support ticket. IP addresses are masked by default in this mode. Unsafe members (path traversal, links, encrypted, suspicious compression ratio) are skipped and listed; size, entry and nesting limits stop zip bombs
- JSON report: each finding has `earliest`, `first_location` and `locations` (set for bundles)
- Redaction: an entropy check masks long random-looking tokens (API keys, session secrets) that match no known shape. UUIDs, paths, short ids and resource names such as pod names are kept. Hex of 32 or more characters is masked, so long hashes and container ids are masked too
- Tests that check every output for leaks: console, Markdown, JSON, HTML, AI payload and incident history

### Fixed
- Redaction: a private key in the logs is now masked as a whole block. Before, only the `BEGIN` line was masked and the key itself was printed
- Redaction: `Authorization` headers are masked at any length (`Bearer abc123` was not masked)
- Redaction: "basic authentication" and similar prose are no longer masked by mistake
- Incident history: a re-run whose findings grow or shrink stays one incident (it used to need exactly the same patterns). Merged records keep every pattern seen, the highest count for each, the worst severity, and what came first
- Incident history: a record with a timestamp far in the future no longer absorbs every later run; up to 5 minutes of clock skew is tolerated, and `last_seen_at` never moves back
- Incident history: timestamps without a zone are read as UTC instead of crashing comparisons; unreadable lines are kept in the file and reported by `history list`, not silently dropped on the next write
- Incident history: runs writing at the same time no longer overwrite each other (lock file plus a unique temporary file)
- `watch` saves count-only growth to history, not only new patterns
- Reports say what the counts cover: the whole input, its most recent part, or the busiest window of a watch. `stats.truncated` is now right for `file` runs on files larger than `--max-bytes`

## [0.2.1] - 2026-11-12

### Fixed
- Log files with Windows (CRLF) line endings: `file` and `watch` no longer keep a stray `\r` at the end of each line

### Added
- CI runs the tests on macOS and Windows as well as Linux
- README: platform support table and Windows install tips; install command is now `pip install firstsignal`

## [0.2.0] - 2026-11-12

First release as **firstsignal** (formerly incopilot).

### Changed
- **Renamed to firstsignal** (was incopilot): package, command, config file (`firstsignal.toml`), environment variables (`FIRSTSIGNAL_*`), history folder (`~/.firstsignal`) and website (https://firstsignal.autoshiftops.com/). The old command, variables, config file and history keep working for one release; the old command prints a note on stderr
- New logo and banner in `docs/brand/`
- JSON report has a new shape with `schema_version: "2"`
- `bundle` accepts any mix of `--unit`, `--container`, `--pod` and `--path`
- Shared options such as `--out-dir` are now given after the subcommand
- Next-step commands are filled in with the targets that were analyzed

### Added
- Website at https://firstsignal.autoshiftops.com/: sticky header with the current section highlighted, new sections for incident memory and `watch`, favicon, social preview card, 404 page, sitemap and robots.txt
- Issue forms (bug report, feature request, new pattern or pack) and a pull request template
- `firstsignal watch <source>`: continuous local triage that prints only what changed, keeps one history record per session, and writes a final report when stopped
- Pattern packs for Redis, MySQL, HAProxy and Kafka (`--packs redis,mysql,haproxy,kafka`)
- Incident memory: each run is remembered as a fingerprint, similar past incidents are shown as "Seen before", and `firstsignal history list|note|forget` manages them. Stored locally with no log text
- `--html` writes a self-contained `report.html` dashboard
- Terminal output shows the golden-signals summary and an order-of-first-appearance table
- Example report on the website at `site/viewer.html`
- `ROADMAP.md` and `docs/PRODUCT_PLAN.md`
- Kubernetes source (`firstsignal k8s`) using `kubectl logs`, by pod, workload reference or label selector
- Structured log support: JSON lines, logfmt levels, and kubectl/docker prefixes and timestamps
- Severity for every finding and an overall severity for the run
- Order of first appearance, to separate likely causes from knock-on effects
- Secret redaction in all reports, on by default (`--no-redact`, `--redact-ips`)
- Optional AI hypothesis (`--ai`) with your own key: Anthropic, OpenAI-compatible endpoints, or local Ollama
- Pattern packs (`--packs`): core, nginx, postgres, node, kubernetes, jvm
- `firstsignal.toml` for custom patterns, noise filters and redaction rules
- `--fail-on` exit code for CI and scheduled runs, `--json` output, stdin and `.gz` input
- Dockerfile, CI on Python 3.10 to 3.13, and a project website

### Fixed
- Report viewer: the paste box was always open because a CSS rule overrode `hidden`; it now opens only from "Paste JSON". The header stays visible while scrolling and links to the website
- Website: the timeline's end label overlapped the first row
- `docker logs` output written to stderr was dropped
- `--max-bytes` truncated by characters and could cut a line in half
- `http_5xx` rarely matched real access logs and could match unrelated numbers
- The test suite imported a Click entry point that did not exist

### Removed
- `config.py` and `config_extended.py`, replaced by pattern packs and `firstsignal.toml`
- Sample reports committed under `out/`

## [0.1.0] - 2026-07-08

### Added
- Initial release of incopilot
- AI-powered incident triage CLI agent
- Three log sources: journalctl, Docker logs, plain files
- Four Golden Signals mapping
- Dual output: Markdown and JSON
- Bundle mode for analyzing multiple sources
- Pure Python implementation
