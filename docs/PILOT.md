# firstsignal pilot

Thank you for trying firstsignal. This page is everything you need: what we are asking, the rules,
a five-minute start, and how to send feedback.

## What we are asking

For **30 days**, run firstsignal when you look at real logs:

- during or after a real incident, or
- on a log bundle a customer attached to a support ticket, or
- on logs from a past incident you remember well.

After each run, take **two minutes** to fill in the feedback form below. Five honest runs are worth
more than twenty polished ones. The pilot is free, nothing is sold, and you can stop at any time.

## The rules

1. **Advisory only.** firstsignal reads logs and explains what it finds. It never changes a system,
   and its findings can be wrong. Decide for yourself; do not act on a finding you have not checked.
2. **Review before you share.** Secrets, emails and (in support-bundle mode) IP addresses are masked
   by default, but masking cannot catch everything. Read a report before you paste it anywhere.
3. **Your logs stay with you.** Do not send us logs or reports. Feedback is about the tool: what
   helped, what misled you, how long things took. Leave out hostnames, customer names and log lines.
4. **A visible secret is a stop.** If you ever see a password, token or key in any output, stop and
   email security@autoshiftops.com with the type of secret and the command you ran (not the secret).
   That is the most important bug you can find.
5. **Consent.** Reply "I agree to the pilot rules" to the invitation before your first run.

## Five-minute start

Requires Python 3.10 or later on Linux, macOS or Windows.

```bash
pipx install "firstsignal>=0.3.0"        # or: pip install "firstsignal>=0.3.0"
firstsignal --version

# a quick look at a sample incident (no setup)
git clone https://github.com/AutoShiftOps/firstsignal && cd firstsignal
firstsignal file --path examples/checkout-incident.log --packs core,nginx
```

Then on your own logs, pick the line that fits:

```bash
firstsignal archive ticket-4821.zip --packs all        # a customer support bundle
firstsignal file --path /var/log/app.log --packs all   # a log file, .gz, or '-' for stdin
firstsignal k8s --pod deploy/api -n prod --since 30m   # Kubernetes
firstsignal docker --container api --since 1h          # Docker
firstsignal journal --unit nginx --since "30 min ago"  # systemd
```

Add `--html` for a page you can open in a browser. Reports go to `./out/`; for a support bundle,
`out/ticket-note.md` is a short summary for an internal ticket note.

What to know:

- Nothing leaves your machine. There is no account and no telemetry. `--ai` is off; please leave it
  off during the pilot so results are comparable.
- Each run with findings is remembered in `~/.firstsignal/history.jsonl` (pattern names, counts,
  times; no log text). Add `--no-history` to skip that. `firstsignal history note <id> "what fixed it"`
  records a fix, so the next similar incident shows it.

## What to look at in each run

- **The earliest observed matching signature.** Is it where you would have started looking?
- **The findings table.** Which findings helped? Which were wrong or noise?
- **For a bundle:** do the `file:line` citations take you to the right lines?
- **Time.** About how long from opening the logs to your first real lead, with firstsignal? How long
  would it usually take you?

## Feedback form

Copy this for each run and send it to **admin@autoshiftops.com** with the subject "firstsignal
pilot". Short answers are fine.

```text
Date:
Source: support bundle / file / k8s / docker / journal
Kind of problem (one line, no names):

1. Was the earliest signature where you would start?   yes / partly / no
2. Findings that helped (names from the report):
3. Findings that were wrong or noise (and why, briefly):
4. Anything important it missed:
5. Minutes to first lead with firstsignal:      usual minutes without:
6. Did "seen before" appear? Was it right?       n/a / yes / no
7. Did you see any secret, email or IP in the output?  no / yes (also email security@)
8. Would you run it again on the next incident?  yes / maybe / no, because:
```

At the end of the 30 days we will ask three questions: what you would miss if it went away, what
would make you stop using it, and whether a shared team history would be worth running yourselves.

## What happens to your feedback

It is summarized without names or company details in `docs/validation/` and used for the go or
no-go decision described in [PRODUCT_PLAN.md](PRODUCT_PLAN.md). Misleading findings become cases in
the regression corpus, written from your description, never from your logs.

## Stopping

```bash
pipx uninstall firstsignal          # or: pip uninstall firstsignal
rm -rf ~/.firstsignal               # remove the local history (Windows: %USERPROFILE%\.firstsignal)
```
