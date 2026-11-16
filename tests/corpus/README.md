# Regression corpus

Labelled log samples that firstsignal is scored against. Each case is a folder:

```
<case>/
  case.json   description, mode (file or archive), packs, truth, snapshot, must_not_leak
  logs/       one log file (file mode) or the files of a support bundle (archive mode)
```

## Labels

`truth` is written by reading the logs, never by copying firstsignal's output.

- **findings**: every pattern whose title accurately describes something in the logs. A specific
  finding and a generic one can both be right (`nginx_upstream_timeout` and `timeout`). A finding is
  wrong when its title says something the logs do not show, for example "Crashes and fatal errors" for
  a traceback that was logged and handled.
- **first**: the finding an engineer would start from, using timestamps across files. When two
  findings share a second, it is the one that caused the other.

`snapshot` is what firstsignal reports today. Accuracy compares `snapshot` with `truth`;
`tests/test_corpus.py` fails whenever a snapshot changes, so every change in results is reviewed.

`must_not_leak` lists strings (fake secrets, IPs) that must not appear in any output.

## Running it

```bash
python scripts/corpus.py              # score and print the table
python scripts/corpus.py --snapshot   # accept current results as the new snapshots; review the diff
python scripts/corpus.py --dir PATH   # score a held-out corpus kept outside the repo
```

## Held-out corpus

Rules must not be written or tuned against the held-out set. Keep it outside the repository (real
bundles from pilots, sanitized), in the same folder layout, and score it before each release with
`--dir`. Only the summary numbers are ever published.

## Data

Every sample here is synthetic, modelled on real formats (log4j, Python logging, Go, pino, nginx,
PostgreSQL, Kubernetes events, Redis, MySQL, Kafka, syslog). Addresses use documentation ranges
(10.0.0.0/8, 198.51.100.0/24, 203.0.113.0/24); no real hosts, people or secrets appear.
