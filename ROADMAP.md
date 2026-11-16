# Roadmap

firstsignal is an open-source, read-only incident triage CLI. It is free and MIT licensed, and nothing here is for sale. This roadmap covers the CLI and a possible team edition later. The reasoning behind it is in [docs/PRODUCT_PLAN.md](docs/PRODUCT_PLAN.md).

Work is tracked in [GitHub issues](https://github.com/AutoShiftOps/firstsignal/issues), grouped by [milestone](https://github.com/AutoShiftOps/firstsignal/milestones). Priorities: **P0** must ship for the milestone, **P1** should ship, **P2** if time allows.

No dates are promised. Stages 4 and 5 only start if Stage 3 says go.

| Stage | Milestone | Goal | Status |
|---|---|---|---|
| 1 | v0.2 Stabilize and ship | Released and verified, with incident memory in the CLI | Done, except real-collector CI |
| 2 | v0.3 Sharper triage | Live local triage, support bundles and published accuracy | Mostly done (0.3.0) |
| 2 | v0.4 Share and integrate | Fits into CI, chat and existing log stores | Planned |
| 3 | Validation gate | Evidence that teams use it and want shared memory | Pilot starting |
| 4 | v0.5 Team memory (alpha) | One shared incident history, fed by findings pushed from the CLI | Conditional on Stage 3 |
| 5 | v1.0 Team portal | Recurrence alerts, trends, roles | Conditional on Stage 4 |

**Direction:** deterministic incident triage with a memory. Logs stay where they are; only redacted findings ever leave the machine. firstsignal will not become a log platform or ship a collection agent.

## Phase 0: v0.2 Stabilize and ship

Shipped: incident memory ("seen before" with fix notes), Kubernetes source, structured log parsing, severity and order of first appearance, redaction, optional AI hypothesis, pattern packs, `--fail-on`, the website, a richer terminal summary, and `--html` for a shareable dashboard report.

Also shipped: `pip install firstsignal` (0.2.0, 0.2.1) and the website.

Remaining: test the collectors against real journalctl, Docker and a Kubernetes cluster in CI (#8).

**Done when:** CI exercises real collectors.

## Phase 1: v0.3 Sharper triage

Shipped in 0.3.0:

- `firstsignal watch`: continuous local triage that reports only what changed
- `firstsignal archive`: every log file in a customer support bundle (.zip, .tar.gz), read without extracting, with `file:line` citations, time order across files and a redacted ticket note
- Multi-line stack traces grouped into one event (Java, Python, Go, Node)
- Timestamps in common formats (nginx, syslog, Apache, epoch), so findings order correctly across files
- Stricter redaction: whole private-key blocks, `Authorization` headers, an entropy check for unlabeled secrets
- Detection precision fixes, and incident history that survives growth, clock skew and concurrent runs
- A labelled regression corpus with published accuracy (see the README); CI fails when results change

Still to do:

- Burst detection: when the error rate jumped, not only what appeared (#13)
- Per-source timelines in `bundle` for live sources (#14; done for `archive`)
- `firstsignal diff` to compare a run against a known-good baseline (#15)
- Kubernetes events and pod status as a source (#16)

**Done when:** on the corpus, the earliest observed finding matches the labelled one in most cases, with the result published. Met on the synthetic corpus; real-log accuracy comes from the pilot.

## Phase 2: v0.4 Share and integrate

- GitHub Action for post-deploy checks, with the report in the job summary
- Opt-in webhook and Slack post of the redacted summary
- Read-only collectors for Loki and CloudWatch Logs
- Container image and one-line installs

**Done when:** a team can run firstsignal in a pipeline and get the result in their channel without writing glue code.

## Phase 3: Validation gate

This phase is evidence, not code. It answers the two open questions in the product plan: do small teams want investigation tooling or only fewer alerts, and will they trust a tool with production logs.

- Interviews with engineers on 5 to 50 person teams, and with support or escalation engineers who triage customer log bundles
- Adoption signals from the open-source tool
- A free, restricted pilot: 3 to 5 engineers using it on real incidents and reporting back ([docs/PILOT.md](docs/PILOT.md))
- A written go or no-go decision

**Go if** the criteria in the product plan are met. **Otherwise** firstsignal stays a maintained open-source CLI, which is a fine outcome.

Whether a team edition would ever be offered commercially is undecided and is not part of this roadmap.

## Phase 4: v0.5 Team memory (alpha)

A small self-hosted service that receives redacted findings pushed by the CLI (`--push <url>`) and gives the team one shared history: live findings, which incidents repeat, and what fixed them. Runs from Docker Compose or Helm. The CLI stays the only thing that touches logs, and raw logs are never sent.

## Phase 5: v1.0 Team portal

Alerts on recurrence and severity, trends over time, teams and roles, an audit log, and retention controls. Whether anyone runs a hosted version is decided here, not before.

## Not planned

- Automatic remediation of any kind. firstsignal explains; people act.
- Raw log ingestion, storage or search.
- A separate collection agent. Later, the same CLI can run as a service.
- Replacing a log store, a metrics system or an on-call scheduler.
