# OpsAI-B demo video — English voiceover (3:00)

Reading pace ~130 wpm. Timecodes match the video scenes. Static frames only,
no zooming.

## 0:00–0:12 — Title

Welcome to OpsAI, the AI assistant for log analysis and guided remediation.
This is variant B, powered exclusively by Meta AI, with the Muse family
of models.

## 0:12–0:32 — Sessions

Every incident starts with a session. On the overview we see our demo
session with twelve records. OpsAI combines desktop UI, web UI, and
a REST API in a single process, so you control the same data from the app
window, the browser, or programmatically.

## 0:32–1:00 — Log collection

Logs flow into the session from ten connectors: file, journald, docker,
Kafka, Loki, Elasticsearch, syslog, Kubernetes, Windows, and Azure, plus
a generic ingest endpoint for external shippers. The session workplace
shows a record table with timestamp, level, host, and service, alongside
template mining and a level-distribution chart. Saved queries keep the
team's frequent filters one click away.

## 1:00–1:20 — OQL

We query the data with OQL: free text, field value pairs, regular
expressions, and AND, OR, NOT logic. Parentheses, time and level
comparisons, field-existence tests. Here we narrow twelve records down
to the two errors that matter.

## 1:20–1:45 — Masking and Meta AI

Before anything leaves for the AI, the masking engine hides sensitive
data: emails, phone numbers, card numbers, and personal details. After
a payload preview and verification, you pick a Muse model: Muse Spark
for everyday analysis, Muse Wonder in preview for harder cases.
Contributor-mode models stay permanently blocked by policy, because Meta
would train on their data. The model returns a diagnosis with a concrete
repair procedure and a risk estimate.

## 1:45–2:05 — Execution

Approved remediation runs in the execution engine. Host inventory, run
state machine, policies such as deny-list, four-eyes approval, and time
windows. Dry-run first, then the live run locally or over SSH, with
rollback support.

## 2:05–2:25 — Audit

Every step is recorded in a hash-chained audit. Records can be neither
deleted nor changed, so you can always prove who did what, from log
ingest to AI dispatch to approval. Verifying the chain is a single
command.

## 2:25–2:40 — Users

Access is guarded by identity: local accounts with strong passwords and
a second factor, expiring personal tokens, and a role-permission matrix
for viewer, analyst, operator, and admin.

## 2:40–3:00 — Closing

OpsAI variant B, version 0.1.0: REST API, .deb and AppImage installers,
docker image, Helm chart, and GitOps for ArgoCD. Three hundred sixty-six
tests passing, Meta only. Sources are on GitHub at RaviSileb OpsAI-B.
Thanks for watching.
