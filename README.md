# OpsAI — varianta B (Meta Model API)

OpsAI je AI asistent pro analýzu logů a návrh nápravy: načte logy z více zdrojů,
umožní je filtrovat a vyhledávat, vybrané záznamy předá zvolenému AI modelu
a vrátí diagnózu s postupem opravy včetně řízené exekuce.

Tento repozitář obsahuje dokumentaci a implementaci **varianty B**
(AI provider Meta Model API).

Související varianty:

- A (OpenAI, Claude, Gemini): https://github.com/RaviSileb/OpsAI-A
- C (M365 Copilot): https://github.com/RaviSileb/OpsAI-C

## Dokumenty

- `OpsAI_BZ_v0.3.md` — business zadání (stav DRAFT)
- `OpsAI_TZ_v0.2.md` — technické zadání (stav DRAFT)

Společný základ variant A/B/C je shodný mimo kapitoly o AI providerech.
Rozdělení proběhlo ve verzi BZ v0.3 / TZ v0.2 (2026-10-27).

## Linux aplikace (0.1.0)

Python 3.12 + NiceGUI: desktop UI, web UI a REST API v jednom procesu.
Konektory `file` / `journald` / `docker` / `kafka` / `loki` /
`elasticsearch` / `syslog` / `kubernetes` / `windows` / `azure`,
OQL filtry s aliasy zdrojů, šablony (regex/Drain3), maskování
(regex + Presidio), AI provider Meta Model API — modely Muse
(`muse-spark-1.3` výchozí, `muse-wonder-1.0` preview) — plus offline
mock, audit s hash řetězcem, exekuční engine (běhy, schvalování,
rollback) a Alembic migrace DB.

Modely `*-contributor` jsou trvale zakázány politikou (FR-310):
Meta používá jejich prompty a odpovědi k tréninku. Web/search
grounding se nepoužívá (FR-311).

```bash
uv venv && uv pip install -e ".[dev]"
.venv/bin/opsai desktop   # desktop UI
.venv/bin/opsai server    # server UI + API na :8080
```

Živý režim (vyžaduje Meta API klíč, viz `docs/META_ONBOARDING.md`):

```bash
export OPSAI_AI_LIVE=1 OPSAI_META_API_KEY="..."
.venv/bin/opsai server
```

Dokumentace:

- `docs/META_ONBOARDING.md` — registrace Meta API, test připojení, ZDR (TBD-101/102)
- `docs/LINUX_APP.md` — běh, testy, struktura, milníky
- `docs/CONNECTORS.md` — konektory zdrojů logů
- `docs/OQL.md` — dotazovací jazyk, aliasy, uložené dotazy
- `docs/PATTERNS.md` — šablony zpráv a anomálie
- `docs/MASKING.md` — maskování a Presidio
- `docs/EXECUTION.md` — exekuční engine
- `docs/SECURITY.md` — model hrozeb a pipeline kontrola
- `docs/DATABASE.md` — schéma app.db a migrace
- `docs/GITOPS.md` — ArgoCD + Kustomize
- `docs/HELM.md` — Helm chart
- `docs/RUNNER.md` — GitHub-hostované runnery

CI/CD: `.github/workflows/` (`ci.yml` lint/test/build/helm,
`security.yml` pip-audit/bandit/gitleaks/Trivy/SBOM,
`release.yml` tag → GHCR + GitHub release s `.deb` a AppImage).
