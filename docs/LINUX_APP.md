# OpsAI-A Linux aplikace (0.11.0: + Alembic migrace)

Linuxová desktopová a serverová aplikace podle `OpsAI_TZ_v0.2.md`:
Python 3.12 + NiceGUI (jedno codebase pro nativní okno i web),
vestavěné REST API (FastAPI), konektory `file` / `journald` /
`docker` / `kafka` / `loki` / `elasticsearch` / `syslog` /
`kubernetes` / `windows` / `azure` + generický push-ingest, maskovací
engine, AI provider varianty B (Meta Model API) a append-only audit.

## Rychlý start na notebooku

```bash
cd /home/ivar/Projekty/OpsAI-ocg
uv venv
uv pip install -e ".[dev]"

# Desktop UI (nativní okno, když je pywebview, jinak prohlížeč)
.venv/bin/opsai desktop

# Server UI + API na http://127.0.0.1:8080
.venv/bin/opsai server
# pouze REST API (bez UI)
.venv/bin/opsai server --api-only
```

Užitečné proměnné (`opsai/app/config.py`): `OPSAI_MODE`,
`OPSAI_DATA_DIR`, `OPSAI_HOST`, `OPSAI_PORT`, `OPSAI_EXECUTION_ENABLED`
(výchozí `false`), `OPSAI_LOCAL_EXEC_ENABLED` (cíle `local`, jen desktop),
`OPSAI_RESTRICTED_MODE`, `OPSAI_LANGUAGE` (`cs`/`en`),
`OPSAI_AI_LIVE` (bez klíčů běží vestavěný mock provider),
`OPSAI_DEV_AUTH` (dev hlavičky `X-User`/`X-Role`, výchozí `false`),
`OPSAI_DESKTOP_LOCK`, `OPSAI_COOKIE_SECURE` (výchozí `true`),
`OPSAI_SESSION_IDLE_MINUTES` (30), `OPSAI_SESSION_ABSOLUTE_HOURS` (12),
`OPSAI_SESSION_BACKEND` (`duckdb`/`sqlite`/`postgres`, výchozí `duckdb`),
`OPSAI_POSTGRES_DSN` (povinné pro backend `postgres`),
`OPSAI_SESSION_LIMIT_BYTES` (výchozí 1 GB na relaci),
`OPSAI_PRESIDIO_MODE` (`auto`/`on`/`off`, výchozí `auto`).

CLI:

```bash
.venv/bin/opsai ingest --path /var/log/syslog --name "syslog"
.venv/bin/opsai audit verify
```

## Co je hotovo a co zbývá

V MVP (v0.1.0): relace nad SQLite (1 soubor na relaci, limit 1 GB),
OQL podmnožina (text, `field:value`, regex, `AND/OR/NOT`, závorky,
`level`/`ts`/`rid` porovnání, `exists:`), maskování M-01–M-07
s allowlistem a post-mask verifikací, náhled payloadu se SHA-256
a jednostupňovým `stage_id`, mock + živí provideři, lokální
klasifikace rizik a deny-list, RBAC matice, audit s hash řetězcem,
znalostní šablony (2 playbooky), i18n cs/en, Docker image (slim/full),
`.deb` a AppImage.

Milník 2 (exekuční engine, v0.2.0): inventář hostů, stavový automat
běhů/kroků, politiky (deny-list, four-eyes, cron okna), exekutory
local/SSH, dry run, schvalování, skip/abort, rollback, UI `/execution`.
Detaily: `docs/EXECUTION.md`.

Milník 3 (konektory, v0.3.0): `kafka` (read-only, nikdy
necommituje), `loki` (LogQL), `elasticsearch` (`search_after`),
`syslog` (UDP/TCP listener + SQLite spool), `kubernetes` (logy podů
přes REST) a generický `POST /sessions/{id}/ingest`. Detaily:
`docs/CONNECTORS.md`.

Milník 4 (zbývající konektory, v0.4.0): `windows` (WinRM/pypsrp
+ lokální EvtQuery) a `azure` (KQL nad Log Analytics, 6 auth metod,
dělení okna při partial results). Živé testy podmíněné Windows
hostem / Azure SP; bez nich stub/mock testy. Detaily:
`docs/CONNECTORS.md`.

Milník 5 (identita, v0.5.0): lokální účty (Argon2id, politika
hesel, lockout, TOTP), PAT se scopy a expirací, web sessions
(Secure cookie, idle/absolutní expirace, CSRF), desktop implicitní
admin, dev hlavičky jen s `OPSAI_DEV_AUTH`. Detaily:
`docs/SECURITY.md`.

Milník 6 (session store, v0.6.0, FR-140): `SessionManager`
nad vyměnitelnými backendy – `duckdb` (výchozí, jeden soubor
na relaci, per-session write lock, `memory_limit` 2 GB), `sqlite`
(legacy) a `postgres` (jedna tabulka na relaci, JSONB, BRIN index
na `ts`, trigram index na zprávy, vyžaduje `pg_trgm`). Každá relace
si pamatuje backend, takže přechod nic nerozbije. OQL kompilátor
umí dialekty `sqlite`/`duckdb`/`postgres` (placeholdery, JSON
operátory, regex `REGEXP`/`regexp_matches`/`~`).

Milník 7 (OQL, v0.7.0): aliasy zdrojů FR-164 pro všechny
konektory, `in(...)`, `ts:last`, číselná porovnání nad JSON,
operátor `!=`, limity hloubky/délky, uložené dotazy + historie
(FR-163, API + UI). Detaily: `docs/OQL.md`.

Milník 8 (šablony, v0.8.0): bezestavový Drain3 backend se stejným
tvarem `TemplateInfo`, dispatch `auto`/`regex`/`drain3`,
`?backend=` na endpointu šablon. Detaily: `docs/PATTERNS.md`.

Milník 9 (Presidio, v0.9.0): volitelný `presidio-analyzer` backend
pro telefon/karty/IBAN/URL/osoby, práh 0.35, režimy `auto`/`on`/`off`
(`OPSAI_PRESIDIO_MODE`). Detaily: `docs/MASKING.md`.

Milník 10 (Helm, v0.10.0): chart `helm/opsai` (parita s `gitops/base`,
opt-in Secret/Ingress), živě ověřen na minikube, CI job pro helm
a kustomize. Detaily: `docs/HELM.md`.

Milník 11 (Alembic, v0.11.0): revize `0001` baseline + `0002` uložené
dotazy, upgrade/stamp pre-Alembic DB se zachováním dat, frozen `.deb`
balí migrace. Detaily: `docs/DATABASE.md`.

Zbývá dle TZ: OIDC/LDAP (vyžadují externí IdP).

## Testy na notebooku (2026-10-28)

| Kontrola | Výsledek |
|---|---|
| `pytest tests/` | 358 passed, 2 skipped (živé WinRM/Azure) |
| `ruff check` + `ruff format --check` | clean |
| `mypy opsai` | bez nálezů |
| `bandit -c .bandit -r opsai -ll` | 0 medium/high |
| `pip-audit` | No known vulnerabilities |
| CLI `ingest` + `audit verify` | OK |
| API server (socket): session → ingest → OQL → preview → send → audit | OK |
| Exekuce (socket): dry-run → run → echo krok → audit | OK |
| NiceGUI UI + co-hosted API (`GET /` 200, Quasar) | OK |
| UI `/execution` + `/admin` (200) | OK |
| `docker build` + run kontejneru (API + UI) | OK |
| `.deb` build + frozen smoke (ingest, migrace 0002) | OK (`opsai_0.11.0_amd64.deb`, 74 MB) |
| AppImage build + extrakt + spuštění | OK (`OpsAI-0.1.0-x86_64.AppImage`, 44 MB) |
| Helm install na minikube + `/health` + uninstall | OK |
| `kubectl kustomize` base + staging + production | validováno |

## Struktura

```
opsai/
  app/         konfigurace (env), bootstrap datových adresářů a DB
  api/         FastAPI router /api/v1 (health, sessions, analyses, audit,
               runs, inventory, policies)
  ui/          NiceGUI stránky (přehled, relace, analýza, exekuce, audit, admin)
  core/        session, normalize, query (OQL), patterns, risk, audit,
               states, policy, inventory
  execution/   engine běhů, exekutory local/SSH
  masking/     detektory M-01..M-07, Presidio, pseudonymizace, verifikace
  connectors/  file, journald, docker, kafka, loki, elasticsearch,
               syslog, kubernetes, windows, azure + registr
  providers/   meta (Meta Model API), mock + JSON schéma 9.5
  secrets/     keyring / lokální šifrovaný trezor + redakce logů
  auth/        RBAC, účty, TOTP, PAT, web sessions, identita, CLI users
  db/          datové tvary entit (TZ 3.1), Alembic migrace
  i18n/        cs.json, en.json
  prompts/     systémové prompty + playbooky
tests/         360 testů (pytest, kontejnery, minikube, helm)
docker/        Dockerfile, Dockerfile.full, docker-compose.yml
packaging/     build_deb.sh, AppImage, .desktop, ikona
gitops/        kustomize base/overlays + ArgoCD aplikace
helm/          Helm chart (parita s gitops/base)
.github/       CI, security a release pipeliny
```
