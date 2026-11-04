# Bezpečnost OpsAI-A

## Model hrozeb (zkráceně z BZ/TZ)

- Logy jsou nedůvěryhodná data: XSS v UI, prompt injection do AI,
  tajemství v textu (M-01–M-07 + allowlist M-14).
- AI může halucinovat: lidské schválení, lokální klasifikace rizik
  (`max(AI, lokální)`), deny-list, zákaz řetězení příkazů.
- Audit je vždy zapnutý, append-only s hash řetězcem (`opsai audit verify`).
- Tajemství: OS keyring na desktopu, šifrovaný trezor (AES-256-GCM,
  obálkové šifrování) na serveru; redakce v logech (`SecretRedactor`).
- Exekuce je ve výchozím stavu vypnutá (`OPSAI_EXECUTION_ENABLED=false`,
  API vrací 403). Po zapnutí: politiky (deny-list, four-eyes, časová
  okna), cíl se musí rozlišit v inventáři, neznámé tokeny blokují krok,
  editované příkazy se kontrolují znovu, SSH jen klíče + strict host
  keys + batch mode. Detaily: `docs/EXECUTION.md`.

## Pipeline kontrola (`.github/workflows/security.yml`)

| Nástroj | Brána |
|---|---|
| `pip-audit` | fail při jakékoli známé zranitelnosti (přísnější než NFR-112) |
| `bandit -ll` | fail při medium a výš (konfig `.bandit`) |
| `gitleaks` | fail při nálezu tajemství (konfig `.gitleaks.toml`) |
| Trivy fs + image | fail při opravitelných HIGH/CRITICAL (`ignore-unfixed`), SARIF do code scanning + artefakt |
| SBOM CycloneDX | artefakt každého security běhu i releasu |

Lokálně:

```bash
.venv/bin/pip-audit
.venv/bin/bandit -q -c .bandit -r opsai -ll
```

## Kontejner (NFR-113)

Non-root UID 10001, read-only root FS (`read_only: true` v compose,
`readOnlyRootFilesystem` v GitOps), drop ALL capabilities,
`no-new-privileges`, healthcheck na `/api/v1/health/live`.

## Klíče AI providerů

Nikdy do repozitáře. Živý režim: `OPSAI_AI_LIVE=1` +
`OPSAI_META_API_KEY` z prostředí nebo secret store. Bez něj běží mock
provider. Modely `*-contributor` jsou trvale zakázány (FR-310).
Onboarding klíče: `docs/META_ONBOARDING.md`.

## Identita (FR-600/603/604/605)

Pořadí vyhodnocení: `Authorization: Bearer <PAT>` → session cookie →
dev hlavičky (jen s `OPSAI_DEV_AUTH=1`) → implicitní admin (jen
desktop bez `OPSAI_DESKTOP_LOCK`). Předložené, ale neplatné údaje
vždy končí 401 (fail-closed, žádný pád na slabší metodu).

- Lokální účty: Argon2id, politika (min. 12 znaků + offline
  blocklist `opsai/auth/blocklist.txt`), lockout 10 pokusů / 15 min,
  volitelné TOTP (RFC 6238, stdlib). První účet vzniká v setup módu
  (otevřený `POST /users`, vynucený admin) nebo přes
  `opsai users create`. Posledního admina nelze smazat, vypnout
  ani degradovat.
- PAT: `opsai_pat_…`, scope `read/analyze/execute/admin` (průnik
  s rolemi uživatele), expirace max. 1 rok, uložen jen SHA-256,
  plaintext se ukáže jednou. `read` token neumí vytvářet relace
  ani spouštět analýzy.
- Web session: cookie `Secure`/`HttpOnly`/`SameSite=Lax`, idle 30 min
  + absolutní 12 h (konfigurovatelné), CSRF synchronizer token pro
  cookie-mutace (`X-CSRF-Token`), Bearer volání jsou vyňata.
- Audit: `auth.login`, `auth.logout`, `auth.login_failed`,
  `users.*`, `pats.*` – nikdy bez tajemství v detailech.

OIDC (FR-601) a LDAP (FR-602) zatím nejsou – vyžadují externího IdP;
rozhraní identity je na ně připravené (`Identity.method`).
