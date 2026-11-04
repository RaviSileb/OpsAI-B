# Exekuční engine (milník 2)

Řízená exekuce remediation plánů podle TZ kap. 11: běh = schválení,
four-eyes pro rizikové kroky, politiky, inventář, dry run a rollback.

## Zapnutí

```bash
export OPSAI_EXECUTION_ENABLED=true   # API jinak vrací 403
export OPSAI_LOCAL_EXEC_ENABLED=true  # jen desktop; cíle "local"
.venv/bin/opsai server
```

Bez `OPSAI_EXECUTION_ENABLED` vrací všechny `/runs` a `/plans/*/runs`
endpointy 403. UI stránka `/execution` pak ukazuje jen upozornění.

## Tok

1. UI `/execution` nebo `POST /api/v1/plans/{analysis_id}/runs`
   s `{"dry_run": true}` — vykreslí kroky s rozlišenými cíli,
   exekutorem, rizikem a politikou, nic nespouští.
2. `POST ... {"run_all": false}` vytvoří běh (DRAFT). `run_all: true`
   spustí vše a zastaví na prvním selhání/bloku/volbě.
3. `POST /runs/{id}/steps/{n}/run {"command": "..."}` — běh je
   schválení; editovaný příkaz se znovu kontroluje politikou.
4. Kroky s `requires_approval` vrací 409 (`ApprovalRequiredError`);
   schválí je jiný uživatel: `POST .../approve` (schválení = spuštění).
5. `.../skip {"reason": "..."}`, `.../abort`, `POST /runs/{id}/abort`,
   `POST /runs/{id}/rollback` (reverzní pořadí, nevratné kroky se hlásí).

## Transporty

- `local` — lokální subprocess bez PTY a stdin, jen desktop,
  defaultně vypnutý. `run_as` jiného uživatele přes `sudo -n`.
- `ssh` — systémový OpenSSH klient: `BatchMode=yes` (žádné dotazy
  na heslo), `StrictHostKeyChecking=yes`, jump hosty `-J`, klíče
  `-i`, známé hosty z `~/.ssh/known_hosts` (přepsatelné v profilu).
  Vzdálený příkaz se předává jako jeden quotovaný `sh -c` skript.
- `psrp`, `kubectl`, `az`, `kafka-cli` zatím nejsou — kroky končí
  BLOCKED s důvodem.

Rozhodnutí MVP: SSH přes CLI místo asyncssh (reuse existujícího
OpenSSH setupu operátora, jump chainy, host keys). Asyncssh zůstává
volbou pro pozdější interní transport.

## Cíle a inventář

Cíl kroku se depseudonymizuje mapou relace; neznámé tokeny blokují
krok (FR-405). `local` míří na lokální exekutor, jinak se hledá
v inventáři (`hostname` → `aliases` → `fqdn` → krátké jméno → IP).
Nula/více kandidátů nebo smíšená prostředí → explicitní volba
(`target_host_id` nebo `target_overrides`).

## Politiky

`GET/PUT /api/v1/policies/execution` (admin): deny-list, allow-only
režim, strop rizika na prostředí, four-eyes (prostředí + rizika),
časová okna (cron + TZ), timeouty, povolené exekutory, výjimky
řetězení. Každá změna je verzovaná a auditovaná s diffem.
Výchozí: deny-list FR-541, four-eyes pro `prod` + `change/destructive`.

## Známá omezení MVP

- Kroky běží synchronně v HTTP requestu (žádné background joby ani
  živý stream; výstup je k dispozici po doběhu).
- Identita je dev-mode (`X-User` hlavička, desktop default `local`);
  OIDC/PAT přijdou s autentizačním milníkem.
- Skutečné SSH proti živému serveru není v CI (v runneru neběží
  sshd); argv a chování kryjí testy se stub binárkou.
