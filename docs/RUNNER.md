# GitHub self-hosted runner na notebooku

Repozitář `RaviSileb/OpsAI-A` má registrovaný runner na tomto notebooku,
takže CI (lint, testy, build `.deb`, Docker) může běžet lokálně.

## Umístění a služba

- Adresář: `~/actions-runner-opsai-a` (mimo repozitář)
- Služba: uživatelská systemd jednotka `opsai-runner.service`
  (`~/.config/systemd/user/opsai-runner.service`), povolený linger
- Jméno runnera: `<hostname>-opsai-a`, labely `self-hosted`, `linux`, `x64`, `notebook`

## Použití ve workflow

```yaml
jobs:
  local-build:
    runs-on: [self-hosted, linux, x64, notebook]
```

Výchozí pipeliny (`ci.yml`, `security.yml`, `release.yml`) běží na
`ubuntu-24.04` z GitHubu; `notebook` label použijte pro úlohy, které
potřebují tento stroj (např. nativní test desktopové aplikace).

## Správa

```bash
# stav
systemctl --user status opsai-runner --no-pager
# log
journalctl --user -u opsai-runner -f
# restart
systemctl --user restart opsai-runner
# online stav v GitHubu
gh api repos/RaviSileb/OpsAI-A/actions/runners --jq '.runners[].status'
```

## Bezpečnostní poznámky

- Runner běží pod běžným uživatelem, ne pod rootem.
- Self-hosted runner spouští kód z PR — pro fork PRs ho nepoužívejte
  (workflow `pull_request_target` jen po review).
- Tokeny runnera (`~/actions-runner-opsai-a/.credentials*`) nikam
  nekopírujte a necommitujte.
