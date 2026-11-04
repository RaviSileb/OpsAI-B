# Runnery pro OpsAI-B (GitHub-hosted)

Všechny workflow repozitáře `RaviSileb/OpsAI-B` (`ci.yml`, `security.yml`,
`release.yml`) běží na GitHub-hostovaných runnerech `ubuntu-24.04`.
Spotřebovávají GitHub Actions minuty (billing); self-hosted runner pro
tento repozitář není registrován.

```yaml
jobs:
  build:
    runs-on: ubuntu-24.04
```

## Volitelně: vlastní runner

Pokud bys chtěl CI přesunout na vlastní stroj (např. notebook),
zaregistruj runner pro `RaviSileb/OpsAI-B` (Settings → Actions →
Runners → New self-hosted runner) s labely `self-hosted`, `linux`,
`x64` a přepni `runs-on` ve workflow zpět. Na stroji pak musí být
Docker (buildx), Python 3.12, Helm a kubectl. Pozor: self-hosted
runner spouští kód z PR — pro fork PRs ho nepoužívej
(`pull_request_target` jen po review) a tokeny runnera
(`.credentials*`) nikam nekopíruj ani necommituj.
