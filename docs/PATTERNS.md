# Šablony zpráv a anomálie (milník 8, v0.8.0)

Těžba šablon bez AI (TZ FR-200..205). Oba backendy vracejí stejný tvar
`TemplateInfo(template, count, hash)` – hash je prvních 16 znaků
SHA-256 šablony, řazení podle počtu sestupně.

## Backendy

| Backend | Princip | Kdy |
|---|---|---|
| `regex` | deterministické maskování IP, čísel, UUID, cest, e-mailů (`<*>`) | vždy dostupný, rychlý, nemění obecná slova |
| `drain3` | Drain3 shlukování (tokenová similarita) | přesnější slučování (`User alice/bob` → jedna šablona) |

Volba: `compute_templates(messages, backend)` s `auto` (výchozí) /
`regex` / `drain3`. `auto` použije Drain3, je-li nainstalován
(volitelný balíček `drain3`, extra `patterns`, v dev závislostech),
jinak regex. Explicitní `drain3` bez balíčku → `DrainUnavailableError`
(API: HTTP 501), neznámý backend → 400.

Drain3 běží bezestavově (čerstvý in-memory miner na každé volání),
takže filtrované podmnožiny přes OQL nikdy neznečistí sdílený stav.
Používá výchozí konfiguraci bez `drain3.ini`.

## API a UI

- `GET /api/v1/sessions/{id}/templates?oql=…&limit=…&backend=auto`
  → `{templates: [{template, count, hash}] (max. 100), sampled, backend}`.
- UI (stránka relace, sekce Templates) používá výchozí `auto`.

## Porovnání oken a špičky

- `compare_windows(old, new, backend)` (FR-205): `{new, gone, changed}`
  – nové/zmizelé šablony a změny počtu ≥2× / ≤0,5× (min. 5 výskytů).
- `spike_buckets(counts)` – robustní z-skóre (MAD), práh 3,5.

Testy: `tests/test_patterns.py` (oba backendy, dispatch, API, okna, špičky).
