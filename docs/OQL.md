# OQL – dotazovací jazyk (milník 7, v0.7.0)

OQL (OpsAI Query Language, TZ FR-160/161) je filtr záznamů v relaci.
Parser (`opsai/core/query.py`, funkce `compile_oql`) překládá OQL
na parametrizované SQL pro dialekty `sqlite`, `duckdb` a `postgres`.
Všechny hodnoty jdou výhradně jako vázané parametry, názvy sloupců
pocházejí z whitelistu a JSON cesty jsou validované – vstupem nelze
injectovat SQL (ověřeno fuzz testem, 2000 vstupů).

## Syntaxe

| Konstrukce | Příklad | Význam |
|---|---|---|
| volný text | `timeout` | `message` obsahuje (case-insensitive) |
| `pole:hodnota` | `service:api` | rovnost |
| wildcard | `service:app-*` | `*` = libovolný řetězec |
| uvozovky | `service:"a b"` | hodnoty s mezerami, `:` a `,` |
| regex | `message:/time.?out/` | regulární výraz (validovaný) |
| porovnání | `level>=WARN`, `ts<2026-10-28`, `rid>100` | `<`, `>`, `<=`, `>=`, `=`, `!=` |
| číselné JSON | `fields.latency_ms>100` | `CAST(json AS REAL)` |
| `in(...)` | `in(service, api, worker)` | výčet (OR) |
| relativní čas | `ts:last 15m` | `ts >= now - 15m` (`s`, `m`, `h`, `d`) |
| existence | `exists:fields.request_id` | `IS NOT NULL` |
| logika | `AND`, `OR`, `NOT`, `-`, `(…)` | `-x` = `NOT x`; sousedící atomy = `AND` |

Limity: dotaz max. 8000 znaků, vnoření max. 50 úrovní
(ochrana proti `RecursionError`, chyby mapují na HTTP 400).

## Pole a aliasy zdrojů (FR-164)

Základní sloupce: `rid`, `ts`, `source_type`, `origin_host`,
`service`, `level`, `message`. Obecný JSON: `fields.*`, `src_meta.*`.
`level` přijímá jména (`ERROR`, `WARN`, `INFO`… → škála 0–8).

Aliasy odpovídají klíčům, které konektory skutečně zapisují:

| Alias | Sloupec / klíč |
|---|---|
| `kafka.topic`, `kafka.partition`, `kafka.offset`, `kafka.key` | `fields.kafka_topic`, `partition`, `offset`, `kafka_key` |
| `kafka.header.<jméno>` | `fields.header_<jméno>` |
| `win.channel`, `win.event_id`, `win.provider`, `win.record_id` | `fields."win.…"` |
| `k8s.namespace`, `k8s.pod`, `k8s.container` | `fields.namespace`, `pod`, `container` |
| `k8s.label.<jméno>` | `fields.labels.<jméno>` |
| `loki.label.<jméno>` | `fields.label_<jméno>` |
| `es.index`, `es.doc_id` | `src_meta.index`, `doc_id` |
| `syslog.pri`, `syslog.facility`, `syslog.procid`, `syslog.msgid` | `fields.pri`, … |
| `azure.table` | `src_meta."azure.table"` |

Čísla uložená v JSON se při rovnosti porovnávají jako text
(`CAST(… AS TEXT)`), takže `kafka.partition:3` najde i číslo `3`.

## Dialekty

- `sqlite`: `json_extract`, operátor `REGEXP` (backend ho registruje).
- `duckdb`: `json_extract_string`, `regexp_matches`.
- `postgres`: `->` / `->>` nad JSONB, `~` pro regex, `%s` parametry.

## Uložené dotazy a historie (FR-163)

- `POST /api/v1/queries/saved` – uložit `{name, oql, shared}` (201).
- `GET /api/v1/queries/saved` – vlastní + sdílené.
- `PATCH /api/v1/queries/saved/{id}`, `DELETE …` – jen vlastník nebo admin.
- `POST /api/v1/queries/history` – zapsat filtr; `GET` – posledních 50.
- OQL se při uložení validuje (`compile_oql`); neplatný → 400.
- UI (stránka relace): vyhledávání zapisuje historii, selecty nabízejí
  uložené dotazy a historii, tlačítko dotaz ukládá.

Testy: `tests/test_query.py` (sada 60+ dotazů, chybové případy, fuzz,
aliasy na SQLite/DuckDB/PostgreSQL), `tests/test_saved_queries.py`.
