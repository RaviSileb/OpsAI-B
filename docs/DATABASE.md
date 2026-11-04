# Databáze aplikace a migrace (milník 11, v0.11.0)

Aplikační databáze `app.db` (SQLite) drží relace, analýzy, uživatele,
tokeny, audit, exekuce a uložené dotazy. Schéma vlastní Alembic –
revize v `opsai/db/migrations/versions/` (cestují ve wheelu i balíčcích).

## Revize

| Revize | Obsah |
|---|---|
| `0001` | baseline: všechny tabulky ve finálním tvaru + audit + triggery |
| `0002` | `saved_queries`, `query_history` (FR-163) |

## Chování `init_app_db`

- Spravovaná DB (`alembic_version`) → `upgrade head`.
- Čerstvá DB → `upgrade head` (revize 0001→0002).
- Pre-Alembic DB → jednorázový legacy doběh (`SCHEMA` + sloupce),
  pak `stamp head`. Data zůstávají.
- `AuditWriter` tabulky pro audit i nadále sám dohojuje
  (`IF NOT EXISTS`), migrace jsou primární vlastník.

Pomocné funkce v `opsai/app/bootstrap.py`: `migrate_app_db`,
`downgrade_app_db`, `stamp_app_db`, `current_revision`.

## Nová revize (postup)

1. Zkopíruj `0002_saved_queries.py` na `0003_<tema>.py`, vyplň
   `revision`/`down_revision`, neměnné SQL do `upgrade()`/`downgrade()`.
2. Otestuj cyklus `base → head → base → head` (vzor:
   `tests/test_migrations.py`).
3. Revize jsou snapshoty – nikdy needituj vydanou revizi, vždy novou.

Session store (SQLite/DuckDB/PostgreSQL) má vlastní schémata
v `opsai/core/store_backends.py` a Alembic ho nespravuje.

Testy: `tests/test_migrations.py` (fresh, legacy, idempotence,
downgrade cyklus, append-only triggery).
