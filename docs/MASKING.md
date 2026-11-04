# Maskování a pseudonymizace (milník 9, v0.9.0)

Maskovací engine (`opsai/masking/engine.py`, TZ FR-400..408, FR-412..415)
hledá citlivé údaje a nahrazuje je konzistentními tokeny `<<TYPE_NNN>>`
(jedna relace = jedna mapa, `PseudonymMap`). Mapa se nikdy neexportuje
raw – pouze šifrovaná AES-256-GCM (`save_encrypted`).

## Regex detektory (M-01..M-07)

IP adresy, e-maily, hesla, tokeny, uživatelská jména, rodná čísla
(vč. validace) a hostname. Allowlist (`root`, `system`, …) vyhrává
(M-14), překryvy řeší první nález, tokenové úseky se při verifikaci
přeskakují (FR-402).

## Presidio (doplňkové entity)

Volitelný balíček `presidio-analyzer` (extra `pii`, v dev závislostech)
pokrývá mezery regexu – mapuje se jen 5 entit:

| Presidio | Token |
|---|---|
| `PHONE_NUMBER` | `<<PHONE_NNN>>` |
| `CREDIT_CARD` | `<<CARD_NNN>>` |
| `IBAN_CODE` | `<<ACCT_NNN>>` (s validací checksumu) |
| `URL` | `<<URLPARAM_NNN>>` |
| `PERSON` | `<<PERSON_NNN>>` (přes NER model) |

`EMAIL_ADDRESS` a `IP_ADDRESS` zůstávají regexu (přesnější pro logy),
skóre pod 0.35 se zahazuje. Presidio běží v `scan()` až po regexu,
takže při překryvu vyhrává regex (např. `USER` proti `PERSON`).

Režim: `MaskingEngine(presidio=…)` / `OPSAI_PRESIDIO_MODE=auto|on|off`
(výchozí `auto` = použít, je-li nainstalováno). `on` bez balíčku
→ `PresidioUnavailableError` (nahlas, ne tiché zhoršení).
Engine se staví jednou (~2 s model), analýza textu trvá milisekundy.

Pozn.: instalace stahuje spacy model `en-core-web-lg` (~400 MB).

## Kontrola a obnova

- `verify_masked` – rescan maskovaného textu; nálezy mimo tokeny
  musí být prázdné před odesláním AI.
- `depseudonymize` – obnova hodnot, toleruje zmršené tokeny;
  neznámé tokeny blokují exekuci (FR-405).

Testy: `tests/test_masking.py` (regex), `tests/test_presidio.py`.
