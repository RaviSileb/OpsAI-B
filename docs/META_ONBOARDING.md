# Meta Model API — onboarding pro variantu B (TBD-101, TBD-102)

Podklady pro krok 1: zprovoznění přístupu k Meta Model API z ČR a rozhodnutí
o Zero Data Retention. Vše ostatní (kód, testy) funguje bez klíče v mock režimu.

## TBD-101: Ověřit funkční přístup z ČR

Vlastník: vlastník projektu. Stav: DONE (2026-11-04, test 5/5 PASS z ČR).

### 1. Registrace a billing

1. Založ účet na https://dev.meta.ai ( Dashboard — `/platform` ).
2. Založ team / organizaci a vyplň billing (platební karta). API je placené
   dle https://dev.meta.ai/docs/pricing-rate-limits
   (Muse Spark 1.25 / 4.25 USD za 1M tokenů in/out, Muse Wonder 4.00 / 20.00).
3. Vytvoř API klíč (`MODEL_API_KEY`) a ulož ho mimo git:
   `export OPSAI_META_API_KEY="..."` (viz `.gitleaks.toml`, klíče do gitu nepatří).
4. Geografická dostupnost: ČR ani EU nejsou na seznamu omezených území
   (https://dev.meta.ai/legal/geographic-use-policy), explicitní seznam
   povolených zemí Meta nepublikuje — funkční dostupnost ověří krok 2.

### 2. Test připojení (FR-208)

Skript v kořeni repozitáře provede kroky testu konektivity proti
`https://api.meta.ai/v1` výhradně se standardní knihovnou Pythonu
(žádné závislosti, žádný venv):

```bash
python3 scripts/test_meta_connection.py --api-key "$OPSAI_META_API_KEY"
```

Kroky: DNS resolve → TCP connect :443 → TLS handshake (verze, platnost
certifikátu) → autentizace `GET /v1/models` → zkušební minimální čtení
(seznam obsahuje `muse-spark-1.3`) → latence. Výsledek je vypsán po krocích,
návratový kód je 0 jen při úspěchu všech kroků.

Selhání kroků 1–3 znamená síťový problém (DNS/proxy/firewall, FR-306:
`HTTPS_PROXY`, vlastní CA bundle). Selhání kroku 4 znamená chybný klíč
nebo neaktivní billing. Detail chyby vypíše skript.

### 3. Akceptační kritérium

- Skript skončí kódem 0 a v seznamu modelů je `muse-spark-1.3`.
- Po splnění lze zapnout živý režim: `OPSAI_AI_LIVE=1` a spustit živé
  kontraktní testy (`pytest tests/test_meta_live.py -m live`).

### 4. Ověřené skutečnosti (živé testy 2026-11-04)

- `GET /v1/models` vrací: `muse-spark-1.1/1.2/1.3`, `muse-wonder-1.0`,
  `muse-spark-1.2-contributor`, `muse-spark-1.3-contributor` plus
  nemodelové `muse-image-1.0`, `muse-voice-transcribe-1.0`, `sam-3.1`.
  Whitelist provideru pouští jen 4 chat modely, contributor modely
  blokuje FR-310.
- Muse Spark/Wonder jsou reasoning modely: reasoning tokeny se počítají
  do `max_tokens` i do fakturace. Triviální dotaz spálí stovky
  reasoning tokenů — proto má analýza rozpočet 8192 tokenů (jinak
  `finish_reason: length` s `content: null`) a provider volitelně
  podporuje `reasoning_effort` (`minimal`–`max`; `none` Meta zamítá).
- `response_format` s `json_schema` a `strict: true` Meta vynucuje;
  schéma `ANALYSIS_JSON_SCHEMA` je striktně kompatibilní
  (`additionalProperties: false`, všechna pole v `required`, enumy
  pro fáze/shelly/rizika/labely). Bez strict si model enumy vymýšlel.
- `muse-wonder-1.0` (preview) je funkční přes stejný endpoint.

## TBD-102: Rozhodnutí o ZDR

Vlastník: vlastník projektu. Stav: OPEN.

- Zero Data Retention je k dispozici pro „qualified accounts", aktivuje ho
  Meta na úrovni organizace přes sales formulář
  (https://dev.meta.ai/help/policies-and-privacy/zero-data-retention).
- Výchozí doba retence bez ZDR není na stránce Meta uvedena — zjistit
  před produkčním nasazením (souvisí s NFR-005, DPIA).
- Bez ohledu na rozhodnutí platí: používat pouze standardní (non-contributor)
  modely — modely `*-contributor` jsou trvale zakázány politikou FR-310,
  protože Meta používá jejich prompty a odpovědi k tréninku. Citlivá data
  navíc chrání maskovací vrstva (FR-320+, `docs/MASKING.md`) před odesláním.
- Rozhodnutí zaznamenej zde: [ ] požádat o ZDR / [ ] ZDR nežádat (důvod, datum).
