# Konektory zdrojů logů (milník 3, v0.3.0)

Všechny konektory jsou striktně read-only (TZ FR-001, FR-002): čtou
ze zdroje, nikdy do něj nezapisují. Registrace probíhá přes
`opsai/connectors/registry.py` (`ensure_builtin_connectors()`).

| Konektor | Zdroj | Protokol | Auth |
|---|---|---|---|
| `file` | lokální soubory | čtení souboru | — |
| `journald` | systemd journal | D-Bus / `journalctl` | — |
| `docker` | kontejnery | Docker socket | — |
| `kafka` | topicy | Kafka consumer | PLAINTEXT, SSL, SASL, SASL_SSL |
| `loki` | Loki | LogQL přes HTTP | none, basic, bearer, org-id |
| `elasticsearch` | indexy | `_search` přes HTTP | none, basic, api-key, bearer |
| `syslog` | UDP/TCP listener | RFC3164 / RFC5424 | — |
| `kubernetes` | logy podů | K8s REST API | bearer, client-cert, kubeconfig |
| `windows` | Event Log | WinRM / EvtQuery | NTLM, Kerberos, CredSSP, cert, Basic |
| `azure` | Log Analytics | KQL přes REST | SP secret/cert, MI, CLI, device-code |

Generický push-ingest: `POST /api/v1/sessions/{id}/ingest`
(pro externí shippery a webhooky, viz níže).

## Kafka (`kafka`)

Read-only consumer s unikátní `group.id` pro každé čtení a trvale
vypnutým commitem (`enable.auto.commit=false`, FR-022). Consumer
nikdy nevstupuje do cílové consumer group a na brokeru po něm
nezůstávají žádné committnuté offsety (ověřeno testem proti živému
brokeru).

```python
ConnectionProfile(id="k", name="k", connector_type="kafka", config={
    "bootstrap_servers": "kafka1:9092,kafka2:9092",
    "topic": "app-logs",            # nebo topics: [...] / topic_pattern: regex
    "security_protocol": "SASL_SSL",
    "sasl_mechanism": "SCRAM-SHA-512",
    "sasl_username": "...",         # tajemství patří do credential store
    "sasl_password": "...",
    "max_poll_seconds": 60,
})
```

- `test()` ověří metadata a existenci topiců (AdminClient, jen čtení).
- `browse()` vypíše topicy.
- `read()` podporuje `time_from`/`time_to` (mapováno přes
  `offsets_for_times`), `limit_records`, `limit_bytes`; JSON payloady
  rozbalí `level`/`message`, hlavičky nese jako `header_*`.
- Bez `time_from` čte od začátku (`OFFSET_BEGINNING`, explicitně –
  unset offset by consumer zbytečně posílal pro committnuté offsety).

## Loki (`loki`)

Dotazy LogQL přes `query_range`, pouze GET endpointy.

```python
ConnectionProfile(id="l", name="l", connector_type="loki", config={
    "url": "http://loki:3100",
    "selector": '{job="api"}',      # nebo plné query: '{job="api"} |= "err"'
    "direction": "BACKWARD",        # nebo FORWARD
    "org_id": "tenant-a",           # volitelně X-Scope-OrgID
    "username": "...",              # volitelně basic auth
    "bearer_token": "...",          # volitelně
})
```

- `test()` volá `/ready` a validuje LogQL levným dotazem (`limit=1`).
- `browse()` bez cesty vrátí label names, `browse("job")` hodnoty labelu.
- `read()` stránkuje časovým oknem s ochranou proti duplicitám,
  `ReadQuery.filters["logql"]` připojí další line filtr.
- Mapování: `job/app/service` → service, `host/hostname/instance` →
  host, `level/severity` → level, všechny labely do `label_*`.

## Elasticsearch (`elasticsearch`)

Vyhledávání přes `POST /{index}/_search`, stránkování `search_after`
(žádný scroll kontext na serveru).

```python
ConnectionProfile(id="e", name="e", connector_type="elasticsearch", config={
    "url": "http://elastic:9200",
    "index": "logs-*",
    "query": {"term": {"service.name": "api"}},  # volitelně DSL nebo string
    "timestamp_field": "@timestamp",
    "sort_order": "desc",
    "api_key": "...",               # nebo username/password, bearer_token
})
```

- `test()` ověří `/` (verze) a existenci indexu (`_mapping`).
- `browse()` bez cesty vrátí indexy (bez systémových `.*`),
  `browse("logs-1")` pole mappingu.
- `read()` skládá Query DSL z časového rozsahu + `query` +
  `filters["query_string"]`; řadí `timestamp` + `_doc` tie-breaker
  (stabilní `search_after` bez point-in-time).
- Mapování: `log.level/level/severity` → level,
  `service.name/service/app` → service, `host.name/host/hostname` → host;
  epoch-millis i ISO časová razítka.

## Syslog listener (`syslog`)

Vestavěný UDP/TCP listener (RFC3164 i RFC5424, TCP s oběma framingy
RFC6587: octet-counting i newline). Zprávy ukládá do SQLite spoolu,
ze kterého čte `read()` – spool přežije restart.

```python
ConnectionProfile(id="s", name="s", connector_type="syslog", config={
    "bind": "127.0.0.1",
    "port": 5514,                   # UDP i TCP (nebo udp_port/tcp_port zvlášť)
    "protocols": "both",
    "spool_path": "/var/lib/opsai/syslog.db",
    "max_messages": 100_000,        # ring buffer cap
})
connector = SyslogConnector()
await connector.start_listener(profile)   # typicky při startu aplikace
...
async for batch in connector.read(profile, ReadQuery()):
...
await connector.stop_listener(profile)    # spool soubor zůstává
```

- `test()` hlásí běžící listener, jinak ověří bindovatelnost portů.
- `browse()` vrací statistiky spoolu (total, by_host, by_app, by_severity).
- `read()` čte ze spoolu s `time_from`/`time_to` pushdownem; funguje
  i bez běžícího listeneru (čte přímo soubor).
- RFC3164 čas bez roku dopočítá rok včetně prosinec/leden zlomu;
  facility/severity mapuje na jména (`local4`, `notice`, …).

Poznámka: standardní port 514 vyžaduje root – výchozí 5514 je
neprivilegovaný. Nasazení s privilegovaným portem řeší systemd
socket nebo `setcap`.

## Kubernetes (`kubernetes`)

Čtení logů podů přes K8s REST API, pouze GET (`/version`,
`/api/v1/pods`, `/…/pods/{pod}/log`). Nesleduje (žádný watch/stream),
nevytváří žádné objekty.

```python
ConnectionProfile(id="k8s", name="k8s", connector_type="kubernetes", config={
    "kubeconfig": "~/.kube/config",
    "context": "prod",              # volitelně (jinak current-context)
    "namespace": "shop",
    "selector": "app=api",          # volitelně label selector
    "container": "api",             # volitelně (jinak první kontejner)
    "tail_lines": 5000,
})
# Alternativa bez kubeconfig: api_url + token/token_file + ca_cert.
```

- Podporovaná auth: bearer token (i `tokenFile`), client certifikáty
  (data i cesty), kubeconfig kontexty. Exec pluginy záměrně odmítá
  (nespouští externí příkazy) – použijte statický token.
- `test()` ověří `/version` a list podů.
- `browse()`: `""` → namespacy, `"ns"` → pody, `"ns/pod"` → kontejnery.
- `read()` čte log každého vybraného podu (`timestamps=true`,
  `tailLines`), čas filtruje klientsky; nedostupné pody přeskočí.
- `pod` v configu čte jediný pod bez listování; `previous: true`
  čte předchozí běh kontejneru.

## Windows Event Log (`windows`)

Dva režimy (FR-040/041): `local` přes `EvtQuery` (jen na Windows,
vyžaduje `pip install opsai[windows]`) a `remote` přes WinRM/pypsrp
ze všech platforem.

```python
ConnectionProfile(id="w", name="w", connector_type="windows", config={
    "mode": "remote",
    "host": "srv-win-01",
    "username": "svc_opsai",        # DOMAIN\user nebo user@domain
    "password": "...",              # tajemství patří do credential store
    "auth": "ntlm",                 # kerberos|ntlm|credssp|certificate|basic
    "channel": "Security",
    "levels": [1, 2],               # volitelně 1-5
    "event_ids": [4625],            # volitelně
    "provider": "Microsoft-Windows-Security-Auditing",  # volitelně
    "order": "newest",              # nebo oldest (dopředné stránkování)
})
```

- Transport: HTTPS 5986 výchozí; HTTP 5985 jen s message encryption;
  Basic jen přes HTTPS (vynuceno validací).
- Vzdálený skript se skládá výhradně z typovaných hodnot
  (`Get-WinEvent -FilterHashtable … | ConvertTo-Json`); kanál,
  provider, levely a ID procházejí whitelistem – injekce `;`/`$()`
  neprojde (testováno).
- Stránkování (FR-041): dávky `-MaxEvents` + posun časového okna,
  hranici jistí `(timestamp, RecordId)` tiebreak bez mezer a duplicit.
- Mapování (FR-043): Level 1–5 → Critical/Error/Warning/Information/
  Verbose; Audit Success/Failure z `KeywordsDisplayNames`; message
  z vyrenderovaného textu, fallback EventData; `Computer` → host.
- Chybějící oprávnění hlásí `test()` i `read()` srozumitelně:
  `Access denied: Security` (FR-044).
- Živý test vyžaduje Windows host s WinRM:
  `OPSAI_TEST_WINRM_HOST/USER/PASSWORD` (+ volitelně `SSL`, `AUTH`).

## Azure Monitor (`azure`)

KQL dotazy nad Log Analytics Query API (pouze `POST …/query`, FR-111).

```python
ConnectionProfile(id="a", name="a", connector_type="azure", config={
    "workspace_id": "00000000-…",
    "table": "Syslog",              # nebo raw kql (níže)
    "auth": "client_secret",
    "tenant_id": "…",
    "client_id": "…",
    "client_secret": "…",           # tajemství patří do credential store
})
# Alternativa: "kql": "ContainerLogV2 | where LogMessage contains 'OOM'"
```

- Auth (FR-110, `azure-identity`): service principal se secretem
  i certifikátem, managed identity, workload identity (AKS), Azure CLI,
  device-code (desktop: při prvním volání vrátí návod do prohlížeče,
  po dokončení pokračuje). Cloudy Public/Government/China + custom
  authority/endpoint.
- Šablony KQL pro `Syslog`, `Event`, `ContainerLogV2`, `AppTraces`,
  `AppExceptions`, `AzureDiagnostics`, `KubeEvents`; `browse()`
  vrací tabulky a jejich sloupce.
- Časové okno se posílá jako `timespan` (absolutní rozsah nebo
  24h lookback); při částečném výsledku se okno automaticky půlí
  a dotazuje rekurzivně (FR-112).
- Mapování (FR-113): `TimeGenerated` → ts, `Computer` → host;
  level auto-detekce (`SeverityLevel` AppInsights 0–4 i syslog text,
  `EventLevelName`, `EventLevel` 1–5), přepsatelná přes `level_field`.
- Živý test: `OPSAI_TEST_AZURE_WORKSPACE_ID` + `TENANT_ID`,
  `CLIENT_ID`, `CLIENT_SECRET` service principalu.

## Generický ingest (`POST /sessions/{id}/ingest`)

Push endpoint pro externí shippery, které neumí žádný konektor výše
(webhooky, skripty, Fluent Bit `http` output):

```bash
curl -X POST http://127.0.0.1:8080/api/v1/sessions/$SID/ingest \
  -H 'Content-Type: application/json' -H 'X-Role: operator' \
  -d '{"source": "webhook-1", "records": [
        {"message": "user login failed", "ts": "2026-10-27T10:00:00Z",
         "level": "ERROR", "host": "web-1", "service": "auth",
         "fields": {"user": "bob"}}]}'
```

- Odpověď `{"added": N, "status": "OPEN|TRUNCATED"}` jako `ingest-file`.
- Limity: max 5000 záznamů na request, zpráva do 1 MB, max 100 klíčů
  ve `fields`; `source` je identifikátor `[\w][\w\-.]*`.
- Neplatné `ts` → 422, neznámá session → 404, RBAC `create_session`
  (viewer čte, nezapisuje).
- Záznamy procházejí stejnou normalizací jako konektory
  (`to_log_record`: detekce hosta, mapování levelu).

## Testování

| Test | Zdroj dat |
|---|---|
| `tests/test_kafka.py` (5) | `apache/kafka:3.8.0` v Dockeru, KRaft single-node |
| `tests/test_loki.py` (7) | `grafana/loki:3.3.0` v Dockeru, TSDB single-binary |
| `tests/test_elasticsearch.py` (7) | `elasticsearch:8.15.0`, single-node, security off |
| `tests/test_syslog.py` (7) | localhost UDP/TCP listener, bez Dockeru |
| `tests/test_kubernetes.py` (9) | živý minikube (`busybox` loggen pod) nebo skip |
| `tests/test_windows.py` (14) | stub WinRM transport, XPath/PS buildry, XML parsing; živý WinRM jen s hostem |
| `tests/test_azure.py` (13) | mock Log Analytics API (MockTransport), stub credentials; živý dotaz jen s SP |
| `tests/test_api.py` (+2) | generický ingest, in-memory |
| `tests/containers.py` | helper pro throwaway Docker kontejnery |

Kontejnerové testy se skipnou bez funkčního Dockeru, K8s testy bez
clusteru (`kubectl cluster-info`). Všechny konektory mají i čisté unit
testy mapování bez externích služeb.
