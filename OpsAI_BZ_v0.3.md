# OpsAI — Business zadání (BZ)

| Položka | Hodnota |
|---|---|
| Dokument | Business zadání (BZ) |
| Produkt | OpsAI — AI asistent pro analýzu logů a návrh nápravy |
| Verze | 0.3 (návrh k review) |
| Varianta | B — Meta (Meta Model API) |
| Datum | 2026-10-27 |
| Autor | Ivar Beliš |
| Stav | DRAFT — čeká na review |
| Navazující dokument | OpsAI_TZ v0.2 (varianta B) |
| Související varianty | A (OpenAI/Claude/Gemini): https://github.com/RaviSileb/OpsAI-A · C (M365 Copilot): https://github.com/RaviSileb/OpsAI-C |

### Historie změn
| Verze | Datum | Změna |
|---|---|---|
| 0.1 | 2026-10-27 | První návrh |
| 0.2 | 2026-10-27 | Odesílání anonymizovaných dat cloudovým AI providerům povoleno (R-07 uzavřeno). Jazyk UI CZ+EN a formát Markdown potvrzeny (A-01, A-02 → CON-009, CON-010). Odstraněny požadavky na schválení compliance (TBD-012 zrušeno, vlastnictví TBD převedeno na vlastníka produktu). |
| 0.3 | 2026-10-27 | Rozdělení na varianty A/B/C podle AI providerů (samostatné repozitáře). Rozhodnutí o odeslání vždy na uživateli, restricted mode jako volba. Spuštění = schválení, minimalizace dotazů. Audit plného textu payloadu, bez auditu čtení. Whitelist + blacklist modelů, allowlist maskování, normalizace tokenů, zákaz řetězení příkazů mimo allowlist, DPIA před produkcí. Referenční HW doplněn. |

---

## 1. Účel a kontext

### 1.1 Problém
Provozní tým řeší incidenty z logů rozptýlených v mnoha systémech (soubory na serverech, Kafka s logy sbíranými z jiných serverů, Windows Event Log, kontejnery, Kubernetes, Loki, Elasticsearch, Azure Monitor). Dnešní postup:
- ruční přihlašování do více nástrojů a ruční korelace událostí v čase,
- ruční hledání příčiny a sestavování opravných příkazů podle znalostí jednotlivce,
- znalost vyřešených incidentů zůstává v hlavách lidí, ne v systému,
- odesílání logů do veřejných AI služeb ad hoc a bez kontroly obsahu (riziko úniku osobních údajů a tajemství).

### 1.2 Cíl produktu
OpsAI je jeden nástroj, ve kterém uživatel:
1. načte logy z jednoho nebo více zdrojů,
2. vyfiltruje a vyhledá relevantní záznamy,
3. vybrané záznamy po anonymizaci předá zvolenému AI modelu,
4. dostane diagnózu, doporučení a postup opravy jako seznam příkazů,
5. volitelně a se schválením nechá opravné příkazy provést krok po kroku na cílovém serveru, včetně kontroly výstupu každého kroku.

### 1.3 Business cíle a měřítka

| ID | Cíl | Měřítko | Cílová hodnota |
|---|---|---|---|
| G-01 | Zkrátit dobu diagnostiky incidentu | MTTD/MTTR před a po zavedení | [TBD-001: výchozí MTTR a cílové snížení v % \| vlastník produktu] |
| G-02 | Sjednotit přístup k logům | Počet nástrojů, které musí analytik použít pro jeden incident | 1 (OpsAI) pro zdroje v MVP |
| G-03 | Zabránit úniku citlivých dat do AI služeb | Počet incidentů, kdy do LLM odešla nemaskovaná citlivá data | 0 |
| G-04 | Zachovat znalost řešení | Podíl uzavřených analýz uložených ve znalostní bázi | [TBD-002: cílový podíl \| vlastník produktu] |
| G-05 | Zajistit dohledatelnost | Podíl volání LLM a provedených příkazů zapsaných v auditu | 100 % |

---

## 2. Zainteresované strany a role

| Role | Popis | Hlavní zájem |
|---|---|---|
| Vlastník produktu | Ivar Beliš | Rozsah, priority, akceptace |
| Analytik / Ops engineer | Hlavní uživatel, analyzuje logy | Rychlost, přesnost, pohodlí |
| Operátor | Analytik s oprávněním spouštět opravné příkazy | Bezpečné provedení opravy |
| Schvalovatel | Schvaluje spuštění opravných kroků (princip čtyř očí, je-li zapnut) | Kontrola rizika |
| Viewer | Pouze čte výsledky analýz a znalostní bázi | Přehled |
| Administrátor OpsAI | Spravuje uživatele, role, povolené AI providery, zdroje a politiky | Řízení a bezpečnost |
| Bezpečnost (interní) | Dohled nad daty odcházejícími z organizace | Anonymizace, audit |
| Vlastníci zdrojových systémů | Kafka, servery, K8s, Azure | Žádný negativní dopad čtení na jejich systémy |

---

## 3. Rozsah

### 3.1 V rozsahu (MVP)
- Desktopová aplikace pro Windows a Linux, webové GUI a REST API, provoz v Docker kontejneru, víceuživatelský režim.
- Zdroje logů: viz kap. 5.
- Správa připojení a credentials pro každý zdroj.
- Filtrování, fulltext, dynamické filtrování podle obsahu, zvýrazňování výskytů.
- Anonymizace dat před odesláním do AI.
- Volba AI modelu (varianta B): Meta (Meta Model API).
- Výstup analýzy: diagnóza, doporučení, opravné příkazy, ověření, rollback.
- Volitelné řízené spouštění opravných příkazů se schválením a kontrolou výstupu.
- Analytické funkce bez spouštění příkazů (kap. 8).
- Audit všech přístupů ke zdrojům, volání AI a provedených příkazů.
- Znalostní báze vyřešených incidentů.

### 3.2 Fáze 2
Graylog, Splunk, AWS CloudWatch, GCP Cloud Logging, archivy v S3 / Azure Blob, MQTT, NATS, Redis Streams, SQL tabulky, příjem přes HTTP/webhook, Prometheus/Alertmanager jako kontext, zakládání issue v GitLabu/Jiře.

### 3.3 Mimo rozsah
- **RabbitMQ** jako zdroj logů (vyřazeno rozhodnutím vlastníka).
- Lokálně provozované LLM (Ollama, LM Studio, vLLM). Rozhodnutí Q4 = pouze cloudoví provideři. Odesílání anonymizovaných dat do cloudu je povoleno (CON-011).
- Funkce centrálního úložiště logů (dlouhodobá retence, indexace všech logů organizace). OpsAI je analytický nástroj, ne SIEM ani logovací platforma.
- Automatické spouštění oprav bez lidského schválení.
- Mobilní aplikace.

---

## 4. Uživatelské scénáře (high-level)

| ID | Scénář |
|---|---|
| UC-01 | Analytik vybere zdroj (např. Kafka topic s logy z aplikačních serverů), nastaví časové okno a filtr, označí podezřelé záznamy a vyžádá si analýzu. |
| UC-02 | Analytik načte log ze serveru přes SSH: ve vzdáleném souborovém systému vybere soubor, aplikace ho načte a analyzuje. |
| UC-03 | Analytik spojí logy z více zdrojů (Windows Event Log + K8s pod + Kafka) do jedné časové osy a hledá souvislosti. |
| UC-04 | Analytik zkontroluje náhled anonymizovaných dat, zvolí AI providera a model a odešle analýzu. |
| UC-05 | AI vrátí postup opravy pro server uvedený v logu (log přišel přes Kafku z jiného serveru). OpsAI identifikuje cílový server a nabídne odpovídající záznam inventáře hostů (včetně profilu připojení a credentials). |
| UC-06 | Operátor spustí opravu krok po kroku. Každý krok schválí, OpsAI vyhodnotí výstup a při neúspěchu zastaví a nabídne rollback. |
| UC-07 | Analytik uloží výsledek do znalostní báze. Při příštím podobném incidentu OpsAI nabídne dřívější řešení. |
| UC-08 | Administrátor povolí jen vybrané AI providery, nastaví politiku anonymizace a role uživatelů. |
| UC-09 | Bezpečnostní pracovník dohledá v auditu, jaká data a komu byla odeslána a jaké příkazy byly kde spuštěny. |

---

## 5. Zdroje logů

### 5.1 MVP

| ID | Zdroj | Business požadavek na rozsah |
|---|---|---|
| BR-001 | Lokální soubor / upload | Textové logy, komprimované archivy, JSON logy, exporty Windows událostí (.evtx). Výběr jednoho i více souborů. |
| BR-002 | SSH / SFTP | Procházení vzdáleného souborového systému a výběr souboru (souborů). Dále čtení systémového journalu a logů kontejnerů na vzdáleném hostu. Podpora přístupu přes jump host. |
| BR-003 | Apache Kafka | Čtení zpráv z topiců s volbou partition, offsetu nebo časového bodu. **Čtení nesmí měnit offsety konzumentských skupin** (žádný commit). Předpoklad: Kafka obsahuje logy sbírané z jiných serverů. |
| BR-004 | Windows Event Log | Lokálně i vzdáleně. Výběr kanálů (System, Application, Security, vlastní). |
| BR-005 | Syslog příjem | Příjem syslog zpráv po síti pro ad hoc analýzu (dočasný listener). |
| BR-006 | systemd journal | Lokálně a přes SSH. |
| BR-007 | Docker / Podman | Logy kontejnerů lokálně a přes SSH. |
| BR-008 | Kubernetes | Logy podů a kontejnerů, včetně předchozí instance restartovaného kontejneru. K8s události (events) jako kontext. |
| BR-009 | Grafana Loki | Dotazy nad Loki. |
| BR-010 | Elasticsearch / OpenSearch | Dotazy nad indexy. |
| BR-011 | Azure Monitor / Log Analytics | Dotazy nad Log Analytics workspace. |

Všechny požadavky BR-001 až BR-011 mají prioritu **Must**.

Akceptační kritérium (společné): pro každý zdroj lze vytvořit připojení, otestovat ho, načíst záznamy za zvolené časové okno a zobrazit je v jednotném seznamu s časem, zdrojem, hostem, úrovní a zprávou.

### 5.2 Normalizace
| ID | Požadavek | Priorita | Akceptační kritéria |
|---|---|---|---|
| BR-012 | Záznamy ze všech zdrojů se zobrazí v jednotném modelu: čas (sjednocená časová zóna), zdroj, host původu, služba/aplikace, úroveň, zpráva, další pole. | Must | Záznam z Kafky obsahující host původu zobrazí jako host tento server, ne Kafka broker. |
| BR-013 | Víceřádkové události (stack trace) se seskupí do jednoho záznamu. | Must | Java/Python/.NET stack trace se zobrazí jako jedna událost. |
| BR-014 | Host původu se pozná i z obsahu zprávy, pokud chybí v metadatech. | Should | Na vzorku [TBD-003: referenční vzorek logů SPCSS \| vlastník] se host pozná u ≥ 95 % záznamů. |

---

## 6. Autentizace ke zdrojům a správa credentials

| ID | Požadavek | Priorita | Akceptační kritéria |
|---|---|---|---|
| BR-020 | Každý zdroj podporuje metody autentizace, které daný systém v organizaci reálně používá (heslo, klíč, certifikát, token, Kerberos, service principal / managed identity apod.). Úplný výčet podle zdroje je v TZ. | Must | Ke každému zdroji MVP se lze připojit všemi metodami uvedenými v TZ. |
| BR-021 | Credentials se ukládají šifrovaně. Na desktopu v úložišti OS, v serverovém režimu v šifrovaném trezoru aplikace. Volitelně lze použít externí trezor (HashiCorp Vault, Azure Key Vault). | Must | Uložené credentials nejsou čitelné v souborech ani v databázi v otevřené podobě. Hesla se nezobrazují v GUI, logu ani exportu. |
| BR-022 | Uživatel může credentials vytvořit, upravit, otestovat, duplikovat, přejmenovat, smazat a přiřadit k více zdrojům. | Must | Všechny operace dostupné v GUI i API. Test připojení vrátí jasný výsledek a důvod chyby. |
| BR-023 | Credentials mají vlastníka a rozsah sdílení: osobní, sdílené s rolí, sdílené globálně (určí administrátor). | Must | Uživatel bez oprávnění nevidí ani nepoužije cizí credentials. |
| BR-024 | Expirace a rotace: evidence platnosti certifikátů a tokenů s upozorněním před vypršením. | Should | Upozornění [TBD-004: počet dní předem \| admin] před expirací. |
| BR-025 | Import a export definic připojení **bez tajemství** (pro sdílení konfigurace v týmu). | Should | Exportovaný soubor neobsahuje hesla, klíče ani tokeny. |
| BR-026 | Přístupové údaje k AI providerům se spravují stejným mechanismem jako credentials zdrojů. | Must | API klíče AI providerů nejsou uloženy v otevřené podobě. |

---

## 7. Načítání, filtrování a vyhledávání

| ID | Požadavek | Priorita | Akceptační kritéria |
|---|---|---|---|
| BR-030 | Výběr jednoho nebo více logů z jednoho i více zdrojů do jedné analytické relace. | Must | Relace obsahuje záznamy alespoň ze 3 různých typů zdrojů současně. |
| BR-031 | Filtrování už při načítání ze zdroje: časové okno (absolutní i relativní), úroveň, host, služba, text. | Must | Ze zdroje se načtou jen odpovídající záznamy. |
| BR-032 | **Dynamické filtrování podle obsahu**: aplikace z načtených dat sama rozpozná pole a jejich hodnoty a nabídne je jako filtry s počty výskytů. Kliknutím se hodnota zahrne nebo vyloučí. | Must | Po načtení JSON logu jsou k dispozici filtry pro všechna jeho pole. U nestrukturovaného logu se nabídnou rozpoznané vzory (host, úroveň, kód chyby, IP, třída výjimky). |
| BR-033 | **Fulltextové vyhledávání** nad načtenými daty s volbami: rozlišovat velikost písmen, celá slova, regulární výraz, negace. | Must | Vyhledávání nad 1 GB načtených dat vrátí první výsledky do [TBD-005: limit odezvy \| vlastník]. |
| BR-034 | **Zvýraznění všech výskytů** hledaného výrazu. Více současných výrazů, každý jinou barvou. Počet výskytů, přechod na další/předchozí, značky výskytů na posuvníku. | Must | Pět výrazů je zvýrazněno pěti odlišnými barvami. Počítadlo odpovídá skutečnosti. |
| BR-035 | Režim „zobrazit jen shodné“ vs. „zvýraznit ve všech“ s volitelným kontextem ±N řádků kolem shody. | Must | Přepnutí režimu neztratí aktuální filtr. |
| BR-036 | Časový histogram záznamů podle úrovně. Výběr úseku v histogramu filtruje seznam. | Must | Výběr úseku zúží seznam na daný interval. |
| BR-037 | Filtry specifické pro zdroj: Kafka (topic, partition, offset, klíč, hlavičky), Windows (kanál, EventID, provider, úroveň), Kubernetes (namespace, pod, container, label), Azure (workspace, tabulka). | Must | Každý typ filtru funguje pro odpovídající zdroj. |
| BR-038 | Dotazovací řádek pro pokročilé uživatele (kombinace podmínek AND/OR/NOT nad poli a textem). | Should | Dotaz lze uložit a znovu použít. |
| BR-039 | Uložené filtry a dotazy, historie filtrů, sdílení filtrů s týmem. | Should | Uložený filtr se po otevření aplikace obnoví. |
| BR-040 | Sbalení opakujících se záznamů (deduplikace s počtem opakování). | Should | 1000 identických chyb se zobrazí jako 1 řádek ×1000. |
| BR-041 | Live tail (průběžné sledování nových záznamů) s aplikovaným filtrem a zvýrazněním. | Should | Nové záznamy se objeví do [TBD-006: max. zpoždění \| vlastník]. |
| BR-042 | Tabulkové zobrazení strukturovaných logů s volbou sloupců. Formátované zobrazení JSON. | Should | Uživatel zvolí, které sloupce vidí. |
| BR-043 | Ruční extrakce polí z nestrukturovaného textu pomocí vzoru (s AI pomocníkem, viz BR-083). Extrahovaná pole se okamžitě stanou filtrovatelnými. | Could | Po definici vzoru se pole objeví ve filtrech. |
| BR-044 | Kopírování a export vybraných záznamů (text, CSV, JSON). | Must | Export obsahuje přesně vybrané a vyfiltrované záznamy. |
| BR-045 | Limit objemu: jedna relace zvládne až **1 GB** načtených dat. | Must | Relace s 1 GB dat je použitelná na referenčním HW [TBD-007: referenční HW desktop/server \| vlastník]. |

---

## 8. Analytické funkce bez spouštění příkazů

| ID | Funkce | Priorita | Akceptační kritéria |
|---|---|---|---|
| BR-080 | Shlukování záznamů do vzorů (šablon zpráv) s počty a trendem v čase. | Must | Log s 1 M řádků se zredukuje na přehled vzorů. Klik na vzor filtruje záznamy. |
| BR-081 | Detekce anomálií: nové, dosud neviděné vzory a náhlé nárůsty četnosti. | Must | Vzor, který se objeví poprvé, je označen. |
| BR-082 | Korelace napříč zdroji na jedné časové ose. | Must | Události ze 3 zdrojů jsou chronologicky zarovnané s vyznačením zdroje. |
| BR-083 | AI pomocník: z popisu v přirozeném jazyce sestaví filtr, dotaz nebo vzor pro extrakci. | Should | Navržený filtr lze před použitím upravit. |
| BR-084 | Vysvětlení vybraného záznamu nebo vzoru (co znamená, typické příčiny). | Must | Vysvětlení obsahuje míru jistoty. |
| BR-085 | Porovnání dvou časových oken (např. před a po nasazení): nové, zmizelé a zesílené vzory. | Should | Výstup je seznam rozdílů s počty. |
| BR-086 | Šablony analýz pro typické problémy: Kafka (consumer lag, rebalance, ISR), Kubernetes (OOMKilled, CrashLoopBackOff, ImagePull), TLS a certifikáty, plný disk, autentizační chyby, výpadek DNS, timeouty. | Should | Šablona předvyplní filtr a zadání pro AI. |
| BR-087 | Znalostní báze: uložení analýzy (problém, příčina, řešení, příkazy, výsledek). Při nové analýze se nabídnou podobné dřívější případy. | Must | Podobný případ se nabídne, pokud existuje. |
| BR-088 | Záložky a anotace na záznamech a v časové ose. Sdílitelné v týmu. | Should | Anotace je viditelná ostatním členům týmu s oprávněním. |
| BR-089 | Test konektivity a stavu zdrojů (dostupnost, platnost credentials, oprávnění ke čtení). | Must | Test vrátí stav a srozumitelnou příčinu chyby. |
| BR-090 | Statistiky relace: počty podle úrovně, hostu, služby, top chyby. | Must | Statistiky odpovídají aktuálnímu filtru. |
| BR-091 | Kontext z dalších zdrojů k vybrané události (např. K8s events, stav podu) jako doplněk analýzy, pouze čtením. | Could | Kontext je přiložen k zadání pro AI a označen. |

---

## 9. AI analýza

### 9.1 Volba providera a modelu

| ID | Požadavek | Priorita | Akceptační kritéria |
|---|---|---|---|
| BR-100 | Uživatel volí model Meta Model API pro každou analýzu. Lze ho změnit i v rámci jedné relace a analýzu zopakovat jiným modelem. | Must | Stejná sada záznamů jde analyzovat dvěma různými modely a výsledky lze porovnat vedle sebe. |
| BR-101 | Podporovaný provider varianty B: **Meta** (Meta Model API). | Must | K providerovi lze nastavit přístup a spustit analýzu. |
| BR-102 | Administrátor spravuje pro každého providera whitelist povolených a blacklist zakázaných modelů, případně výchozí model podle role. | Must | Model mimo whitelist nebo na blacklistu nelze vybrat ani přes API. |
| BR-103 | Zobrazení odhadu velikosti požadavku (objem dat, tokeny) a případně ceny před odesláním. | Should | Odhad se zobrazí před potvrzením. |
| BR-104 | Evidence spotřeby podle uživatele, providera a modelu. | Should | Report spotřeby za zvolené období. |

### 9.2 Omezení providerů (business dopad)

| Provider | Stav a omezení dle veřejných informací (k 2026-10-27) | Míra jistoty |
|---|---|---|
| Meta | Původní hostované Llama API (public preview) bylo dle sekundárního zdroje ukončeno 6. 7. 2026. Meta nyní nabízí **Meta Model API** (modely Muse) kompatibilní s OpenAI i Anthropic SDK. Dostupnost v EU ani smluvní podmínky pro zpracování dat neověřeny. | střední, viz [TBD-008: ověřit dostupnost Meta Model API v ČR/EU a podmínky zpracování dat \| vlastník] |

Varianta B nepokrývá OpenAI, Claude ani Gemini (varianta A) ani Microsoft 365 Copilot (varianta C).

| ID | Požadavek | Priorita | Akceptační kritéria |
|---|---|---|---|
| BR-106 | Při nedostupnosti modelu lze analýzu přesměrovat na jiný povolený model providera (ručně, nebo dle nastavení automaticky). | Should | Výpadek modelu neztratí připravená data analýzy. |

Poznámka: BR-105 (adaptace pro M365 Copilot) se ve variantě B nepoužije, je popsána ve variantě C.

### 9.3 Ochrana dat odesílaných do AI

| ID | Požadavek | Priorita | Akceptační kritéria |
|---|---|---|---|
| BR-110 | **Rozhodnutí o odeslání je vždy plně na uživateli.** Před odesláním vidí náhled payloadu, výsledek maskování a varování o riziku úniku citlivých dat. Odeslání s nálezy je povoleno po explicitním potvrzení. Režim **restricted mode** (nastavení administrátora) potvrzení s nálezy blokuje. | Must | Bez restricted mode lze po varování odeslat. Se zapnutým restricted mode odeslání s nálezy neprojde. Ověřeno testem. |
| BR-111 | Maskují se minimálně: IP adresy (v4/v6), e-maily, tokeny, API klíče a tajemství, **hesla**, **uživatelská jména**, rodná čísla. Dále volitelně: hostname, FQDN, URL s parametry, čísla účtů a karet, telefonní čísla, jména osob, vlastní vzory definované administrátorem. Administrátor spravuje **allowlist** hodnot, které se nemaskují (např. systémové účty root, SYSTEM). | Must | Na testovací sadě [TBD-010: testovací sada citlivých dat \| vlastník] je recall maskování ≥ [TBD-011: cílová hodnota \| vlastník]. Hodnota z allowlistu se nemaskuje. |
| BR-112 | Maskování je **konzistentní a vratné lokálně**: stejná hodnota dostane v rámci analýzy stejný zástupný token (např. <<HOST_003>>). Mapa záměn neopouští OpsAI. Doporučené příkazy se po návratu z AI lokálně doplní skutečnými hodnotami. | Must | Příkaz vrácený AI pro <<HOST_003>> se uživateli zobrazí se skutečným hostname. Mapa záměn není součástí žádného požadavku na AI. |
| BR-113 | Volba rozsahu odesílaných dat: (a) celé anonymizované záznamy, (b) **pouze zprávy (message/payload)** bez metadat, (c) jen vzory s počty a vybrané vzorky. Text payloadu lze před odesláním zkrátit a editovat; po editaci se maskování a náhled přepočítají. | Must | Uživatel volbu vidí a mění před odesláním. Admin může varianty omezit. |
| BR-114 | **Náhled odchozích dat** před odesláním: přesně to, co odejde, se zvýrazněnými maskovanými místy. | Must | Náhled je bajtově shodný s odesílaným obsahem. |
| BR-115 | Uživatel může před odesláním ručně doplnit maskování konkrétního výrazu. | Should | Ručně označený výraz je maskován ve všech výskytech. |

### 9.4 Výstup analýzy

| ID | Požadavek | Priorita | Akceptační kritéria |
|---|---|---|---|
| BR-120 | Výstup obsahuje: shrnutí problému, pravděpodobné příčiny seřazené podle pravděpodobnosti s mírou jistoty, odkazy na záznamy, které je dokládají, doporučení a **postup opravy jako číslovaný seznam příkazů**. | Must | Každá příčina má míru jistoty a odkaz na doklad v logu. |
| BR-121 | Každý příkaz má: cílový systém (host/cluster), typ prostředí (bash, PowerShell, kubectl, Kafka CLI, Azure CLI…), účel, **úroveň rizika** (read-only / změnový / destruktivní), očekávaný výsledek, způsob ověření a rollback. | Must | Žádný příkaz nemá prázdné pole riziko, cíl ani ověření. |
| BR-122 | **Cíl opravy se určuje z hostu původu záznamu**, ne ze zdroje, odkud byl log načten. U logů z Kafky je cílem server uvedený v logu. | Must | Pro záznam z Kafky s hostem `app-srv-12` je cílem příkazu `app-srv-12`. |
| BR-123 | Diagnostické (read-only) příkazy jsou v postupu odlišeny od změnových a předcházejí jim. | Must | Postup začíná ověřovacími kroky. |
| BR-124 | Doplňující dotazy: uživatel může na výsledek reagovat a zpřesnit ho (konverzace nad analýzou). | Must | Kontext relace je zachován a nová data jsou opět anonymizována. |
| BR-125 | Export výsledku: Markdown, PDF, JSON. | Must | Export obsahuje skutečné hodnoty (po lokálním doplnění) jen pokud to uživatel zvolí. Výchozí je maskovaná verze. |
| BR-126 | Hodnocení výsledku uživatelem (pomohlo / nepomohlo / částečně) pro znalostní bázi a srovnání modelů. | Should | Hodnocení se ukládá k analýze a modelu. |

---

## 10. Řízené spouštění opravných příkazů

Princip: OpsAI je ve výchozím stavu **read-only**. Spouštění je volitelný modul, který zapíná administrátor a smí ho používat jen role Operátor. Primárním výstupem je zobrazený postup opravy; jeho částečná nebo plná exekuce je navazující akce. Platí **spuštění = schválení**: jedno potvrzení krok spustí, dodatečné dotazy jsou minimalizovány.

| ID | Požadavek | Priorita | Akceptační kritéria |
|---|---|---|---|
| BR-140 | Modul spouštění je ve výchozí instalaci vypnutý. | Must | Čistá instalace neumí spustit žádný příkaz. |
| BR-141 | Spouštění **postupně, krok po kroku**, volitelně **běh celého zbytku postupu** bez dalších dotazů (zastaví se při selhání, nálezu politiky nebo nutné volbě). **Spuštění = schválení**: jedno potvrzení krok spustí. Uživatel (Operátor) je hlavním schvalovatelem a může příkaz upravit před schválením i po něm. | Must | Bez kliknutí na spuštění se nic neprovede. Všechny verze příkazu se zalogují. |
| BR-142 | Volitelný **princip čtyř očí** (formální záznam): změnové a destruktivní kroky schvaluje druhá osoba (Schvalovatel) jedním potvrzením „Schválit a spustit". Úpravy příkazu žadatelem schválení neruší, všechny verze se logují. | Should | Schválení a jeho autor jsou zaznamenáni v běhu. |
| BR-143 | **Kontrola výstupu** každého kroku: návratový kód, výstup, porovnání s očekávaným výsledkem. Volitelně vyhodnocení výstupu AI (po anonymizaci). | Must | Neočekávaný výsledek kroku zastaví postup. |
| BR-144 | Při selhání: zastavit, zobrazit výstup, nabídnout rollback předchozích kroků (rollback opět krok po kroku se schválením). | Must | Rollback nelze spustit bez schválení. |
| BR-145 | **Určení cílového serveru**: host z logu se spáruje se záznamem inventáře hostů (inventář → SSH/WinRM/K8s kontext + credentials). Cíl (host, prostředí, účet) je zobrazen přímo v prvku pro spuštění, bez separátních dialogů. Pokud záznam neexistuje, nabídne se jeho vytvoření. | Must | Krok se nespustí na hostu, který nebyl zobrazen v potvrzení spuštění. |
| BR-146 | Režim „suchý běh“: zobrazení přesně toho, co bude provedeno, kde a pod jakým účtem, bez provedení. | Must | Suchý běh nic nemění na cíli. |
| BR-147 | Politiky: seznam zakázaných příkazů a vzorů (např. mazání dat, restart produkčních clusterů), omezení na prostředí (dev/test/prod), časová okna. Řetězení příkazů (`;`, `&&`, `$()`, backticky) je zakázáno mimo explicitně povolené vzory. Deny list je best-effort; hlavní obranou je lidské schválení a klasifikace rizika. | Must | Zakázaný příkaz nelze spustit. |
| BR-148 | Časový limit kroku a možnost přerušení běžícího kroku. | Must | Přerušení je zalogováno. |
| BR-149 | Úplný záznam běhu: kdo, kdy, kde, jaký příkaz, kdo schválil, výstup, výsledek. | Must | Záznam je v auditu a u analýzy. |

---

## 11. Uživatelé, role, audit

| ID | Požadavek | Priorita | Akceptační kritéria |
|---|---|---|---|
| BR-160 | Víceuživatelský režim s rolemi Viewer, Analytik, Operátor, Schvalovatel, Administrátor. | Must | Oprávnění rolí odpovídají kap. 2. |
| BR-161 | Přihlášení: lokální účty a podnikové SSO (OIDC — Entra ID, Keycloak). Volitelně LDAP/AD. | Must | Uživatel se přihlásí podnikovým účtem. |
| BR-162 | Oprávnění k jednotlivým zdrojům a připojením podle rolí nebo skupin. | Must | Uživatel vidí jen přidělené zdroje. |
| BR-163 | **Audit (vždy zapnutý)**: odeslání dat do AI (provider, model, objem, hash obsahu, **plný text odeslaného payloadu**, uživatel), výsledky, spouštění příkazů, změny konfigurace a credentials. Čtení ze zdrojů se neaudituje. Audit čte a spravuje administrátor (samostatná role auditora se nezavádí). | Must | Audit nelze vypnout. Záznamy jsou chráněny proti změně. |
| BR-164 | Export auditu pro bezpečnostní dohled (např. do centrálního logování). | Should | Audit lze předávat do externího systému. |
| BR-165 | Desktop v režimu jednoho uživatele se může připojit k serverové instanci a sdílet zdroje, znalostní bázi a audit. | Should | Analýza z desktopu je vidět v serverové instanci. |

---

## 12. Nefunkční požadavky (business úroveň)

| ID | Požadavek | Priorita | Akceptační kritéria |
|---|---|---|---|
| NFR-001 | Čtení ze zdrojů nesmí měnit stav zdroje (žádný commit offsetů v Kafce, žádné mazání ani posun čtecích pozic). | Must | Ověřeno testem na každém zdroji. |
| NFR-002 | Zátěž zdrojů: čtení musí být omezitelné (rychlost, objem), aby nezatěžovalo produkční systémy. | Must | Administrátor nastaví limity podle zdroje. |
| NFR-003 | Výkon: relace do 1 GB, viz BR-045 a BR-033. | Must | Viz [TBD-005], [TBD-007]. |
| NFR-004 | Bezpečnost: šifrovaná komunikace se zdroji i AI providery, šifrované uložení credentials, princip nejmenších oprávnění. | Must | Bezpečnostní review před nasazením. |
| NFR-005 | Ochrana osobních údajů: zpracování v souladu s GDPR (minimalizace dat odcházejících mimo OpsAI). Před produkčním nasazením proběhne jednorázové DPIA. | Must | Splněny BR-110 až BR-115 a NFR-009. DPIA je dokončeno před prvním produkčním nasazením. Samostatné průběžné schvalování compliance se nevyžaduje. |
| NFR-006 | Dostupnost serverové instance: [TBD-013: cílová dostupnost \| vlastník]. | Should | — |
| NFR-007 | Lokalizace UI: čeština a angličtina. | Must | Celé UI je dostupné v obou jazycích, přepínatelné za běhu (CON-009). |
| NFR-008 | Použitelnost: hlavní scénář UC-01 zvládne nový analytik bez školení do [TBD-014: čas \| vlastník]. | Should | Uživatelský test. |
| NFR-009 | Retence uložených analýz a auditu: [TBD-015: doba retence \| vlastník]. | Must | — |
| NFR-010 | Přenositelnost konfigurace mezi desktopem a serverem. | Should | Viz BR-025. |

---

## 13. Omezení (constraints)

| ID | Omezení | Zdroj rozhodnutí |
|---|---|---|
| CON-001 | Cílové platformy: Windows desktop, Linux desktop, webové GUI, REST API, Docker kontejner. Varianta pro více uživatelů. | Q1 |
| CON-002 | Implementace v Pythonu. GUI framework **NiceGUI**: jeden kód pro nativní (desktop) i webový režim. | Q2 = b |
| CON-003 | Provozní model: desktop pro jednoho uživatele + Docker server pro více uživatelů s rolemi. | Q3 = a |
| CON-004 | Varianta B: pouze Meta Model API. Lokální LLM mimo rozsah. | Q4 = b, rozdělení v0.3 |
| CON-005 | Úložiště credentials: OS keyring (desktop), šifrovaný trezor (server), volitelně HashiCorp Vault / Azure Key Vault. | Q6 = a |
| CON-006 | Interní použití. Z organizace odcházejí pouze anonymizovaná data (případně jen zprávy). Audit trvale zapnut. | Q11 |
| CON-009 | Jazyk UI: čeština a angličtina. | Q13 |
| CON-010 | Projektová dokumentace ve formátu Markdown. | Q14 |
| CON-011 | Odesílání anonymizovaných dat cloudovým AI providerům (CON-004) je povoleno. Schvalování compliance se nevyžaduje. | Rozhodnutí vlastníka |
| CON-007 | RabbitMQ není podporovaný zdroj. | Rozhodnutí vlastníka |
| CON-008 | Maximální objem dat v relaci 1 GB. | Q12 |

Poznámka: CON-009 až CON-011 byly doplněny ve v0.2, původní číslování je zachováno.

---

## 14. Rizika

| ID | Riziko | Pravděpodobnost | Dopad | Opatření |
|---|---|---|---|---|
| R-01 | AI navrhne chybný nebo škodlivý příkaz (halucinace). Jde o prokázanou vlastnost LLM. | vysoká | vysoký | BR-121, BR-123, BR-141, BR-146, BR-147. Deny list je best-effort; hlavní obranou je lidské schválení a klasifikace rizika. |
| R-02 | Únik citlivých dat přes nedokonalé maskování (žádná regex/NER metoda nemá 100% recall). | střední | vysoký | BR-110 až BR-115, náhled, testovací sada, audit. |
| R-03 | Záměna cílového serveru (stejné hostname v různých prostředích, chybná identifikace hostu z logu). | střední | vysoký | BR-145 (potvrzení cíle), oddělení prostředí v inventáři. |
| R-04 | Zátěž produkčních zdrojů při čtení velkých objemů. | střední | střední | NFR-002. |
| R-05 | Kompromitace OpsAI = přístup k credentials mnoha systémů. | nízká | velmi vysoký | NFR-004, RBAC, externí trezor, audit. |
| R-06 | Změna nebo ukončení Meta Model API (Llama API bylo dle sekundárního zdroje ukončeno), neověřená dostupnost v EU a smluvní podmínky. | vysoká | střední | Vrstva providerů vyměnitelná, BR-106, TBD-008. |
| R-07 | ~~Zákaz odesílání dat do cloudu~~ — **uzavřeno**: odesílání povoleno (CON-011). Zbytkové riziko: výpadek providera Meta. | nízká | střední | BR-106, funkce z kap. 8 fungují bez AI. |
| R-09 | Kontext modelu nepojme 1 GB dat. Analýza tedy pracuje jen se vzorky nebo vzory, takže příčina mimo vzorek může zůstat neodhalena. | vysoká | střední | BR-113 (c), BR-080, uživatel vidí, co bylo odesláno. |

Poznámka: R-08 (rizika M365 Copilot) se ve variantě B nepoužije, je popsán ve variantě C.

---

## 15. Předpoklady

| ID | Předpoklad |
|---|---|
| A-03 | Logy v Kafce obsahují identifikaci hostu původu (pole nebo text zprávy). |
| A-04 | Organizace má smluvní vztah s vybranými AI providery, který umožňuje zpracování anonymizovaných provozních dat. |
| A-05 | Pro spouštění oprav existuje síťová dostupnost OpsAI k cílovým serverům (SSH/WinRM/K8s API). |

---

## 16. Slovník

| Pojem | Význam |
|---|---|
| Relace | Pracovní prostor s načtenými záznamy, filtry a analýzami |
| Host původu | Server, kde log vznikl (může se lišit od zdroje, odkud byl načten) |
| Vzor | Šablona zprávy po odstranění proměnných částí |
| Anonymizace / maskování | Nahrazení citlivých hodnot konzistentními zástupnými tokeny |
| Grounding | Ukotvení odpovědi AI v dalších datech (web, M365) |
| MTTD / MTTR | Průměrná doba detekce / opravy incidentu |

---

## 17. Seznam TBD

| ID | Co chybí | Kdo doplní |
|---|---|---|
| TBD-001 | Výchozí MTTR a cílové snížení | vlastník produktu |
| TBD-002 | Cílový podíl analýz ve znalostní bázi | vlastník produktu |
| TBD-003 | Referenční vzorek logů SPCSS | vlastník |
| TBD-004 | Počet dní pro upozornění před expirací credentials | admin |
| TBD-005 | Limit odezvy vyhledávání nad 1 GB | vlastník |
| TBD-006 | Max. zpoždění live tail | vlastník |
| TBD-007 | Referenční HW: notebook (Intel i7-4710MQ 4C/8T, 15 GiB RAM, SSD 234 GB, Ubuntu 24.04) a VPS (2 vCPU, 4 GB RAM, 40 GB disk) — doplněno | vlastník |
| TBD-008 | Dostupnost Meta Model API v ČR/EU a podmínky zpracování dat | vlastník |
| TBD-012 | ~~Příslušné interní předpisy a regulace~~ — zrušeno ve v0.2 (viz Historie změn) | — |
| TBD-010 | Testovací sada citlivých dat | vlastník |
| TBD-011 | Cílový recall maskování | vlastník |
| TBD-013 | Cílová dostupnost serverové instance | vlastník |
| TBD-014 | Čas zvládnutí UC-01 novým uživatelem | vlastník |
| TBD-015 | Doba retence analýz a auditu | vlastník |

---

## Zdroje použité pro kap. 9.2
- Meta: Model API docs — https://dev.meta.ai/docs/overview
- ECORPIT: Llama API sunset (sekundární zdroj, oficiální oznámení neověřeno) — https://ecorpit.com/llama-api-sunset-migrate-third-party-host-cost-2026/
