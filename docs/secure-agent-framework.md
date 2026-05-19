# Secure Agent Framework — Security-Konzept

Status: v0.1 (Konzept, framework-agnostisch).
Zielgruppe: Architekten, Plattform-Ingenieure und Security-Reviewer, die
LLM-Agenten in Produktion betreiben oder evaluieren.

Dieses Dokument beschreibt **wie man einen Agent sicher betreibt** — als
allgemeines Konzept, unabhängig von einer konkreten Agent-Plattform oder
einem konkreten PDP. Die hier verwendeten Patterns sind aus den
Referenzimplementierungen `authz` (Policy Decision Point) und einer
Enterprise-Agent-Plattform abgeleitet, lassen sich aber auf jede
Architektur übertragen, die LLMs mit Werkzeug- oder Datenzugriff
kombiniert.

Begriffe in diesem Dokument:

| Begriff | Bedeutung |
|---------|-----------|
| **User** | Menschliche Identität, die einen Agenten beauftragt. |
| **Agent** | LLM-gesteuerter Prozess, der im Auftrag eines Users Aktionen ausführt. |
| **Tool / MCP-Tool** | Ausführbare Funktion oder Remote-Endpunkt, den der Agent aufrufen kann. |
| **Tenant** | Isolationsgrenze (Kunde, Workspace, Org). |
| **PDP** | Policy Decision Point — entscheidet ALLOW / DENY. |
| **PEP** | Policy Enforcement Point — setzt die Entscheidung durch. |

---

## 1. Threat Model

Ein Agent ist kein klassischer Service. Er hat drei Eigenschaften, die
das Bedrohungsmodell vom üblichen Web-App-Modell unterscheiden:

1. **Er nimmt Anweisungen aus untrusted content entgegen.** Prompts,
   Dokumente, Tool-Ergebnisse, E-Mails — alles, was der Agent liest,
   kann eine Anweisung enthalten (Prompt Injection).
2. **Er kombiniert Berechtigungen.** Er handelt im Namen eines Users,
   greift aber gleichzeitig auf System-Credentials für Tools zu. Naiv
   implementiert akkumulieren sich diese Rechte zur Summe.
3. **Er läuft autonom über mehrere Schritte.** Eine einzelne falsche
   Tool-Erlaubnis am Anfang hat Konsequenzen für den ganzen Lauf.

Daraus ergeben sich die wichtigsten Angreifermodelle:

| Angreifer | Vektor | Konsequenz ohne Schutz |
|-----------|--------|------------------------|
| **Bösartiger Mandant** | Prompt-Injection im eigenen Workspace | Eskalation auf andere Mandanten |
| **Bösartiger End-User** | Manipuliert Eingaben, um privilegiertere User-Rechte zu nutzen | Privileg-Eskalation innerhalb eines Mandanten |
| **Prompt-Injection von außen** | Inhalte (Dokumente, Tool-Ausgaben, E-Mails) enthalten Instruktionen | Agent ruft destruktive Tools auf, exfiltriert Daten |
| **Kompromittierter Tool-Server** | Manipulierte Tool-Antworten lenken den Agent um | Datenleck, Datenmanipulation |
| **Gestohlener API-Key** | Service-Key wurde geleakt | Beliebige Mandanten-Zugriffe |
| **Veraltete Berechtigungs-Cache** | Recht wurde widerrufen, Snapshot lebt weiter | Aktion läuft trotz Widerruf durch |
| **Operator-Fehler** | Falsche Konfiguration in Prod (Dev-Modus, `*`-CORS, fehlende Migrationen) | Stilles Öffnen der Plattform |
| **Cross-Tenant-Leck über Persistenz** | Pfad-Traversal, geteilte Caches, gemeinsame Verzeichnisse | Daten eines Mandanten in einem anderen sichtbar |

Konkret außerhalb des Scopes dieses Dokuments:
- Transport-Sicherheit (TLS) — Verantwortung des Reverse-Proxy.
- Authentifizierung des End-Users — Verantwortung des IdP.
- Modell-Alignment / RLHF — Verantwortung des LLM-Anbieters.
- Host-OS-Härtung — Verantwortung der Plattform-Infrastruktur.

---

## 2. Architekturprinzipien

Sechs Prinzipien, an denen sich jede konkrete Entscheidung messen lassen
muss. Sie sind nicht alternativ, sondern komplementär.

### 2.1 PDP/PEP-Trennung

Berechtigungs-**Entscheidungen** gehören an einen Ort (PDP), die
**Durchsetzung** an viele Orte (PEPs). Der PDP ist sprach- und
laufzeit-agnostisch, kennt das Permission-Modell und führt das Audit;
die PEPs sind dort, wo Aktionen tatsächlich passieren (HTTP-Handler,
Tool-Gateway, Datei-Resolver, Gateway-Router).

```
+--------+        +------+        +------+
|  User  | ─────▶ | App  | ─────▶ | PDP  |  (RBAC + ABAC + Mandantenmaske)
+--------+        |      | ◀───── |      |
                  | PEPs |   ALLOW / DENY
                  +──┬───+
                     │
                     ▼
                  Tools, Stores, Channels
```

Konsequenz: das LLM und die Tool-Runtime **stellen niemals selbst
Berechtigungs-Annahmen**. Sie konsultieren den PDP (oder einen
preloaded Snapshot, siehe §5).

### 2.2 Fail-closed by default

Jede unklare Situation muss zur Ablehnung führen, nicht zur stillen
Annahme. Konkrete Ausprägungen:

- Fehlende Konfiguration ⇒ Service verweigert den Start oder lehnt
  jeden Request ab. „Permissive“-Verhalten erfordert ein explizites
  Dev-Mode-Flag, niemals implizit.
- Ein Dev-Mode-Flag schaltet sich **automatisch ab**, sobald ein
  echter Tenant/Key konfiguriert ist (vergessene Test-Deployments
  härten sich selbst).
- Cross-Service-Aufruf zum PDP scheitert (Netz, 5xx, Timeout)
  ⇒ ablehnen. **Kein** Fallback auf eine lokale, stale Policy. Eine
  vorübergehende PDP-Störung darf nicht zur impliziten
  Rechte-Eskalation führen.
- Unbekannte Berechtigungsstrings werden **nicht** als „wahrscheinlich
  okay“ interpretiert. Bei Auflistung in Identity-Tokens werden sie
  separat abgelegt (z. B. `attributes.external_permissions`), aber
  nie als gewährt gewertet.
- Schema-Migrationen werden auf produktiven Datenbanken **nicht
  implizit** ausgeführt; nur SQLite o. Ä. darf auto-migrieren.

### 2.3 Least Privilege und Tenant-Isolation

Jede Identität (User, Agent, API-Key, Service-Konto) bekommt den
minimal nötigen Scope:

- **Scoped API-Keys**: getrennte Rollen für `admin` /
  `runtime` / `tenant:<id>`. Der Bootstrap-Admin-Key ist „break glass“,
  kein Daily-Driver.
- **Mandanten-gebundene Keys** werden auf Body-Ebene erneut geprüft
  (nicht nur am Routing-Surface), damit der Key keine fremden
  Mandanten-IDs im Body schmuggeln kann.
- Persistenz wird **per Mandant** geroutet: alle Pfade unter
  `…/tenants/<tenant_id>/…`, Caches und LRU-gepoolte Manager werden
  per `(tenant_id, …)` geschlüsselt — kein impliziter
  Single-User-Cache, der vom nächsten Request übernommen wird.
- Auto-Provisionierung von Mandanten ist standardmäßig aus. Self-Service
  bekommt einen eigenen, audit-vollen Code-Pfad (z. B. Signup-Endpunkt
  mit Verifikation), nicht eine versteckte Default-Verzweigung.

### 2.4 Defense in Depth

Eine Schicht alleine reicht nicht. Eine sichere Agent-Plattform hat
mindestens drei voneinander unabhängige Verteidigungslinien:

1. **Policy-Schicht** (RBAC, ABAC, Mandantenmaske) — entscheidet, was
   überhaupt erlaubt ist.
2. **Cooperative Path/Tool-Scoping** — der Agent kann Tools nur mit
   sanitierten Argumenten aufrufen; Pfade werden gegen den Agent-Root
   aufgelöst; `..`-Traversal wird im Resolver verworfen.
3. **Process-/Syscall-Isolation** — der Tool-Ausführungspfad
   (Subprocess, MCP-Server, Code-Interpreter) läuft in einer Sandbox
   mit eigenem Netz-/FS-/User-Namespace, sodass selbst kompromittierte
   Tools nicht aus der Bahn brechen.

Ohne (1) entscheidet die Policy nichts; ohne (2) genügt eine clevere
Pfadangabe; ohne (3) reicht eine Tool-Implementierung, die selbst nicht
sauber spielt.

### 2.5 Audit ist nicht optional

Jede Verweigerung wird synchron in der gleichen Transaktion wie die
Entscheidung protokolliert. Allow-Logging ist optional, aber sollte in
der Einführungsphase aktiv sein, solange das Berechtigungsmodell
stabilisiert wird. Audit-Logs enthalten Tenant-ID, App-ID, Subject
(User oder Agent), Resource, Action, Reason-Code und Request-ID — aber
**niemals** das Geheimnis selbst (nur ein nicht-sensitives Präfix des
verwendenden Keys).

Audit-Daten haben eine eigene Retention-Policy und werden von einem
Hintergrund-Worker gepflegt; sie sind **nicht** Teil der Operational-Logs.

### 2.6 Eventual Consistency akzeptieren — aber kennen

Snapshots von „effective permissions“ sind eine Latenz-Optimierung; sie
sind per Definition stale. Das bedeutet konkret:

- Ein widerrufenes Recht kann bis zum Ende der TTL noch genutzt werden.
- Ein neu vergebenes Recht ist erst nach Refresh sichtbar.
- **Destruktive oder irreversible Aktionen dürfen niemals aus einem
  Snapshot heraus entschieden werden** — sie laufen über einen
  expliziten Revalidierungs-Pfad zum PDP (siehe §5.3).
- Nach Massen-Änderungen am Berechtigungsmodell muss man langlaufende
  Agent-Laufzeiten bouncen, um Snapshots zu invalidieren.

---

## 3. Identität & Tenancy

### 3.1 Normalisierung am Rand

Externe IdPs (Entra, Cognito, GCP, OIDC-generisch) haben jeweils eigene
Claim-Schemata. Diese Heterogenität wird **am Eingang** in eine
Normalform überführt: ein `IdentityPrincipal` mit
`(provider, issuer, subject, email, claims, ...)`. Alles dahinter
arbeitet mit der Normalform — der PDP sieht keine
provider-spezifischen Felder mehr.

Vorteil: pluggable IdPs ohne Policy-Änderungen, ein Testkorpus für die
Policy, klare Verantwortlichkeit (JWT-Validierung am Edge, nicht im
PDP).

### 3.2 Externe → interne Tenant-Auflösung

Externe IdPs liefern eigene Tenant-IDs (z. B. Entra-Tenant-GUID). Diese
werden via expliziter Mapping-Tabelle auf interne Tenant-IDs
übersetzt. Vorteile:

- Keine impliziten Mandanten-Annahmen aus IdP-Claims.
- Ein Mandant kann mehrere IdPs (oder mehrere Issuer im selben IdP)
  bedienen.
- Mandanten-Onboarding ist ein bewusster Administrationsakt, kein
  Seiteneffekt eines Logins.

### 3.3 Request-Scope statt globaler Zustand

Die aktive Mandanten- und User-Kontext-Information lebt
**request-scoped** (z. B. `ContextVar` in Python, AsyncLocalStorage in
Node). Sie wird vom Auth-Middleware gesetzt und in einem `finally`
gelöscht. Folgen:

- Kein „durchschleifen“ von `user`/`tenant` durch ganze Aufrufketten.
- Hintergrund-Jobs ohne Middleware bekommen explizit einen
  Default-Mandanten (`DEFAULT_TENANT_ID`); sie greifen **nie** auf
  einen „letzten gesehenen“ Kontext zu.
- Cross-Tenant-Leaks durch geteilte Singletons (LRU-Caches,
  Class-Level-State) werden vermieden, indem Caches per Mandant +
  optional User gekeyt werden — niemals global.

### 3.4 Frozen Identity-Objekte

`UserContext`, `TenantContext`, `AgentContext` etc. sind **immutable**
Datenklassen. Updates erzeugen neue Instanzen. Begründung:

- Ein Stack-Frame, der einen Kontext entgegennimmt, kann ihn nicht
  unbemerkt aufweiten.
- Logging und Audit sehen den Wert, der bei Entscheidung galt.
- Tests können Kontexte als Konstanten ablegen, ohne Side-Effects zu
  fürchten.

---

## 4. Autorisierungsmodell

### 4.1 RBAC als Basis, ABAC als optionales Add-on

Berechtigungen sind flache Strings — `<resource>.<action>` oder
`<namespace>.<resource>.<action>` (z. B. `mcp.github.create_issue`).
Rollen sind Bündel von Permissions; Memberships verbinden User mit
Tenant + Rollen.

Empfehlungen:

- Permission-Namen beschreiben, **was** erlaubt ist, nicht **wer** es
  hat (`contracts.read` ja; `admin.contracts.read` nein — `admin` ist
  eine Rolle).
- Rollen haben einen **Scope** (`platform`, `application`, `tenant`,
  `agent`). Der Scope ist Metadatum für die Admin-Oberfläche; die
  Engine prüft ihn nicht inhaltlich — er existiert nur, um zu
  verhindern, dass ein Mensch versehentlich eine Agent-Rolle bekommt.
- ABAC ist optional und läuft **nach** RBAC. Es kodiert Bedingungen,
  die vom konkreten Resource-Kontext abhängen
  („nur während Geschäftszeiten“, „nur eigene Dokumente“).

### 4.2 Die Agent-Intersektions-Regel (Kernpattern)

Wenn das Subject ein Agent ist, gilt:

```
effective = (user_perms ∩ agent_perms) ∩ tenant_mask
```

In Worten: der Agent erhält **nur** Berechtigungen, die sowohl dem
auftraggebenden User als auch der Agent-Rolle gewährt sind, und nur
soweit der Mandanten-Feature-Mask sie freischaltet.

Diese Regel ist die einzige Eigenschaft, die einen Prompt-Injection-
Angriff bezüglich Berechtigungen tragbar macht: **die Blast Radius
eines kompromittierten Agenten ist durch das beschränkt, was der
User direkt selbst könnte.** Ein Agent kann nicht „nach oben
delegieren“. Es gibt insbesondere keinen Pfad „Agent A delegiert an
Agent B“, der den User-Mask umgeht.

Konsequenz für das Design:

- Agent-Rollen haben **maximale** Privilegien für ihren Job; die
  tatsächliche Einschränkung kommt durch den User. Das ist kein Bug,
  sondern entlastet das Mandanten-Admin von Detail-Berechtigungen.
- Critical Actions (z. B. `mcp.github.delete_repo`) werden niemals
  nur in der Agent-Rolle abgelegt. Wenn der User das nicht direkt
  darf, darf es der Agent auch nicht.

### 4.3 Mandanten-Maske als Feature-Gate

Features lassen sich elegant über eine Tenant-Permission-Mask
abbilden:

- Mandant „ACME“ hat das KI-Modul gebucht → Mask enthält `ai.*`.
- Mandant „Globex“ nicht → Mask enthält `ai.*` nicht. Die Rollen
  bleiben gleich; der Mandant ist einfach „nicht freigeschaltet“.

Eine **leere Maske** bedeutet „keine Einschränkung“ (alle Permissions
durchgereicht). Sie bedeutet ausdrücklich **nicht** „alles
verboten“. Das ist ein gefährlicher Default; achte darauf, dass der
Code zwischen „nicht gesetzt“ und „leer“ unterscheidet, falls beides
auftreten kann.

Wichtige UX-Konsequenz: die Engine unterscheidet
`missing_permission` (Rolle reicht nicht) von
`tenant_feature_disabled` (Rolle reicht, aber Mandant ist nicht
freigeschaltet). Erstes ist ein 403; zweites verdient einen
„Upgrade dein Paket“-Hinweis.

### 4.4 Stabile Reason-Codes

Jede Deny-Entscheidung trägt einen stabilen Grund-String. Beispiele:
`tenant_not_active`, `application_not_active`, `no_active_membership`,
`missing_permission`, `tenant_feature_disabled`,
`policy_condition_failed`. Aufrufende Apps bauen ihre UX (403 vs.
Upgrade-Banner vs. „Bitte den Admin fragen“) auf diesen Codes auf,
nicht auf freiem Text.

Diese Codes sind Teil der API-Stabilitätsgarantie; Renames sind
Breaking Changes.

---

## 5. Agent-Laufzeit-Härtung

### 5.1 Vier-Schritt-Pattern pro Agent-Session

Jede Agent-Session folgt strikt diesem Ablauf:

1. **Resolve**: Aus dem User-Token wird der `IdentityPrincipal`
   gewonnen, daraus der `UserContext` (Mandant, Rollen, Permissions).
2. **Preload**: Der PDP wird einmalig nach den
   `effective_permissions` für das `(user, agent)`-Paar gefragt. Das
   ist ein einzelner Round-Trip; das Ergebnis ist ein flaches
   `Set[str]`.
3. **Guard**: Aus dem Set wird ein in-process Guard gebaut
   (`ToolGuard`, `MCPGuard`). Der Guard hat keine Netzkomponente; alle
   Checks im Heißpfad sind reine Set-Membership-Tests.
4. **Enforce**: Bei jedem Tool-Aufruf prüft die Tool-Runtime
   `guard.require(server, action)`. Treffer → Aufruf. Miss →
   `PermissionDeniedError` → wird an das LLM als „tool denied“
   zurückgegeben, damit das Modell einen anderen Weg suchen kann.

Begründung: ein Agent ruft pro Schritt mehrere Tools auf; ohne lokalen
Guard wäre jede Schritt-Latenz von der PDP-Latenz dominiert. Mit
diesem Pattern zahlt man genau einen Round-Trip pro Session plus
optional einen weiteren für Critical Actions (siehe §5.3).

### 5.2 Tool-Palette filtern, nicht prüfen

Vor dem LLM-Aufruf wird die **vollständige** Tool-Liste durch den
Guard gefiltert, **bevor** sie dem Modell als verfügbar präsentiert
wird:

```
tools_for_llm = guard.filter_allowed(tool_catalog)
```

Das Modell „sieht“ nur Tools, die es tatsächlich aufrufen darf. Das
reduziert sowohl die Wahrscheinlichkeit als auch die
Konsequenzen einer Prompt-Injection: der Angreifer kann das Modell
nicht überreden, ein Tool zu rufen, das nicht im Catalog steht.

Für PDPs, die Bulk-Authorize anbieten, ist das in einem einzigen
Round-Trip zu erledigen. Niemals `authorize` in einer Schleife — das
generiert N Round-Trips für ein Problem, das einer ist.

### 5.3 Critical Actions revalidieren

Bestimmte Aktionen sind irreversibel oder schaden außerhalb des
Mandanten. Beispiele: `mcp.github.delete_repo`, `tools.gmail.send`,
`tools.payment.charge`. Diese werden **niemals** aus dem Snapshot
heraus entschieden:

```
guard = AgentGuard(
    ctx,
    critical_actions={"tools.gmail.send", "mcp.github.delete_repo"},
    revalidate=pdp_check,
)
guard.require("tools.gmail", "send")  # lokal + remote
```

Der Revalidierungs-Hook wird **nach** der lokalen Prüfung aufgerufen.
Lokales DENY → kein Remote-Call, schnelle Antwort an das LLM. Lokales
ALLOW + Remote DENY → der Lauf wird unterbrochen (z. B. Rolle wurde
mid-Session widerrufen). Das ist der Korrekturpfad gegen den
„veraltete Snapshot“-Fall.

Pragmatisches Anti-Pattern: **kein `fall_back_on_error`-Flag**.
Wenn der Remote-Check scheitert, ist das **DENY**, nicht „nimm den
lokalen Snapshot“. Die Schwächung des Sicherheitsmodells im Fehlerfall
ist genau die Klasse von Bug, die das ganze Konzept untergräbt.

### 5.4 Tool-Argumente sind untrusted

Der Guard prüft, **dass** das Tool aufgerufen werden darf, nicht
**womit**. Das Tool selbst (oder ein vorgelagerter Sanitizer) muss
die Argumente prüfen — insbesondere:

- Pfad-Argumente werden gegen den Agent-Workspace aufgelöst (siehe
  §6.3); jeder `..`-Anteil wird verworfen.
- IDs werden gegen die Mandanten-Zugehörigkeit geprüft, **nicht** auf
  „existiert in der DB“. Cross-Tenant-Existenz darf nicht zu „Object
  not found“ (das wäre ein Enumeration-Vektor) konfundieren; sie ist
  einfach „404 für diesen Mandanten“.
- Beträge, Limits, Empfänger werden gegen Mandanten-Konfiguration
  geprüft, nicht gegen LLM-Output blind übernommen.

### 5.5 Output ist untrusted

Tool-Ausgaben und Dokumenten-Inhalte landen im Prompt des nächsten
Schritts. Sie können neue Anweisungen enthalten. Mitigationen:

- **Markieren**, was Output ist (z. B. eigener Rollen-Block im
  Chat-Verlauf), damit das Modell Instruktionen aus Daten trennen
  kann. Vollständigen Schutz gibt es nicht — die Maßnahme verschiebt
  die Wahrscheinlichkeitsverteilung.
- Keine sensitiven Geheimnisse in Prompts. Tokens / Keys werden
  serverseitig referenziert, nie in den LLM-Kontext geschrieben.
- Tools, deren Antworten User-kontrollierten Text enthalten, **dürfen
  nicht implizit weitere Aktionen triggern**. Ein „Send Email“ als
  Folge eines „Read Email“ ist ein 2-Schritt-Pfad, nicht ein
  Tool-Aufruf.

---

## 6. Isolation

### 6.1 Mandanten-Isolation auf Persistenz-Ebene

Jedes Persistenz-Artefakt eines Mandanten lebt unter einem
mandantenspezifischen Pfad:

```
${WORK_DIR}/
└── tenants/
    ├── default/
    ├── tenant_a/
    │   ├── conversations/
    │   ├── settings.json.enc
    │   └── users/
    │       └── <user_id>/
    │           └── auth/<provider>.enc
    └── tenant_b/
```

Folgen:

- Stores werden über eine Factory pro Mandant gebaut und nach
  `(tenant_id, …)` gecached. Kein globaler LRU-Cache, der vom
  nächsten Mandanten übernommen wird.
- Ein versehentlich nicht gesetzter Mandanten-Kontext fällt
  deterministisch in `tenants/default/` — und **nicht** in den
  zuletzt bedienten Mandanten.
- Encrypted Token-Stores werden pro `(tenant_id, user_id)`
  geschlüsselt, damit der framework-eigene `AuthManager`-Cache keinen
  User unter einem anderen User impersonieren kann.
- Tenant-IDs werden **vor** jeder Pfad-Interpolation validiert
  (Whitelist-Regex, keine `..`, kein Separator); ein bösartiger
  Tenant-ID-String darf niemals als Pfad-Segment landen.

### 6.2 Mandanten-Routing am Eingang

Eingehende Nachrichten von Channels (Telegram, Web, Teams …) tragen
keine Tenant-ID. Statt sie zu raten oder per Default zu vergeben,
gibt es einen expliziten Recipient-Resolver:

```
channel + sender_id  ─▶  (tenant_id, user_id, default_agent_id)
```

Quellen für den Resolver:

1. **Admin-Konfiguration** (YAML/DB) für service accounts.
2. **Self-Service-Pairing-Code** mit kurzer TTL: User generiert im
   Webportal einen Einmal-Code, gibt ihn im Channel ein, Resolver
   trägt das Mapping ein.

Ein **nicht gemappter Sender** wird mit auditiertem Deny
zurückgewiesen — er kommt nie zu einem Agent, fällt nie in einen
„Default-Mandanten“ und kann keine Daten anderer Mandanten triggern.

### 6.3 Per-(Tenant, Agent)-Workspace

Jeder Agent in einem Mandanten bekommt einen eigenen, beschreibbaren
Workspace:

```
${WORK_DIR}/tenants/${tenant_id}/agents/${agent_id}/workspace/
```

Alle Datei-, Edit- und Such-Tools des Agenten lösen relative Pfade
**gegen diesen Workspace** auf. Ein `../`-Anteil wird im Resolver
verworfen (kooperative Schicht). Wenn der Agent-Kontext fehlt (System-
Job), fällt der Resolver auf einen tenant-only Workspace zurück, nie
auf den globalen Work-Dir.

Diese kooperative Schicht ist die billige Stufe. Sie schützt gegen
Misskonfiguration und gegen wohlerzogene Tools mit Pfad-Bugs. Sie
schützt **nicht** gegen ein Tool, das selbst `subprocess`,
`open("/etc/...")` oder direkte FS-Calls macht.

### 6.4 Process-/Syscall-Sandbox für Tool-Ausführung

Für echten Schutz vor bösartigen oder kompromittierten Tools muss der
Tool-Ausführungspfad in einer Sandbox laufen, die das Host-OS schützt:

- Container/Microcontainer (gVisor, Firecracker) mit eigenem
  PID-/Net-/User-Namespace.
- Read-only Root-FS; nur der Agent-Workspace ist beschreibbar
  ge-bind-mounted.
- Egress-Netz nur gegen freigegebene Endpunkte; Egress-Proxy mit
  Allow-List für DNS-Namen.
- Keine Host-Credentials in der Sandbox; was sie braucht, bekommt sie
  per kurzlebigem, scoped Token reingereicht.
- CPU-/Memory-/Wallclock-Limit pro Tool-Aufruf.

Diese Schicht löst zwei Threats: kompromittiertes Tool und „der Agent
ruft `bash` und macht damit was er will“.

### 6.5 Daten-Isolation in geteilten Backends

Wo Daten in einer geteilten DB liegen (Postgres, Vector-Store,
Memory-Store), gelten zwei Regeln:

1. **Jeder Query hat `tenant_id` als Pflichtfeld in der `WHERE`-Klausel**.
   Repository-Code, der den Mandanten nicht aus dem Request-Kontext
   liest, ist ein Code-Review-Blocker.
2. **Cross-Tenant-Existenz darf nicht leaken**. Ein
   `GET /users/<id>` für einen User aus einem anderen Mandanten gibt
   `404`, nicht `403` — Letzteres würde bestätigen, dass die ID
   existiert.

Stärker: Row-Level Security (RLS) in der DB, sodass auch ein Bug im
Repository-Code keinen Cross-Tenant-Read verursachen kann.

---

## 7. Schlüssel-, Geheimnis- und Token-Management

### 7.1 API-Keys für Service-zu-Service

- 32-Byte zufällig (`secrets.token_urlsafe`), prefixed mit einem
  kurzen, **nicht-geheimen** Identifier.
- **SHA-256-Hash at rest**, nie der Klartext.
- Vergleich mit `hmac.compare_digest`; die Lookup-Schleife läuft mit
  konstanter Anzahl Iterationen, damit Timing nicht über
  Prefix-Matches leakt.
- Scopes (`admin`, `runtime`, `tenant:<id>`) sind Pflicht; ein
  All-Power-Key ist ein Anti-Pattern.
- Rotation: neuer Key wird parallel ausgegeben, alter bleibt aktiv,
  bis alle Konsumenten umgestellt sind, dann widerrufen. **Nie**
  widerrufen, bevor der neue Key überall live ist.
- `last_used_at`-Tracking; Stale-Key-Reports laufen periodisch.
- Im Audit erscheint nur das `key_prefix`, nie der volle Key.

### 7.2 User-Tokens (JWT)

- Signaturalgorithmus mindestens HS256 mit hinreichend langem Secret
  (≥ 32 Byte zufällig), besser RS256/EdDSA mit Schlüsselrotation.
- Claims: `sub`, `tenant_id`, `email`, `roles`, `iat`, `exp`,
  `iss`. Kein direktes Aufnehmen von Permission-Strings — Rollen
  werden zur Laufzeit zu Permissions aufgelöst, damit
  Berechtigungs-Änderungen sofort wirken (statt erst beim
  Token-Refresh).
- `exp` kurz halten (z. B. 60 min); Refresh-Tokens separat verwalten.
- `validate_token` **lädt nach erfolgreicher Signaturprüfung den
  User-Datensatz nach**: deaktivierte Accounts dürfen mit
  nicht-abgelaufenem Token nicht durchkommen.

### 7.3 Passwort-Hashing

- bcrypt mit Cost ≥ 12 in Produktion (oder Argon2id mit aktuellen
  Parametern). Test-Cost (z. B. 4) wird über eine Umgebungsvariable
  gesetzt, damit Tests schnell laufen, aber Prod nicht versehentlich
  schwach wird.
- Login-Failures geben **immer** den gleichen 401 zurück, ohne
  Unterscheidung „User unbekannt“ vs. „Passwort falsch“. Im
  Audit-Log sind die beiden Fälle separat (für interne
  Untersuchung), aber im HTTP-Response nicht.

### 7.4 OAuth-Tokens / Provider-Credentials

- Verschlüsselt at rest, pro `(tenant, user)` geschlüsselt — nie in
  einem prozessweiten Cache, der vom nächsten Request übernommen wird.
- Refresh-Logik kapselt den Klartext-Token; aufrufender Code bekommt
  nur Ergebnis-Calls, niemals den Token selbst.
- Bei Mandantenlöschung: Tokens werden zuerst widerrufen
  (Provider-API), dann lokal gelöscht. Nicht umgekehrt.

### 7.5 Einladungs- und Pairing-Tokens

- 32-Byte zufällig, gehasht at rest, **single-use** (markierte als
  konsumiert beim ersten Accept), kurze TTL.
- Niemals direkt in Log-Zeilen oder Fehlermeldungen.

### 7.6 Keine eigene Krypto

Krypto-Primitive (HMAC, AEAD, KDF) kommen aus der Standard-Library
oder etablierten Drittbibliotheken. „Wir machen das mal eben“ ist
nicht akzeptabel.

---

## 8. Beobachtbarkeit & Limits

Sicherheit braucht Telemetrie, sonst merkt man Angriffe nicht.

### 8.1 Strukturierte Logs

- Pro Request: `request_id`, `tenant_id`, `user_id` (oder
  `agent_id`), `key_prefix`, Pfad, Status, Latenz, Reason-Code bei
  Deny.
- Kein voller API-Key, kein User-Passwort, kein Token. Schwarze
  Listen sind unzuverlässig; sicherer ist eine Allow-List der zu
  loggenden Felder.

### 8.2 Metriken

Mindest-Metriken:

- `authz_decisions_total{decision,reason}`: Allow- und Deny-Rate, pro
  Grund-Code.
- `authz_decision_latency_seconds`: p50/p95/p99 der PDP-Latenz.
- `authz_decisions_total{decision="error"}`: PDP-Fehler (5xx, Timeout).
  Alert bei jeder dauerhaften Spitze.
- `auth_login_failures_total`: brute-force-Detektion.
- `tenant_isolation_violations_total`: jeder Versuch, einen
  fremden Mandanten zu treffen. Sollte konstant 0 sein. Jeder
  Treffer ist ein Incident.

### 8.3 Rate-Limits und Idempotenz

- Per-Key Rate-Limit (z. B. `requests/min`), in Multi-Prozess-Setups
  zentral (Redis). Verteidigt gegen runaway clients und billige DoS.
- Idempotency-Keys auf nicht-GET Management-Endpunkten, damit Retries
  keinen doppelten Effekt haben. Idempotency-Cache-Keys **enthalten
  den vollen Credential-Fingerprint**, damit ein Replay mit einem
  anderen Key nicht auf einer alten Antwort landen kann.

### 8.4 Health vs. Readiness

- `/healthz` — der Prozess läuft. Wird vom Orchestrator gepollt.
- `/readyz` — alle Abhängigkeiten erreichbar (DB, Cache, IdP-JWKs
  geladen). Bei Nicht-Ready → Out-of-Pool nehmen, aber Prozess nicht
  killen.

---

## 9. Bereitstellung & Operations

### 9.1 Transport

TLS terminiert am Reverse-Proxy / Ingress. Der Service selbst hört
**nie** ohne TLS auf einer Adresse, die nicht 127.0.0.1 ist. mTLS
zwischen Services, wo es geht.

### 9.2 Container-Härtung

- Non-root-User (UID ≥ 1000), `tini` o. Ä. als PID 1.
- Read-only Root-FS; nur explizit gemountete Pfade beschreibbar.
- Image-Scan in der Pipeline; Updates regelmäßig.
- Keine Build-Secrets im Image. Provisionierung von Geheimnissen
  ausschließlich zur Laufzeit (Vault, K8s Secrets, Cloud KMS).

### 9.3 Schema-Migrationen

- Produktions-Datenbanken werden **nie implizit** migriert. Der
  Service verweigert das Auto-Create für nicht-SQLite-Backends und
  defertiert auf Alembic/Migration-CLI.
- Migration läuft als eigener Schritt in der Pipeline, vor dem Start
  des Service-Containers.
- Schema-Drift wird über ein Self-Check beim Start erkannt; nicht
  gematchtes Schema → fail-closed (Service startet nicht).

### 9.4 Mehrprozess-Setup

Wenn mehrere Service-Instanzen laufen, müssen alle geteilten Zustände
über einen externen Store laufen:

- Rate-Limit-Zähler → Redis.
- Idempotency-Cache → Redis.
- Audit-Sink → DB (synchron für Deny, asynchron für Allow ist
  akzeptabel mit Buffer-Bounds und Drop-Policy).

Niemals in-process Rate-Limits in Mehrprozess-Setups belassen — das
ist effektiv kein Limit.

### 9.5 Dev-Mode kontrolliert

Ein expliziter `DEV_MODE`-Schalter ist akzeptabel, aber:

- Standard ist `false`. Setzen in Prod ist ein Audit-Finding.
- Beim Start mit `DEV_MODE=true` und produktivem DB-URL: **lautes
  Warning im Log**, idealerweise im Health-Endpoint sichtbar.
- Ein erster echter Schlüssel/Tenant in der DB **deaktiviert** den
  Dev-Mode automatisch. Vergessene Test-Deployments härten sich
  selbst.

---

## 10. Audit-Garantien

Konkrete Garantien, die ein sicheres Agent-System bieten sollte:

1. **Jedes DENY wird synchron** mit der Entscheidung in das
   Audit-Log geschrieben. Eine Deny ohne Audit-Zeile ist ein Bug.
2. **ALLOWs sind opt-in** (`AUDIT_ALL=true`); in den ersten Wochen
   eines Rollouts an, danach nach Risiko-Appetit.
3. **Audit-Zeilen enthalten** Tenant-ID, App-ID, Subject (User
   und/oder Agent), Resource, Action, Decision, Reason, Request-ID,
   Key-Prefix. **Nie** das Geheimnis selbst.
4. **Retention ist konfigurierbar** und wird von einem Hintergrund-
   Worker durchgesetzt.
5. **Audit-Logs sind nicht löschbar** außer durch das
   Retention-System; kein Endpoint, der einen einzelnen Eintrag
   entfernen kann.
6. **Audit-Logs sind tenant-scoped lesbar**, damit Mandanten ihre
   eigenen Aktivitäten im Self-Service einsehen können (compliance
   ready).

---

## 11. Anti-Patterns

Eine Liste konkreter Designentscheidungen, die in Reviews fail-closed
abgelehnt werden sollten — alle aus realen Vorfällen abgeleitet:

| Anti-Pattern | Warum schlecht | Stattdessen |
|--------------|----------------|-------------|
| `fall_back_on_error=True` für PDP-Outages | Stille Eskalation auf stale Policy | Fail-closed; loggen; alerten |
| `CORS=*` in Prod | Browser-basierte CSRF/Token-Theft | Allowlist konkreter Origins |
| API-Key in `localStorage` der Admin-UI | XSS-staging | `sessionStorage` + ausdrückliche UI als „dev tool“-Markierung |
| Permission-String parsen, um Rollen zu erschließen | Bricht bei jedem Schema-Change | Permissions sind opake Strings; Rollen auflösen, nicht parsen |
| Cross-Tenant-403 | Bestätigt Existenz fremder IDs | 404 |
| Bootstrap-Key als Daily-Driver | Audit-Log nicht zuordenbar | Per-Konsumenten-Scoped-Keys |
| Globaler LRU-Cache über Mandantengrenzen | Cross-Tenant-Leak | Per-Mandanten gekeyt |
| Tool-Liste an LLM ohne Filterung | Modell kann nicht erlaubte Tools nennen | Liste vor LLM-Aufruf filtern |
| `TypeError` im PDP-Client mit DENY | Versteckt Programmierfehler | Programmierfehler propagieren; nur Netz-/SDK-Fehler werden zu Denies |
| Auto-Create der Schema in Prod | Schema-Drift, Datenverlust | Migration als expliziter Schritt |
| Default-Tenant für unklare Channels | Cross-Tenant-Datenleck | Audited Deny, kein Default-Routing |
| Single-Process Rate-Limit in Multi-Pod | Effektiv kein Limit | Redis-backed |
| Klartext-API-Keys in Logs | Credential-Leak | Nur Prefix loggen |
| Custom-Krypto „weil simpler“ | Klassischer Foot-Gun | Standard-Library |

---

## 12. Reifegrad-Modell

Eine pragmatische Selbsteinschätzung. Eine Plattform sollte sich
nicht in Produktion bewegen, bevor mindestens Level 2 erreicht ist;
Level 3 ist das Ziel für regulierte Mandanten.

| Level | Voraussetzungen |
|-------|-----------------|
| **0 — Demo** | Einzelmandant, lokale Storage, keine Auth. |
| **1 — Internal** | RBAC, JWT, Tenant-Modell, Fail-closed-Defaults, Audit-Deny synchron. |
| **2 — Pilot** | Scoped API-Keys mit Rotation, Tenant-Maske, Agent-Intersektion, ToolGuard, kooperative Path-Scoping, Audit-Retention, Rate-Limits, Mehr-Prozess-fähig. |
| **3 — Production** | Critical-Action-Revalidation, Process-Sandbox für Tools, RLS in geteilter DB, Egress-Allowlist, SCIM, mTLS, observability dashboards + alerts, regelmäßige Pentest-Runde. |
| **4 — Regulated** | FIPS-Mode-Krypto, BYOK, Customer-managed Audit-Export, getrennte Control- und Data-Plane, formale Threat-Modelle pro Tool, Confidential-Compute optional. |

---

## 13. Checkliste vor Go-Live

Eine destillierte Variante, die ein Operator vor jeder Mandanten-
Aufschaltung durchgeht.

**Pflicht:**

- [ ] `DEV_MODE` ist `false`.
- [ ] Scoped API-Keys ausgestellt; Bootstrap-Key widerrufen.
- [ ] CORS-Allowlist mit konkreten Origins.
- [ ] Postgres-Migrationen liefen; Auto-Create ist aus.
- [ ] TLS am Reverse-Proxy, mTLS zwischen Services wenn möglich.
- [ ] Per-Key Rate-Limit konfiguriert; Redis bei Multi-Pod.
- [ ] Admin-UI ist hinter Auth-Proxy **oder** deaktiviert.
- [ ] Tenant-IDs werden per Regex validiert; `..`-Tests im
      Pfad-Resolver grün.
- [ ] Identity-Token-Validierung lädt User nach (deaktiv. Account ≠ erlaubt).
- [ ] PDP-Outage simuliert; Verhalten ist DENY mit Audit-Eintrag.

**Stark empfohlen:**

- [ ] `AUDIT_ALL=true` für die ersten Wochen.
- [ ] Audit-Retention gemäß Compliance-Vorgabe gesetzt.
- [ ] Prometheus-Scrape + Alerts auf `decisions{decision="error"}` und
      `tenant_isolation_violations_total`.
- [ ] Critical-Actions-Liste pro Agent dokumentiert und mit
      Revalidierung verkabelt.
- [ ] Tool-Ausführung in Sandbox (Container o. Ä.).
- [ ] Cache-TTL der PEP-Snapshots auf die akzeptable Stale-Zeit
      gesetzt.
- [ ] Container läuft non-root; Root-FS read-only.
- [ ] Cross-Tenant-Probe-Tests in CI (z. B. Mandanten-A-Key probiert
      Mandanten-B-Aktionen → erwartet 403/404).

**Optional, je nach Umgebung:**

- [ ] OpenTelemetry-Exporter aktiv.
- [ ] BYOK / KMS-managed Crypto.
- [ ] WAF / Bot-Protection vor dem öffentlichen Endpunkt.

---

## 14. Weiterführend

Das Konzept hier ist absichtlich Implementation-agnostisch. Konkrete
Patterns und API-Beispiele finden sich in den Referenzimplementierungen:

- **PDP-Schicht** (RBAC + Agent-Intersection + ABAC + Audit): `authz/`
  in diesem Repo. Insbesondere `docs/concepts.md` (Modell),
  `docs/agents.md` (Intersection-Rule), `docs/tools-and-mcp.md`
  (Guards), `SECURITY.md` (Threat Model + Hardening-Checkliste).
- **PEP-Integration in einer Agent-Plattform** (Mandanten-Routing,
  Per-Tenant-Stores, Per-(Tenant,Agent)-Workspace, Postgres-Identity,
  Encrypted Token-Stores, Channel-Link-Registry):
  `taskforce-enterprise/`. Insbesondere `CLAUDE.md` (Architektur),
  Iter-3 (Gateway-Routing), Iter-4 (Workspace-Scoping).

Beide Implementierungen demonstrieren das Konzept dieses Dokuments
end-to-end; sie sind aber nicht die einzige mögliche Form. Ein PDP
in einer anderen Sprache, eine Agent-Plattform mit anderem
Persistenz-Layer, eine alternative Sandbox-Technologie — alle sind
kompatibel, solange die Prinzipien aus §2 erfüllt sind und die
Patterns aus §5 implementiert werden.
