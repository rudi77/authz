# Redaktionsleitfaden für die authz-Website und den Blog

Dieser Leitfaden beschreibt, wie die öffentliche authz-Dokumentation und der
Blog geschrieben werden. Er übernimmt die Arbeitsweise der agentkit-Website
und passt sie an ein Autorisierungsprodukt an. Ziel ist, dass Leser eine
Zugriffsentscheidung nachvollziehen, die passende Funktion für ihre Anwendung
auswählen und ein Beispiel selbst ausführen können.

## 1. Geltungsbereich und verpflichtende Lektüre

**Lies diesen Leitfaden vollständig, bevor du Inhalte unter `website/`
aktualisierst oder einen Blogbeitrag entwirfst, schreibst oder überarbeitest.**
Er gilt auch für Übersichten, Vorschautexte, Seitentitel, Beschreibungen und
Inhaltsverzeichnisse. Prüfe den fertigen Text anschließend anhand der
Checkliste am Ende.

Die öffentlichen Seiten und Blogbeiträge bleiben **Englisch**, solange der
Auftrag keine andere Sprache verlangt. Dieser Leitfaden und interne Hinweise
sind Deutsch. Namen von Endpunkten, Feldern, Umgebungsvariablen, Reason-Codes
und Dateien bleiben unverändert. Verwende im veröffentlichten Text die
Projektschreibweise `authz`.

Die Leseanweisung ist in der Root-`CLAUDE.md` verankert. Die redaktionellen
Regeln werden nur hier gepflegt.

## 2. Zielgruppe und Erklärhaltung

Schreibe für Entwicklerinnen und Entwickler, die eine Anwendung oder eine
Agent-Runtime bauen und Zugriffe absichern wollen. Sie kennen HTTP, JSON und
eine Programmiersprache, aber nicht unbedingt RBAC-Begriffe, OIDC-Claims oder
die Begriffe *Policy Decision Point* und *Policy Enforcement Point*.

Eine Erklärung beginnt bei einer konkreten Situation: Alice will einen Vertrag
freigeben, ein Agent soll einen Vertrag zusammenfassen, ein Kunde hat ein
Feature nicht gebucht. Erst wenn klar ist, was dabei entschieden wird, folgen
die internen Namen wie `resolve-context`, `effective-permissions` oder
`delegation_revoked`.

Die Leitfrage beim Schreiben lautet: **Was muss der Leser an dieser Stelle
wissen, damit der nächste Schritt verständlich wird?** Beantworte diese Frage
im Text, statt Leser von Begriff zu Begriff zu schicken.

## 3. Schreibstil

### Ton und Wortwahl

- Schreibe sachlich, zugänglich und wie ein Kollege, der einen Ablauf erklärt.
- Verwende konkrete Verben und benenne den handelnden Teil: Die Anwendung
  fragt, authz prüft die Membership, die Runtime sendet das Token.
- Nutze kurze bis mittellange Sätze. Ein längerer Satz ist sinnvoll, wenn er
  einen Zusammenhang erklärt; Kürze ist kein Selbstzweck.
- Entwickle pro Absatz einen Hauptgedanken.
- Nutze direkte Ansprache für Anleitungen und ein zurückhaltendes „we“ für
  gemeinsam durchgeführte Beispiele. Erfinde keine Erlebnisse, Kunden oder
  Messungen.
- Führe Fachbegriffe bei ihrer ersten Verwendung ein: eine Membership als
  Rollen eines Users in einem Tenant, einen Tenant als meist einen Kunden.
- Unterscheide sauber zwischen **Caller** (das Programm, das fragt) und
  **Subject** (der User oder Agent, um den es geht).
- Beschreibe Gründe, Folgen und relevante Grenzen einer Entscheidung.

### Was vermieden werden soll

- Werbesprache wie „enterprise-grade“, „bulletproof“, „zero-trust“ oder
  „seamless“, wenn keine konkrete, belegte Aussage dahintersteht.
- Sicherheitsversprechen ohne Einschränkung: „agents can never misbehave“,
  „fully secure“, „impossible to bypass“. authz schützt nur dort, wo die
  Anwendung die Antwort tatsächlich prüft.
- Selbstlob und Schlussformeln wie „that's all there is to it“.
- Wiederkehrende Gegensatzformeln wie „not X, but Y“. Erkläre Unterschiede
  direkt am Verhalten.
- Ketten aus Abstraktionen („multi-tenant agent-aware fail-closed PDP“) ohne
  vorher eingeführte Begriffe und ein Beispiel.
- Künstlich abgehackte Sätze und rhetorische Fragen mit Kurzantwort.

### Vorher und nachher

**Zu abstrakt:**

> authz provides agent-aware permission intersection with delegation-scoped
> narrowing.

**Erklärend:**

> When an agent works for Alice, authz allows only what both Alice and the
> agent may do. A delegation grant can narrow this further for one run, for
> example to reading contracts for 15 minutes.

## 4. Aufbau einer Erklärung

Als Ausgangspunkt eignet sich diese Reihenfolge:

1. **Situation:** Wer möchte was tun?
2. **Benötigter Begriff:** Welche Idee muss dafür verstanden werden?
3. **Konkreter Ablauf:** Wer fragt wen, mit welchen Daten?
4. **Beispiel:** Request, Befehl oder Code.
5. **Ergebnis:** Welche Antwort kommt zurück, und was bedeutet der Reason-Code?
6. **Folgen und Grenzen:** Kosten, Caching, Vertrauensannahmen.
7. **Weiterführung:** Ein gezielter Link zum nächsten Schritt oder zur Quelle.

Diese Reihenfolge ist eine Hilfe, keine Pflichtgliederung.

## 5. Aufbau der Website-Seiten

| Seitentyp | Leserfrage | Aufbau |
|---|---|---|
| Startseite (`index.html`) | Was ist authz, und wo beginne ich? | Eine Entscheidung erklären, kleinen Einstieg zeigen, passende Vertiefungen anbieten. |
| Einstieg (`get-started.html`) | Wie bekomme ich eine erste Entscheidung? | Service starten, Konsole, Modell anlegen, erste Entscheidung, Python, Agent, Produktion, typische Fehler. |
| Funktionen (`features.html`) | Welche Funktion brauche ich? | Nach Aufgaben gliedern; Zweck, kleines Beispiel, Aktivierung, Grenzen. |
| Architektur (`architecture.html`) | Wie läuft eine Anfrage durch das System? | Einem Request folgen, dann Identitäten, Speicherung, Mehrprozessbetrieb, Code-Karte. |
| Designprinzipien (`principles.html`) | Warum ist es so gebaut? | Entscheidung an einem Beispiel, Gründe und Preis. |

Längere Seiten erhalten ein Inhaltsverzeichnis mit funktionierenden Ankern.
Bestehende Anker bleiben erreichbar, auch wenn Überschriften neu formuliert
werden; andere Seiten verlinken auf sie.

## 6. Aufbau eines Blogbeitrags

Ein Blogbeitrag entwickelt einen Zusammenhang ausführlicher als die
Funktionsübersicht. Er hat eine klare Fragestellung und ein durchgehendes
Beispiel. Bewährtes Gerüst:

1. Präziser Titel ohne Zeitversprechen.
2. Metadaten: Veröffentlichungsdatum, bei Überarbeitung Änderungsdatum,
   geprüfte authz-Version.
3. Einstieg mit konkreter Situation und benanntem Vorwissen.
4. Inhaltsverzeichnis bei längeren Artikeln.
5. Grundmechanismus vollständig erklären.
6. Durchgeführtes Beispiel mit Eingabe, Verarbeitung und tatsächlicher Ausgabe.
7. Vertiefung mit Rückbezug auf das Beispiel.
8. Grenzen konkret benennen.
9. Abschluss mit Erkenntnissen und Links; keine neuen Themen.

[`blog/delegating-access-to-agents.html`](blog/delegating-access-to-agents.html)
zeigt dieses Vorgehen und ist ein Beispiel, keine starre Vorlage.

## 7. Code, Befehle, Tabellen und Diagramme

- Voraussetzungen nennen: Docker, Python-Version, laufender Service, welcher Key.
- **Bash und PowerShell getrennt kennzeichnen**, sobald die Syntax abweicht.
  Unter PowerShell ist `curl` ein Alias für `Invoke-WebRequest`; verwende
  `curl.exe` oder `Invoke-RestMethod`.
- Platzhalter in spitzen Klammern ausdrücklich benennen (`<runtime-key>`).
- Vollständige Beispiele liegen unter `examples/` und werden verlinkt;
  Auszüge werden als Auszug gekennzeichnet.
- Ausgaben nur als beobachtet darstellen, wenn das Beispiel gegen den
  aktuellen Stand ausgeführt wurde. Gekürzte IDs als gekürzt kennzeichnen.
- JSON muss kopierbar sein; schematische Requests als „shortened“ kennzeichnen.
- Unterscheide Admin-Key (`AUTHZ_API_KEYS`, volle Rechte) und Runtime-Key
  (nur Entscheidungen). Beispiele für Anwendungen verwenden Runtime-Keys.
- Diagramme als `<pre class="diagram">` mit Bildunterschrift; Pfeile
  beschriften. Keine Build-Abhängigkeit für Grafiken einführen.

## 8. Sachliche Genauigkeit

Prüfe Aussagen gegen die aktuelle Implementierung, nicht gegen ältere
Dokumente. `README.md`, `CLAUDE.md` und Kommentare können veraltet sein.
Besonders prüfbedürftig sind:

- Standardwerte von Umgebungsvariablen (`authz_service/config.py`);
- welcher Scope einen Endpunkt aufrufen darf (`require_admin`,
  `require_runtime` in den Routern);
- Reason-Codes (`authzkit/rbac/checker.py`, `authzkit/security/delegations.py`);
- ob eine Funktion im HTTP-Service oder nur in der Bibliothek verfügbar ist
  (z. B. ABAC-Bedingungen: derzeit nur eingebettet);
- Unterschiede zwischen SQLite und PostgreSQL (Schema-Erzeugung,
  Signing-Keys);
- Caching und Snapshots gegenüber Live-Prüfung (AgentGuard, SDK-Cache);
- was die Go- und TypeScript-SDKs abdecken.

Verlinke die passende Quelldatei unmittelbar am Abschnitt. Lokale Links sind
relativ; GitHub-Links zeigen auf `main`.

## 9. Arbeitsablauf und Abnahme

### Vor dem Schreiben

1. Diesen Leitfaden und `website/README.md` lesen.
2. Betroffene Seiten samt Links und Vorschautexten lesen.
3. Leserfrage und tragendes Beispiel festlegen.
4. Technische Aussagen am Code prüfen; Beispiele gegen einen laufenden
   Service ausführen.

### Checkliste vor der Abgabe

- [ ] Der Text beantwortet eine konkrete Leserfrage.
- [ ] Fachbegriffe werden eingeführt, bevor sie gebraucht werden.
- [ ] Caller und Subject, Admin- und Runtime-Key werden nicht verwechselt.
- [ ] Kein Sicherheitsversprechen ohne die Bedingung, dass die Anwendung prüft.
- [ ] Beispiele nennen Voraussetzungen, Eingaben, Startbefehl und Ergebnis.
- [ ] Ausgeführte Beispiele sind als beobachtet, nicht ausgeführte (z. B.
  PowerShell ohne Testumgebung) nicht als getestet ausgegeben.
- [ ] Titel, Beschreibung, Inhaltsverzeichnis und Vorschautexte passen
  zusammen (`index.html`, `blog/index.html`).
- [ ] Lokale Links und Anker funktionieren; jede Seite hat genau eine `h1`.
- [ ] Seiten in breiter und schmaler Ansicht geprüft; kein seitlicher Überlauf.
- [ ] Der Abschlussbericht nennt Änderungen, Prüfungen und verbleibende Grenzen.
