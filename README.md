# OpnSenseACME2Exchange

Windows-Tool (WinForms, .NET 10), das das ACME-Zertifikat aus dem **HAProxy der OPNsense** holt und auf **alle Exchange-Server** verteilt. HAProxy und Exchange haben damit immer **dasselbe** Zertifikat, was Extended Protection bei TLS-Bridging voraussetzt.

```
OPNsense-Cluster (ACME-Client → HAProxy)          Exchange-Cluster
  ├─ CARP-Master  ─┐                               ├─ EXCH01  Import → Enable (IIS) → TLS-Prüfung
  └─ Backup       ─┴─ SSH: haproxy.conf, PEM ──►   ├─ EXCH02  …
                      (Failover automatisch)       └─ …
```

## Ablauf eines Laufs

1. **OPNsense-Knoten prüfen**: Alle Knoten werden per SSH angefragt, der CARP-Master kommt zuerst. Ein ausgefallener Knoten wird gemeldet, der Lauf geht über den anderen weiter.
2. **`haproxy.conf` lesen** und den gewählten Abschnitt (Frontend) auswerten: `crt`, `crt-list` (inkl. SNI-Filter), ACL-/Map-Dateien.
3. **Zertifikat bestimmen**: Unter allen PEM-Dateien des Abschnitts gewinnt die, die *alle* Pflichtnamen abdeckt, einen Private Key hat und am längsten gültig ist. Existiert der Abschnitt nicht mehr (z.B. umbenannt), werden alle TLS-Frontends durchsucht.
4. **Prüfen**: Gültigkeit, Namen und Key werden kontrolliert. Hinweise gibt es bei ECDSA-Schlüsseln, fehlender Kette und baldigem Ablauf.
5. **PFX bauen**: Zertifikat, Kette und Key landen nur im Arbeitsspeicher, mit zufälligem Einmal-Passwort. Nichts davon wird auf die Platte geschrieben.
6. **Pro Exchange-Server** (ein Fehler auf einem Server stoppt die anderen nicht):
   - `Get-ExchangeCertificate`: Getauscht wird **nur, wenn das neue Zertifikat wirklich neuer ist**. Ausnahmen: Das aktive Zertifikat deckt den Hostnamen nicht ab (z.B. das selbstsignierte) oder ist abgelaufen.
   - `Import-ExchangeCertificate` und anschließend `Enable-ExchangeCertificate` für die gewählten Dienste.
   - **TLS-Prüfung**: Es wird nachgesehen, welches Zertifikat IIS auf Port 443 tatsächlich ausliefert.
   - Optional werden ersetzte Vorgänger entfernt, aber nur eindeutige: gleicher Name, nicht selbstsigniert, keine fremden Dienste.

## Selbstheilung

| Situation | Reaktion |
|---|---|
| CARP-Master nicht erreichbar | Backup-Knoten wird verwendet, Warnung im Log |
| Mehrere Knoten melden MASTER | Warnung „Split-Brain“ |
| Gewählter HAProxy-Abschnitt existiert nicht mehr | Alle TLS-Frontends werden durchsucht |
| Remote-PowerShell über http scheitert | Automatisch https, die funktionierende URI wird gemerkt |
| Import meldet Fehler, Zertifikat ist aber angekommen | Kein Doppelimport, es geht weiter |
| Transiente Fehler (Abfrage/Aktivieren) | Ein Wiederholungsversuch nach 10 s |
| Zertifikat ist aktiv, IIS liefert aber ein anderes aus | Wird neu gebunden (und optional `iisreset /noforce`) |
| Lauf in GUI und Aufgabenplanung gleichzeitig | Prozessübergreifende Sperre, der zweite Lauf wird abgewiesen |

## Voraussetzungen

- **OPNsense**: ACME-Client mit HAProxy als „Automation“ (das Zertifikat wird an den HAProxy übergeben). SSH aktivieren unter *System → Einstellungen → Verwaltung → Secure Shell*, dort je nach Anmeldung „Root-Login erlauben“ und „Passwort-Login erlauben“, oder einen Key hinterlegen. Benutzer ist `root` oder ein Benutzer mit `sudo` (Option „sudo“). Lesbar sein müssen `/usr/local/etc/haproxy.conf` und `/tmp/haproxy/ssl/*`. Alle Befehle laufen über `/bin/sh -c`, die csh/tcsh-Login-Shell von root ist also egal.
- **Exchange**: Das Konto braucht die Rolle *Organization Management* bzw. *Server Management*. Remote-PowerShell (`http(s)://<server>/PowerShell/`) muss erreichbar sein. Für die optionale `iisreset`-Funktion zusätzlich WinRM 5985 und lokale Adminrechte.
- **Rechner, auf dem das Tool läuft**: Domänenmitglied (für die AD-Abfrage und Kerberos), Windows PowerShell 5.1, bei der Variante *framework-dependent* zusätzlich die .NET 10 Desktop Runtime.
- **ACME-Client**: Für Exchange **RSA** (2048/4096) als Schlüsseltyp wählen. ECDSA unterstützt Exchange nur eingeschränkt.

## Einrichtung

1. **OPNsense**: Beide Cluster-Knoten eintragen, SSH-Anmeldung setzen und **Verbindung testen**. Beim ersten Kontakt wird der SSH-Hostkey zur Bestätigung angezeigt; danach ist er fest hinterlegt (TOFU, strikt).
2. **HAProxy / Zertifikat**: **Einlesen**, das Frontend wählen, den externen Hostnamen (z.B. `mail.domain.de`) und weitere Pflichtnamen (z.B. `autodiscover.domain.de`) angeben, dann **Zertifikat ermitteln**.
3. **Exchange**: **Server aus AD ermitteln**, gewünschte Server aktivieren und **Verbindung testen**. Getestet werden DNS, Ping, Ports, Remote-PowerShell, der Zertifikatsspeicher und das, was IIS tatsächlich ausliefert.
4. **Ausführung**: Erst **Dry-Run**, dann **Jetzt austauschen**. Danach den Auto-Modus aktivieren.

## Auto-Modus

Es gibt zwei Möglichkeiten; bitte **nur eine** davon nutzen:

- **In der GUI**: Einmal täglich zur eingestellten Uhrzeit, solange das Programm läuft (minimiert im Infobereich). Ein verpasster Termin wird am selben Tag nachgeholt.
- **Windows-Aufgabenplanung**: `OpnSenseACME2Exchange.exe --run` (bzw. `--run --dry-run`). Exitcode `0` = OK, `1` = Fehler, `2` = Warnung. Die Aufgabe muss unter einem Konto mit Exchange-Rechten laufen. Unbekannte SSH-Hostkeys werden ohne GUI **nie** akzeptiert.

## Dateien (neben der EXE)

| Datei | Inhalt |
|---|---|
| `config.dat` | Konfiguration, AES-256-GCM-verschlüsselt (Passwörter zusätzlich feldweise) |
| `key.bin` | Master-Key, DPAPI-geschützt (LocalMachine), ACL nur für SYSTEM, Administratoren und den Ersteller |
| `Logs\OpnSenseACME2Exchange_yyyy-MM-dd.log` | Tageslogs, Aufbewahrung einstellbar. Keine Passwörter, Keys oder PFX-Inhalte |

`config.dat` und `key.bin` gehören zusammen und funktionieren nur auf dem Rechner, auf dem sie erstellt wurden.

## Build

```
dotnet build OpnSenseACME2Exchange.sln -c Release
dotnet run --project tests/OpnSenseACME2Exchange.Tests      # Logik-Tests (laufen auch unter Linux)
```

Die gesamte Logik (Parser, Zertifikate, Entscheidung, Engine) liegt in `OpnSenseACME2Exchange.Core` ohne externe Abhängigkeiten. Die GitHub Action baut auf `windows-latest` und erzeugt zwei EXE-Varianten: eine *self-contained* und eine *framework-dependent*.
