using System.Drawing.Imaging;
using OpnSenseACME2Exchange.Core.Certificates;
using OpnSenseACME2Exchange.Core.Config;
using OpnSenseACME2Exchange.Core.Engine;
using OpnSenseACME2Exchange.Core.Exchange;
using OpnSenseACME2Exchange.Core.Haproxy;
using OpnSenseACME2Exchange.Core.Ipc;
using OpnSenseACME2Exchange.Core.Service;

namespace OpnSenseACME2Exchange.UI;

/// <summary>
/// Screenshot-Modus für die Doku: GUI mit festen Demodaten (example.de, keine echten Namen) füllen,
/// jeden Reiter rendern, als PNG speichern. Kein Dienst, kein Netzwerk.
/// </summary>
partial class MainForm
{
    private static readonly DateTime DemoNow = new(2026, 10, 27, 9, 15, 0);

    public static void RenderScreenshots(string directory)
    {
        Directory.CreateDirectory(directory);
        using var form = new MainForm(demo: true) { StartPosition = FormStartPosition.Manual, Location = new Point(0, 0) };
        form.Show();
        form.LoadDemo();
        Pump();

        var shots = new (TabPage Page, string File)[]
        {
            (form._pageOpn, "01-opnsense.png"),
            (form._pageHaproxy, "02-haproxy-zertifikat.png"),
            (form._pageExchange, "03-exchange-dag-gruppen.png"),
            (form._pageRun, "04-ausfuehrung.png"),
            (form._pageLog, "05-log.png"),
            (form._pageService, "06-dienst.png")
        };
        foreach (var (page, file) in shots)
        {
            form._tabs.SelectedTab = page;
            if (page == form._pageHaproxy && form._lstSections.Items.Count > 0) form._lstSections.SelectedIndex = 0;
            Pump();
            CaptureForm(form, Path.Combine(directory, file));
        }

        using var url = new UrlCheckForm(DemoUrlReport(), recheck: null, acceptHost: null)
            { StartPosition = FormStartPosition.Manual, Location = new Point(0, 0) };
        url.Show();
        Pump();
        CaptureForm(url, Path.Combine(directory, "07-url-pruefung.png"));
        url.Close();
        form._connected = false; // keine Rückfrage beim Schließen
        form.Close();
    }

    private static void Pump()
    {
        for (int i = 0; i < 5; i++) { Application.DoEvents(); Thread.Sleep(60); }
    }

    private static void CaptureForm(Form f, string path)
    {
        f.Refresh();
        using var bmp = new Bitmap(f.Width, f.Height);
        f.DrawToBitmap(bmp, new Rectangle(0, 0, f.Width, f.Height));
        bmp.Save(path, ImageFormat.Png);
    }

    private void LoadDemo()
    {
        var cfg = new AppConfig();
        cfg.OpnSense.Nodes.Add(new OpnSenseNode { Name = "FW01", Host = "fw01.corp.local", HostKeyFingerprint = "SHA256:q3Vt8m1nZ2c0dXJlLWZpbmdlcnByaW50LWZ3MDE" });
        cfg.OpnSense.Nodes.Add(new OpnSenseNode { Name = "FW02", Host = "fw02.corp.local", HostKeyFingerprint = "SHA256:Zm9vYmFyLWZpbmdlcnByaW50LWZ3MDItZGVtbw" });
        cfg.OpnSense.Username = "root";
        cfg.Selection.SectionKey = "frontend 1_HTTPS_frontend";
        cfg.Selection.ExchangeHostname = "mail.example.de";
        cfg.Selection.AdditionalRequiredNames.Add("autodiscover.example.de");
        cfg.Exchange.ServiceIis = true;
        cfg.Exchange.AcceptedUrlHosts.Add("*.corp.local");
        cfg.Auto.Enabled = true;
        cfg.Auto.Time = "03:30";

        ExchangeServerEntry S(string name, string? dag, string site, string cert, string status, string urls, bool edge = false, bool on = true) => new()
        {
            Name = name, Fqdn = name.ToLowerInvariant() + ".corp.local", Dag = dag, Site = site, IsEdge = edge, Enabled = on,
            Version = edge ? "Version 15.2 (Build 1748.10)" : "Version 15.2 (Build 1748.24)",
            PowerShellUri = edge ? null : $"http://{name.ToLowerInvariant()}.corp.local/PowerShell/",
            CurrentCertificate = cert, LastStatus = status, UrlCheckSummary = urls
        };
        const string newCert = "8F3A61C0D29B4E7781A5F0C3B2D9E14A7C6B5D21 bis 24.01.2027";
        cfg.Exchange.Servers.AddRange(new[]
        {
            S("EXCH01", "DAG01", "Rathaus", newCert, "OK – Remote-PowerShell, Zertifikate, TLS 443, URLs", "OK (12 passend, 4 akzeptiert)"),
            S("EXCH02", "DAG01", "Rathaus", newCert, "OK – Remote-PowerShell, Zertifikate, TLS 443, URLs", "OK (12 passend, 4 akzeptiert)"),
            S("EXCH03", "DAG01", "Bauhof", "2C1D9E44A0B7F6631E2A8D5C9B0F7E3A1D4C6B88 bis 05.11.2026", "Warning: Nicht getauscht (URLs)", "1 Abweichung(en) vom Zertifikat"),
            S("EXCH10", null, "Rathaus", newCert, "OK – Remote-PowerShell, Zertifikate, TLS 443, URLs", "OK (14 passend)"),
            S("EDGE01", null, "DMZ", "", "Edge-Transport – deaktiviert", "", edge: true, on: false)
        });
        cfg.Exchange.Servers[3].Dag = null;

        ApplyConfigDto(new ConfigDto
        {
            Config = cfg, HasSshPassword = true, DataDirectory = @"C:\ProgramData\OpnSenseACME2Exchange",
            ServiceAccount = @"CORP\gmsa-acme$", MachineName = "MGMT01"
        });
        _connected = true;
        SetConnectedUi(true);

        foreach (DataGridViewRow row in _gridNodes.Rows)
        {
            var host = Cell(row, "Host");
            if (host.Length == 0) continue;
            row.Cells["Status"].Value = host.StartsWith("fw01")
                ? "erreichbar, CARP Master, OPNsense 26.7.4, HAProxy läuft, Config lesbar"
                : "erreichbar, CARP Backup, OPNsense 26.7.4, HAProxy läuft, Config lesbar";
            row.DefaultCellStyle.BackColor = Color.FromArgb(220, 245, 220);
        }

        // HAProxy
        var parsed = HaproxyConfig.Parse(DemoHaproxy);
        _sections = parsed.Sections.Select(sec => new HaproxySectionDto(sec.Key, sec.Type, sec.Name, sec.Text, sec.TerminatesTls, sec.CanCarryCertificate,
            sec.Hostnames.Concat(sec.Key.Contains("HTTPS") ? new[] { "autodiscover.example.de" } : Array.Empty<string>()).Distinct().ToList())).ToList();
        _lblHaproxySource.Text = "Gelesen von FW01 (fw01.corp.local) um 09:14:52 – 4 Abschnitte, 2 mit TLS-Zertifikat";
        FillSectionList();

        var info = new CertificateInfo("CN=mail.example.de", "CN=R11, O=Let's Encrypt, C=US", "8F3A61C0D29B4E7781A5F0C3B2D9E14A7C6B5D21",
            "04A1", new DateTime(2026, 10, 26, 2, 11, 0), new DateTime(2027, 1, 24, 2, 11, 0),
            new[] { "mail.example.de", "autodiscover.example.de" }, "RSA 4096", true, 1);
        var other = info with { Subject = "CN=www.example.de", Thumbprint = "11AA22BB33CC44DD55EE66FF7788990011223344", DnsNames = new[] { "www.example.de" } };
        _lvCandidates.Items.Clear();
        AddCandidate("/tmp/haproxy/ssl/60f1e2d3c4b5a.pem", other, false, "");
        AddCandidate("/tmp/haproxy/ssl/6a1b2c3d4e5f6.pem", info, true, "SNI: mail.example.de autodiscover.example.de", chosen: true);
        _txtCertInfo.Text = string.Join(Environment.NewLine,
            "GEWÄHLT:     /tmp/haproxy/ssl/6a1b2c3d4e5f6.pem  (von FW01 (fw01.corp.local), frontend 1_HTTPS_frontend)",
            "Subject:     CN=mail.example.de",
            "SAN:         mail.example.de, autodiscover.example.de",
            "Aussteller:  CN=R11, O=Let's Encrypt, C=US",
            "Gültig:      26.10.2026 02:11 – 24.01.2027 02:11  (noch 89 Tage)",
            "Thumbprint:  8F3A61C0D29B4E7781A5F0C3B2D9E14A7C6B5D21   Schlüssel: RSA 4096   Kette: 1 Zwischenzert.");

        // Ausführung
        var run = new RunResult { StartedAt = DemoNow.AddMinutes(-2), DryRun = false, Certificate = info, CertificateSource = "FW01 (fw01.corp.local):/tmp/haproxy/ssl/6a1b2c3d4e5f6.pem" };
        run.Duration = TimeSpan.FromSeconds(48.3);
        run.Servers.Add(new ServerRunResult { Server = "EXCH01", Action = "Zertifikat tauschen", Outcome = ServerOutcome.Ok, Details = "Neues Zertifikat ist neuer (Ablauf 24.01.2027 statt 05.11.2026). Verifiziert." });
        run.Servers.Add(new ServerRunResult { Server = "EXCH02", Action = "Zertifikat tauschen", Outcome = ServerOutcome.Ok, Details = "Neues Zertifikat ist neuer (Ablauf 24.01.2027 statt 05.11.2026). Verifiziert." });
        run.Servers.Add(new ServerRunResult
        {
            Server = "EXCH03", Action = "Nicht getauscht (URLs)", Outcome = ServerOutcome.Warning,
            Details = "Neues Zertifikat ist neuer. URL-Prüfung: 1 Abweichung(en) vom Zertifikat (OWA Extern: webmail.example.de). URLs korrigieren und erneut prüfen – oder Option 'trotz URL-Abweichung tauschen' bzw. Host akzeptieren. ACHTUNG: aktuelles Zertifikat läuft in 9 Tagen ab!",
            UrlFindings = DemoUrlReport().Servers[0].Findings.Where(f => f.Kind != UrlFindingKind.Ok).ToList()
        });
        run.Servers.Add(new ServerRunResult { Server = "EXCH10", Action = "Kein Tausch", Outcome = ServerOutcome.Skipped, Details = "Zertifikat ist bereits installiert und für alle Dienste aktiv." });
        run.Warnings.Add("EXCH03: Tausch wegen URL-Abweichungen zurückgestellt.");
        ShowRun(run, live: false);
        _lblNextRun.Text = "Mi 28.10.2026 03:30";
        _lblLastRun.Text = "27.10.2026 09:13 – Lauf beendet: 2 getauscht, 1 aktuell, 0 simuliert, 1 Warnung, 0 Fehler [manuell von CORP\\admin]";
        _statusNext.Text = "Auto: Mi 28.10.2026 03:30";
        _statusConn.Text = @"Dienst: MGMT01 (CORP\gmsa-acme$)";
        _status.Text = "Lauf beendet: 2 getauscht, 1 aktuell, 0 simuliert, 1 Warnung, 0 Fehler";

        // Log
        _lstLogFiles.Items.Clear();
        _lstLogFiles.Items.Add(new LogFileItem("OpnSenseACME2Exchange_2026-10-27.log", 18_420));
        _lstLogFiles.Items.Add(new LogFileItem("OpnSenseACME2Exchange_2026-10-26.log", 41_877));
        _logFile = "OpnSenseACME2Exchange_2026-10-27.log";
        _txtLog.Text = string.Join(Environment.NewLine,
            "[2026-10-27 09:13:02] INFO  Lauf ausgelöst: manuell von CORP\\admin",
            "[2026-10-27 09:13:02] INFO  AD-Abgleich vor dem Lauf: 5 Server, 0 neu, 0 fehlen.",
            "[2026-10-27 09:13:02] INFO  ══ Durchlauf gestartet ══",
            "[2026-10-27 09:13:04] INFO  HAProxy-Konfiguration von FW01 (fw01.corp.local) gelesen (6214 Zeichen).",
            "[2026-10-27 09:13:05] INFO  Zertifikat gefunden auf FW01 (fw01.corp.local): /tmp/haproxy/ssl/6a1b2c3d4e5f6.pem → CN=mail.example.de | gültig bis 24.01.2027 02:11",
            "[2026-10-27 09:13:05] INFO  Zertifikat OK: CN=mail.example.de | RSA 4096 | SAN: mail.example.de, autodiscover.example.de",
            "[2026-10-27 09:13:12] INFO  [EXCH01] Entscheidung: Zertifikat tauschen – Neues Zertifikat ist neuer (Ablauf 24.01.2027 statt 05.11.2026).",
            "[2026-10-27 09:13:19] INFO  [EXCH01] Importiere Zertifikat 8F3A61C0D29B4E7781A5F0C3B2D9E14A7C6B5D21 …",
            "[2026-10-27 09:13:24] INFO  [EXCH01] Aktiviere 8F3A61C0D29B4E7781A5F0C3B2D9E14A7C6B5D21 für IIS …",
            "[2026-10-27 09:13:27] INFO  [EXCH01] Verifiziert: IIS präsentiert das neue Zertifikat.",
            "[2026-10-27 09:13:41] INFO  [EXCH02] Verifiziert: IIS präsentiert das neue Zertifikat.",
            "[2026-10-27 09:13:46] WARN  [EXCH03] URL OWA Extern: https://webmail.example.de/owa – 'webmail.example.de' ist nicht im Zertifikat (mail.example.de, autodiscover.example.de)",
            "[2026-10-27 09:13:46] WARN  [EXCH03] Tausch wegen URL-Abweichungen zurückgestellt.",
            "[2026-10-27 09:13:50] INFO  [EXCH10] Entscheidung: Kein Tausch – Zertifikat ist bereits installiert und für alle Dienste aktiv.",
            "[2026-10-27 09:13:50] INFO  ══ Lauf beendet: 2 getauscht, 1 aktuell, 0 simuliert, 1 Warnung, 0 Fehler (Dauer 48.3s) ══");

        // Dienst
        _txtServiceHost.Text = ".";
        _lblConn.Text = @"Verbunden mit MGMT01 – Dienstkonto CORP\gmsa-acme$ – Daten C:\ProgramData\OpnSenseACME2Exchange";
        _lblSvcInstalled.Text = @"Running – Konto: CORP\gmsa-acme$ – ""C:\Program Files\OpnSenseACME2Exchange\OpnSenseACME2Exchange.exe"" --service";
        _txtSvcAccount.Text = @"CORP\gmsa-acme$";
        _txtSvcAccess.Text = @"CORP\IT-Admins";
        _btnSvcInstall.Text = "Neu installieren / Konto ändern";
        _txtSvcLog.Text = string.Join(Environment.NewLine,
            "[09:02:11] Install: OK – Dienst installiert und gestartet.",
            @"    Konto: CORP\gmsa-acme$ (S-1-5-21-…)",
            @"    Programm nach C:\Program Files\OpnSenseACME2Exchange\OpnSenseACME2Exchange.exe kopiert.",
            @"    Datenverzeichnis C:\ProgramData\OpnSenseACME2Exchange geschützt (SYSTEM, Administratoren, Dienstkonto).",
            @"    GUI-Zugriff: CORP\admin, CORP\IT-Admins (+ Administratoren erhöht).",
            "    Recht 'Als Dienst anmelden' erteilt.",
            "    Dienst angelegt (automatisch, verzögert; Neustart bei Fehlern).",
            "    Dienst läuft.");
    }

    private void AddCandidate(string path, CertificateInfo info, bool covers, string note, bool chosen = false)
    {
        var item = new ListViewItem(path);
        item.SubItems.Add($"{info.Subject}  [{string.Join(", ", info.DnsNames)}]");
        item.SubItems.Add(info.NotAfter.ToString("dd.MM.yyyy HH:mm"));
        item.SubItems.Add(covers ? "ja" : "nein");
        item.SubItems.Add(note);
        if (chosen) { item.BackColor = Color.FromArgb(220, 245, 220); item.Font = UiKit.BoldFont; }
        _lvCandidates.Items.Add(item);
    }

    private static UrlCheckReport DemoUrlReport()
    {
        var names = new List<string> { "mail.example.de", "autodiscover.example.de" };
        ExchangeServerEntry E(string n) => new() { Name = n, Fqdn = n.ToLowerInvariant() + ".corp.local", Dag = "DAG01" };
        List<ExchangeUrlEntry> U(string server, string ext) => new()
        {
            new("OWA", "Intern", $@"{server}\owa (Default Web Site)", $"https://{server.ToLowerInvariant()}.corp.local/owa"),
            new("OWA", "Extern", $@"{server}\owa (Default Web Site)", $"https://{ext}/owa"),
            new("ECP", "Extern", $@"{server}\ecp (Default Web Site)", $"https://{ext}/ecp"),
            new("EWS", "Extern", $@"{server}\EWS (Default Web Site)", "https://mail.example.de/EWS/Exchange.asmx"),
            new("OAB", "Extern", $@"{server}\OAB (Default Web Site)", "https://mail.example.de/OAB"),
            new("EAS", "Extern", $@"{server}\Microsoft-Server-ActiveSync (Default Web Site)", "https://mail.example.de/Microsoft-Server-ActiveSync"),
            new("MAPI", "Extern", $@"{server}\mapi (Default Web Site)", "https://mail.example.de/mapi"),
            new("OutlookAnywhere", "Extern", $@"{server}\Rpc (Default Web Site)", "mail.example.de"),
            new("Autodiscover", "Intern", server, "https://autodiscover.example.de/Autodiscover/Autodiscover.xml")
        };
        var results = new List<UrlCheckResult>
        {
            UrlChecker.Evaluate(E("EXCH03"), U("EXCH03", "webmail.example.de"), names, new[] { "*.corp.local" }, "mail.example.de", "autodiscover.example.de"),
            UrlChecker.Evaluate(E("EXCH01"), U("EXCH01", "mail.example.de"), names, new[] { "*.corp.local" }, "mail.example.de", "autodiscover.example.de"),
            UrlChecker.Evaluate(E("EXCH02"), U("EXCH02", "mail.example.de"), names, new[] { "*.corp.local" }, "mail.example.de", "autodiscover.example.de")
        };
        UrlChecker.CompareWithinDag(results);
        return new UrlCheckReport(names, "Zertifikat 8F3A61C0D29B4E7781A5F0C3B2D9E14A7C6B5D21 von FW01 (fw01.corp.local) (bis 24.01.2027)", results, new List<string>());
    }

    private const string DemoHaproxy = """
        global
            daemon

        defaults
            timeout client 30s

        # Frontend: HTTPS_frontend (Exchange, OWA, Autodiscover)
        frontend 1_HTTPS_frontend
            bind 0.0.0.0:443 name 0.0.0.0:443 ssl prefer-client-ciphers ssl-min-ver TLSv1.2 alpn h2,http/1.1 crt-list /tmp/haproxy/ssl/6a1b2c3d.certlist
            mode http
            option http-keep-alive
            acl acl_exchange hdr(host) -i mail.example.de autodiscover.example.de
            use_backend exchange_backend if acl_exchange

        # Frontend: Web (Homepage)
        frontend 2_WEB_frontend
            bind 0.0.0.0:8443 ssl crt /tmp/haproxy/ssl/60f1e2d3c4b5a.pem
            mode http
            acl acl_www hdr(host) -i www.example.de
            use_backend web_backend if acl_www

        backend exchange_backend
            mode http
            balance roundrobin
            server exch01 10.10.0.11:443 ssl verify none check
            server exch02 10.10.0.12:443 ssl verify none check
            server exch03 10.10.0.13:443 ssl verify none check
        """;
}
