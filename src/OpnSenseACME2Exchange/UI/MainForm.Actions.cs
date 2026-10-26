using System.Text;
using OpnSenseACME2Exchange.Core.Certificates;
using OpnSenseACME2Exchange.Core.Config;
using OpnSenseACME2Exchange.Core.Engine;
using OpnSenseACME2Exchange.Core.Exchange;
using OpnSenseACME2Exchange.Core.Haproxy;
using OpnSenseACME2Exchange.Core.Logging;
using OpnSenseACME2Exchange.Core.OpnSense;
using OpnSenseACME2Exchange.Infrastructure;

namespace OpnSenseACME2Exchange.UI;

partial class MainForm
{
    private HaproxyConfig? _haproxy;
    private Dictionary<string, SortedSet<string>> _sectionHosts = new();

    // ───────────────────────── OPNsense ─────────────────────────

    private async Task TestNodesAsync()
    {
        CollectConfig();
        if (_cfg.OpnSense.Nodes.Count == 0)
        {
            MessageBox.Show(this, "Bitte mindestens einen OPNsense-Knoten (Host/IP) eintragen.", "OPNsense",
                MessageBoxButtons.OK, MessageBoxIcon.Information);
            return;
        }

        var cfg = _cfg;
        var statuses = await RunBusyAsync("Teste OPNsense-Knoten", _ =>
        {
            var src = _services.CreateCertificateSource(cfg, ConfirmHostKey, MarkLearned);
            return cfg.OpnSense.Nodes.Select(src.Probe).ToList();
        });
        if (statuses == null) return;

        foreach (DataGridViewRow row in _gridNodes.Rows)
        {
            if (row.Tag is not OpnSenseNode n) continue;
            var st = statuses.FirstOrDefault(s => ReferenceEquals(s.Node, n));
            if (st == null) continue;
            row.Cells["Status"].Value = st.Summary;
            row.Cells["HostKey"].Value = n.HostKeyFingerprint ?? "";
            row.DefaultCellStyle.BackColor = !st.Reachable || st.ConfigReadable == false
                ? Color.FromArgb(250, 215, 215)
                : st.HaproxyRunning == false ? Color.FromArgb(255, 243, 205) : Color.FromArgb(220, 245, 220);
            Log.Info($"OPNsense {n}: {st.Summary}");
        }

        int masters = statuses.Count(s => s.Carp == CarpState.Master);
        _status.Text = $"{statuses.Count(s => s.Reachable)}/{statuses.Count} Knoten erreichbar, CARP-Master: " +
                       (masters == 1 ? statuses.First(s => s.Carp == CarpState.Master).Node.ToString() : masters == 0 ? "keiner" : "MEHRERE!");
        SaveQuiet();
    }

    private void ResetHostKeys()
    {
        var rows = _gridNodes.SelectedRows.Cast<DataGridViewRow>().Where(r => r.Tag is OpnSenseNode).ToList();
        if (rows.Count == 0) return;
        if (MessageBox.Show(this,
                "Gespeicherten SSH-Hostkey der ausgewählten Knoten verwerfen?\n\nNur nötig, wenn die Firewall neu installiert wurde. " +
                "Beim nächsten Verbindungstest wird der neue Key zur Bestätigung angezeigt.",
                "Hostkey zurücksetzen", MessageBoxButtons.YesNo, MessageBoxIcon.Warning) != DialogResult.Yes) return;

        foreach (var r in rows)
        {
            var n = (OpnSenseNode)r.Tag!;
            Log.Warn($"SSH-Hostkey für {n} zurückgesetzt (war {n.HostKeyFingerprint}).");
            n.HostKeyFingerprint = null;
            r.Cells["HostKey"].Value = "";
        }
        SaveQuiet();
    }

    // ───────────────────────── HAProxy ─────────────────────────

    private async Task ReadHaproxyAsync()
    {
        CollectConfig();
        var cfg = _cfg;
        var res = await RunBusyAsync("Lese HAProxy-Konfiguration", _ =>
        {
            var src = _services.CreateCertificateSource(cfg, ConfirmHostKey, MarkLearned);
            var (text, node) = src.ReadHaproxyConfig();
            var parsed = HaproxyConfig.Parse(text);
            var hosts = new Dictionary<string, SortedSet<string>>();
            foreach (var sec in parsed.CertificateSections)
            {
                try { hosts[sec.Key] = src.ReadReferencedHostnames(sec, node); }
                catch (Exception ex)
                {
                    Log.Debug($"Hostnamen für {sec.Key} nicht vollständig lesbar: {Log.Describe(ex)}");
                    hosts[sec.Key] = new SortedSet<string>(sec.Hostnames, StringComparer.OrdinalIgnoreCase);
                }
            }
            return (parsed, node, hosts);
        });
        if (res.parsed == null) return;

        _haproxy = res.parsed;
        _sectionHosts = res.hosts;
        _lblHaproxySource.Text =
            $"Gelesen von {res.node} um {DateTime.Now:HH:mm:ss} – {_haproxy.Sections.Count} Abschnitte, " +
            $"{_haproxy.CertificateSections.Count(s => s.TerminatesTls)} mit TLS-Zertifikat";
        FillSectionList();

        // Vorauswahl: gespeicherter Abschnitt, sonst der, der den Exchange-Hostnamen kennt, sonst erstes TLS-Frontend
        if (_lstSections.SelectedIndex < 0)
        {
            var host = _cmbHostname.Text.Trim();
            var pick = _lstSections.Items.Cast<HaproxySection>()
                           .FirstOrDefault(s => host.Length > 0 && _sectionHosts.TryGetValue(s.Key, out var h) && h.Any(x => HostMatcher.Matches(x, host)))
                       ?? _lstSections.Items.Cast<HaproxySection>().FirstOrDefault(s => s.TerminatesTls);
            if (pick != null) _lstSections.SelectedItem = pick;
        }
        _status.Text = "HAProxy-Konfiguration eingelesen – Abschnitt wählen und 'Zertifikat ermitteln'.";
    }

    private void FillSectionList()
    {
        var selectedKey = (_lstSections.SelectedItem as HaproxySection)?.Key ?? _cfg.Selection.SectionKey;
        _lstSections.BeginUpdate();
        _lstSections.Items.Clear();
        if (_haproxy != null)
        {
            var items = _chkAllSections.Checked ? _haproxy.Sections : _haproxy.CertificateSections.ToList();
            foreach (var s in items) _lstSections.Items.Add(s);
            var match = items.FirstOrDefault(s => s.Key == selectedKey);
            if (match != null) _lstSections.SelectedItem = match;
        }
        _lstSections.EndUpdate();
    }

    private void OnSectionSelected()
    {
        if (_lstSections.SelectedItem is not HaproxySection sec) return;
        _txtSection.Text = sec.Text;

        var current = _cmbHostname.Text;
        _cmbHostname.Items.Clear();
        var hosts = _sectionHosts.TryGetValue(sec.Key, out var h) ? h : sec.Hostnames;
        foreach (var host in hosts.Where(x => !x.StartsWith('.') && !x.StartsWith("*.")))
            _cmbHostname.Items.Add(host);

        if (string.IsNullOrWhiteSpace(current))
        {
            var guess = hosts.FirstOrDefault(x => x.StartsWith("mail.") || x.StartsWith("owa.") || x.StartsWith("exchange."))
                        ?? hosts.FirstOrDefault(x => !x.StartsWith('.') && !x.StartsWith("*."));
            if (guess != null) _cmbHostname.Text = guess;
        }
        else _cmbHostname.Text = current;

        if (string.IsNullOrWhiteSpace(_txtAdditionalNames.Text) && hosts.Any(x => x.StartsWith("autodiscover.")))
            _txtAdditionalNames.Text = hosts.First(x => x.StartsWith("autodiscover."));

        _cfg.Selection.SectionKey = sec.Key;
    }

    private sealed record ResolveView(
        CertificateInfo? Info, string? Node, string? Path, string? Section,
        List<PemCandidate> Candidates, List<string> Warnings, List<string> Errors, CertificateValidator.Result? Validation);

    private async Task ResolveCertificateAsync()
    {
        CollectConfig();
        if (string.IsNullOrWhiteSpace(_cfg.Selection.ExchangeHostname))
        {
            MessageBox.Show(this, "Bitte den externen Exchange-Hostnamen angeben (z.B. mail.domain.de).", "Zertifikat",
                MessageBoxButtons.OK, MessageBoxIcon.Information);
            return;
        }

        var cfg = _cfg;
        var view = await RunBusyAsync("Ermittle Zertifikat", ct =>
        {
            var src = _services.CreateCertificateSource(cfg, ConfirmHostKey, MarkLearned);
            using var r = src.Resolve(cfg.Selection, ct);
            var validation = r.Bundle != null
                ? CertificateValidator.Validate(r.Bundle.Info, OpnSenseCertificateSource.RequiredNames(cfg.Selection), DateTime.Now)
                : null;
            if (r.SourcePath != null) cfg.Selection.LastKnownPemPath = r.SourcePath;
            return new ResolveView(r.Bundle?.Info, r.SourceNode?.ToString(), r.SourcePath, r.SectionKey,
                r.Candidates.ToList(), r.Warnings.ToList(), r.Errors.ToList(), validation);
        });
        if (view == null) return;

        _lvCandidates.BeginUpdate();
        _lvCandidates.Items.Clear();
        foreach (var c in view.Candidates)
        {
            var item = new ListViewItem(c.Path);
            item.SubItems.Add(c.Info != null ? $"{c.Info.Subject}  [{string.Join(", ", c.Info.DnsNames)}]" : "");
            item.SubItems.Add(c.Info != null ? c.Info.NotAfter.ToString("dd.MM.yyyy HH:mm") : "");
            item.SubItems.Add(c.CoversAll ? "ja" : "nein");
            item.SubItems.Add(c.Error ?? (c.SniFilters.Count > 0 ? "SNI: " + string.Join(" ", c.SniFilters) : ""));
            if (c.Path == view.Path) { item.BackColor = Color.FromArgb(220, 245, 220); item.Font = UiKit.BoldFont; }
            else if (c.Error != null) item.ForeColor = Color.Firebrick;
            _lvCandidates.Items.Add(item);
        }
        _lvCandidates.EndUpdate();

        var sb = new StringBuilder();
        if (view.Info != null)
        {
            var i = view.Info;
            sb.AppendLine($"GEWÄHLT:     {view.Path}  (von {view.Node}, {view.Section})");
            sb.AppendLine($"Subject:     {i.Subject}");
            sb.AppendLine($"SAN:         {string.Join(", ", i.DnsNames)}");
            sb.AppendLine($"Aussteller:  {i.Issuer}");
            sb.AppendLine($"Gültig:      {i.NotBefore:dd.MM.yyyy HH:mm} – {i.NotAfter:dd.MM.yyyy HH:mm}  (noch {(i.NotAfter - DateTime.Now).TotalDays:0} Tage)");
            sb.AppendLine($"Thumbprint:  {i.Thumbprint}   Schlüssel: {i.KeyAlgorithm}   Kette: {i.ChainCount} Zwischenzert.");
        }
        foreach (var e in view.Errors) sb.AppendLine("FEHLER:  " + e);
        if (view.Validation != null)
        {
            foreach (var e in view.Validation.Errors) sb.AppendLine("FEHLER:  " + e);
            foreach (var w in view.Validation.Warnings) sb.AppendLine("Hinweis: " + w);
        }
        foreach (var w in view.Warnings) sb.AppendLine("Hinweis: " + w);
        _txtCertInfo.Text = sb.ToString();

        _status.Text = view.Info != null && view.Validation?.Ok == true
            ? $"Zertifikat gefunden: {view.Info.ShortDescription}"
            : "Kein gültiges Zertifikat gefunden – Details siehe unten.";
        SaveQuiet();
    }

    // ───────────────────────── Exchange ─────────────────────────

    private async Task DiscoverServersAsync()
    {
        CollectConfig();
        var e = _cfg.Exchange;
        string? user = e.UseCurrentUser ? null : e.Username;
        string? pw = e.UseCurrentUser ? null : RevealSafe(e.PasswordProtected);

        var found = await RunBusyAsync("Ermittle Exchange-Server aus dem AD", _ => ExchangeAdDiscovery.Discover(user, pw));
        if (found == null) return;

        int added = 0;
        foreach (var d in found)
        {
            var existing = _cfg.Exchange.Servers.FirstOrDefault(s =>
                s.Fqdn.Equals(d.Fqdn, StringComparison.OrdinalIgnoreCase) || s.Name.Equals(d.Name, StringComparison.OrdinalIgnoreCase));
            if (existing == null)
            {
                existing = new ExchangeServerEntry { Enabled = !d.IsEdge, Name = d.Name, Fqdn = d.Fqdn };
                _cfg.Exchange.Servers.Add(existing);
                added++;
                existing.LastStatus = d.IsEdge ? "Edge-Transport – deaktiviert" : "neu ermittelt – bitte Verbindung testen";
            }
            existing.Name = d.Name;
            existing.Fqdn = d.Fqdn;
            existing.Version = d.Version;
            existing.Dag = d.Dag;
            existing.Site = d.Site;
        }
        foreach (var s in _cfg.Exchange.Servers.Where(s => !found.Any(d => d.Fqdn.Equals(s.Fqdn, StringComparison.OrdinalIgnoreCase))))
            s.LastStatus = "nicht (mehr) im AD gefunden";

        BindServersGrid();
        _status.Text = $"{found.Count} Exchange-Server im AD, {added} neu hinzugefügt.";
        SaveQuiet();
    }

    private async Task TestServersAsync()
    {
        CollectConfig();
        var selected = _gridServers.SelectedRows.Cast<DataGridViewRow>()
            .Where(r => !r.IsNewRow && r.Tag is ExchangeServerEntry)
            .Select(r => (ExchangeServerEntry)r.Tag!)
            .ToList();
        var targets = selected.Count > 0 ? selected : _cfg.Exchange.Servers.ToList();
        if (targets.Count == 0)
        {
            MessageBox.Show(this, "Keine Exchange-Server eingetragen – zuerst 'aus AD ermitteln'.", "Exchange",
                MessageBoxButtons.OK, MessageBoxIcon.Information);
            return;
        }

        var cfg = _cfg;
        var host = string.IsNullOrWhiteSpace(cfg.Selection.ExchangeHostname) ? null : cfg.Selection.ExchangeHostname;
        await RunBusyAsync("Teste Exchange-Server", ct =>
        {
            var ops = _services.CreateExchange(cfg, MarkLearned);
            foreach (var s in targets)
            {
                ct.ThrowIfCancellationRequested();
                BeginInvoke(new Action(() => SetServerStatus(s, "teste …")));
                var r = ops.TestConnection(s, host ?? s.Fqdn, ct);
                s.LastStatus = (r.Ok ? "OK – " : "FEHLER – ") + r.Summary;
                BeginInvoke(new Action(() => SetServerStatus(s, s.LastStatus!)));
            }
            return true;
        });

        BindServersGrid();
        SaveQuiet();
    }

    private void SetServerStatus(ExchangeServerEntry s, string status)
    {
        foreach (DataGridViewRow row in _gridServers.Rows)
        {
            if (!ReferenceEquals(row.Tag, s)) continue;
            row.Cells["Status"].Value = status;
            row.Cells["Uri"].Value = s.PowerShellUri ?? "";
            row.Cells["Cert"].Value = s.CurrentCertificate ?? "";
            row.Cells["Version"].Value = s.Version ?? "";
            ColorStatusRow(row, status);
        }
    }

    // ───────────────────────── Ausführung ─────────────────────────

    private async Task StartRunAsync(bool dryRun, bool unattended)
    {
        if (_busy) { if (!unattended) _status.Text = "Bitte warten – es läuft bereits eine Aktion."; return; }
        CollectConfig();

        var problems = new List<string>();
        if (_cfg.OpnSense.Nodes.Count == 0) problems.Add("Keine OPNsense-Knoten eingetragen.");
        if (string.IsNullOrWhiteSpace(_cfg.Selection.ExchangeHostname)) problems.Add("Kein Exchange-Hostname gewählt.");
        if (!_cfg.Exchange.Servers.Any(s => s.Enabled)) problems.Add("Kein Exchange-Server aktiviert.");
        if (string.IsNullOrEmpty(_cfg.Exchange.ServicesString())) problems.Add("Keine Exchange-Dienste ausgewählt.");
        if (problems.Count > 0)
        {
            Log.Warn("Lauf nicht gestartet: " + string.Join(" ", problems));
            if (unattended)
            {
                _cfg.Auto.LastRun = DateTime.Now;
                _cfg.Auto.LastResult = "nicht gestartet: " + string.Join(" ", problems);
                UpdateLastRunLabel();
                SaveQuiet();
            }
            else MessageBox.Show(this, string.Join("\n", problems), "Konfiguration unvollständig", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            return;
        }

        if (!dryRun && !unattended)
        {
            var n = _cfg.Exchange.Servers.Count(s => s.Enabled);
            if (MessageBox.Show(this,
                    $"Zertifikat für {_cfg.Selection.ExchangeHostname} jetzt auf {n} Exchange-Server verteilen?\n\n" +
                    "Getauscht wird nur, wo das OPNsense-Zertifikat wirklich neuer ist.",
                    "Austausch starten", MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes) return;
        }

        _tabs.SelectedTab = _pageRun;
        _gridResults.Rows.Clear();
        _lblRunCert.Text = dryRun ? "Dry-Run läuft …" : "Austausch läuft …";
        _unattended = unattended;

        var cfg = _cfg;
        RunResult? result;
        try
        {
            result = await RunBusyAsync(dryRun ? "Dry-Run" : "Zertifikatsaustausch", ct =>
            {
                var engine = _services.CreateEngine(cfg, ConfirmHostKey, MarkLearned);
                engine.ServerUpdated += sr => BeginInvoke(new Action(() => AddResultRow(sr)));
                return RunGuard.Execute(() => engine.Run(dryRun, ct), dryRun);
            }, showErrors: !unattended);
        }
        finally
        {
            _unattended = false;
        }

        if (result == null)
        {
            _lblRunCert.Text = "Lauf abgebrochen oder fehlgeschlagen – siehe Log.";
            if (unattended)
            {
                _cfg.Auto.LastRun = DateTime.Now;
                _cfg.Auto.LastResult = "abgebrochen/fehlgeschlagen";
            }
        }
        else
        {
            ShowRunResult(result);
            if (unattended)
            {
                _cfg.Auto.LastRun = DateTime.Now;
                _cfg.Auto.LastResult = result.Summary;
                bool swapped = result.Servers.Any(s => s.Outcome == ServerOutcome.Ok);
                if (!result.Success || result.Servers.Any(s => s.Outcome == ServerOutcome.Warning))
                    _tray.ShowBalloonTip(8000, "Zertifikatsaustausch: Problem", result.Summary, ToolTipIcon.Warning);
                else if (swapped)
                    _tray.ShowBalloonTip(5000, "Zertifikat getauscht", result.Summary, ToolTipIcon.Info);
            }
            else if (!result.Success)
            {
                MessageBox.Show(this, result.Summary + (result.FatalError != null ? "" : "\n\nDetails siehe Ergebnisliste und Log."),
                    "Ergebnis", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            }
        }

        BindServersGrid();
        UpdateLastRunLabel();
        UpdateNextRunLabel();
        SaveQuiet();
    }

    private void AddResultRow(ServerRunResult sr)
    {
        var outcome = sr.Outcome switch
        {
            ServerOutcome.Ok => "OK",
            ServerOutcome.Skipped => "aktuell",
            ServerOutcome.DryRun => "simuliert",
            ServerOutcome.Warning => "WARNUNG",
            _ => "FEHLER"
        };
        var i = _gridResults.Rows.Add(sr.Server, sr.Action, outcome, sr.Details);
        _gridResults.Rows[i].DefaultCellStyle.BackColor = UiKit.OutcomeColor(sr.Outcome);
    }

    private void ShowRunResult(RunResult r)
    {
        var sb = new StringBuilder();
        sb.Append($"{r.StartedAt:dd.MM.yyyy HH:mm:ss}  –  {r.Summary}  ({r.Duration.TotalSeconds:0.0}s)");
        if (r.Certificate != null)
            sb.Append($"\nZertifikat: {r.Certificate.ShortDescription}   Quelle: {r.CertificateSource}");
        if (r.FatalError != null) sb.Append("\nFEHLER: " + r.FatalError);
        foreach (var w in r.Warnings.Take(4)) sb.Append("\nHinweis: " + w);
        _lblRunCert.Text = sb.ToString();
        _lblRunCert.ForeColor = r.Success ? SystemColors.ControlText : Color.Firebrick;
        _status.Text = r.Summary;
    }

    // ───────────────────────── Log ─────────────────────────

    private string? _logFile;
    private long _logLength;

    private void OnLogEntry(LogEntry entry)
    {
        if (IsHandleCreated && !IsDisposed)
        {
            try { BeginInvoke(new Action(PollLog)); } catch (InvalidOperationException) { /* Fenster wird geschlossen */ }
        }
    }

    private void RefreshLogFiles()
    {
        var files = Log.ListFiles().ToList();
        var current = Log.CurrentFile;
        if (!files.Contains(current)) files.Insert(0, current);

        var keep = _logFile;
        _lstLogFiles.BeginUpdate();
        _lstLogFiles.Items.Clear();
        foreach (var f in files) _lstLogFiles.Items.Add(new LogFileItem(f));
        _lstLogFiles.EndUpdate();

        var target = files.Contains(keep ?? "") ? keep : current;
        var idx = files.IndexOf(target!);
        if (idx >= 0) _lstLogFiles.SelectedIndex = idx;
    }

    private sealed record LogFileItem(string Path)
    {
        public override string ToString() => System.IO.Path.GetFileName(Path);
    }

    private void LoadSelectedLog()
    {
        if (_lstLogFiles.SelectedItem is not LogFileItem item) return;
        _logFile = item.Path;
        _logLength = 0;
        _txtLog.Clear();
        PollLog();
    }

    /// <summary>Liest neue Zeilen nach (auch von der geplanten Aufgabe geschrieben) und folgt dem Tageswechsel.</summary>
    private void PollLog()
    {
        // Tageswechsel: neue Datei anbieten und – wenn bisher die aktuelle angezeigt wurde – dorthin wechseln
        var current = Log.CurrentFile;
        if (!_lstLogFiles.Items.Cast<LogFileItem>().Any(i => i.Path == current) && File.Exists(current))
        {
            bool followed = _logFile == null || _lstLogFiles.SelectedIndex == 0;
            _logFile = followed ? current : _logFile;
            RefreshLogFiles();
            return;
        }

        if (_logFile == null || !File.Exists(_logFile)) return;
        try
        {
            using var fs = new FileStream(_logFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            if (fs.Length < _logLength) { _logLength = 0; _txtLog.Clear(); }
            if (fs.Length == _logLength) return;

            fs.Seek(_logLength, SeekOrigin.Begin);
            using var reader = new StreamReader(fs, Encoding.UTF8, detectEncodingFromByteOrderMarks: _logLength == 0);
            var text = reader.ReadToEnd();
            _logLength = fs.Length;

            if (_txtLog.TextLength > 3_000_000) _txtLog.Clear(); // sehr große Tage nicht endlos im Speicher halten
            if (_chkAutoScroll.Checked)
            {
                _txtLog.AppendText(text.Replace("\r\n", "\n").Replace("\n", Environment.NewLine));
            }
            else
            {
                var sel = _txtLog.SelectionStart;
                _txtLog.Text += text.Replace("\r\n", "\n").Replace("\n", Environment.NewLine);
                _txtLog.SelectionStart = sel;
                _txtLog.ScrollToCaret();
            }
        }
        catch (IOException) { /* gerade gesperrt – nächster Tick */ }
    }
}
