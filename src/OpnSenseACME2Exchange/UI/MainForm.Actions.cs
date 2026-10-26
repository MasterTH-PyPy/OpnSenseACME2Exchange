using System.Text;
using OpnSenseACME2Exchange.Client;
using OpnSenseACME2Exchange.Core.Certificates;
using OpnSenseACME2Exchange.Core.Engine;
using OpnSenseACME2Exchange.Core.Ipc;
using OpnSenseACME2Exchange.Core.Logging;
using OpnSenseACME2Exchange.Core.OpnSense;
using OpnSenseACME2Exchange.ServiceHost;

namespace OpnSenseACME2Exchange.UI;

partial class MainForm
{
    private List<HaproxySectionDto> _sections = new();
    private DateTime? _watchRunSince;
    private string? _shownRunKey;
    private bool _pollingStatus;

    // ───────────────────────── Allgemein: Befehl an den Dienst ─────────────────────────

    /// <summary>Speichert die aktuelle Konfiguration im Dienst, schickt den Befehl und behandelt Hostkey-Rückfragen.</summary>
    private Task<T?> OpAsync<T>(string status, string command, object? payload, bool saveFirst = true) =>
        RunBusyAsync(status, async ct =>
        {
            if (saveFirst) await SaveCoreAsync(ct);
            var resp = await _client.SendAsync(command, payload, ct);
            if (resp.UnknownHostKeys.Count > 0 && await ConfirmHostKeysAsync(resp.UnknownHostKeys, ct))
                resp = await _client.SendAsync(command, payload, ct);
            if (!resp.Ok) throw new ServiceCallException(resp.Error ?? "Unbekannter Fehler im Dienst.");
            return PipeProtocol.FromElement<T>(resp.Payload);
        });

    /// <summary>Unbekannte SSH-Hostkeys dem Menschen vorlegen. true = mindestens einer bestätigt (Befehl wiederholen).</summary>
    private async Task<bool> ConfirmHostKeysAsync(List<UnknownHostKey> keys, CancellationToken ct)
    {
        bool any = false;
        foreach (var k in keys)
        {
            var answer = MessageBox.Show(this,
                $"Unbekannter SSH-Hostkey für {(string.IsNullOrWhiteSpace(k.Name) ? k.Host : $"{k.Name} ({k.Host})")}:\n\n{k.Fingerprint}\n\n" +
                "Bitte mit dem Fingerprint der OPNsense vergleichen (Konsole: ssh-keygen -lf /conf/sshd/ssh_host_ed25519_key.pub).\n\n" +
                "Diesem Schlüssel dauerhaft vertrauen?",
                "SSH-Hostkey bestätigen", MessageBoxButtons.YesNo, MessageBoxIcon.Warning, MessageBoxDefaultButton.Button2);
            if (answer != DialogResult.Yes) continue;
            await _client.CallAsync<object>(Commands.TrustHostKey, new TrustHostKeyRequest(k.Host, k.Fingerprint), ct);
            any = true;
        }
        return any;
    }

    // ───────────────────────── OPNsense ─────────────────────────

    private async Task TestNodesAsync()
    {
        if (!CollectRequest().Config.OpnSense.Nodes.Any())
        {
            MessageBox.Show(this, "Bitte mindestens einen OPNsense-Knoten (Host/IP) eintragen.", "OPNsense",
                MessageBoxButtons.OK, MessageBoxIcon.Information);
            return;
        }
        var list = await OpAsync<List<NodeStatusDto>>("Dienst testet OPNsense-Knoten", Commands.TestNodes, null);
        if (list == null) return;

        foreach (DataGridViewRow row in _gridNodes.Rows)
        {
            var host = Cell(row, "Host");
            var st = list.FirstOrDefault(s => s.Host.Equals(host, StringComparison.OrdinalIgnoreCase));
            if (st == null) continue;
            row.Cells["Status"].Value = st.Summary;
            row.DefaultCellStyle.BackColor = !st.Reachable || st.ConfigReadable == false
                ? Color.FromArgb(250, 215, 215)
                : st.HaproxyRunning == false ? Color.FromArgb(255, 243, 205) : Color.FromArgb(220, 245, 220);
        }
        int masters = list.Count(s => s.Carp == CarpState.Master);
        _status.Text = $"{list.Count(s => s.Reachable)}/{list.Count} Knoten erreichbar, CARP-Master: " +
                       (masters == 1 ? list.First(s => s.Carp == CarpState.Master).Host : masters == 0 ? "keiner" : "MEHRERE!");
    }

    private async Task ResetHostKeysAsync()
    {
        var hosts = _gridNodes.SelectedRows.Cast<DataGridViewRow>().Where(r => !r.IsNewRow).Select(r => Cell(r, "Host"))
            .Where(h => h.Length > 0).ToList();
        if (hosts.Count == 0) return;
        if (MessageBox.Show(this,
                "Gespeicherten SSH-Hostkey der ausgewählten Knoten im Dienst verwerfen?\n\nNur nötig, wenn die Firewall neu installiert wurde. " +
                "Beim nächsten Verbindungstest wird der neue Key zur Bestätigung angezeigt.",
                "Hostkey zurücksetzen", MessageBoxButtons.YesNo, MessageBoxIcon.Warning) != DialogResult.Yes) return;

        await RunBusyAsync("Setze Hostkeys zurück", async ct =>
        {
            foreach (var h in hosts) await _client.CallAsync<object>(Commands.ResetHostKey, h, ct);
            return true;
        });
    }

    // ───────────────────────── HAProxy ─────────────────────────

    private async Task ReadHaproxyAsync()
    {
        var res = await OpAsync<HaproxyReadResult>("Dienst liest HAProxy-Konfiguration", Commands.ReadHaproxy, null);
        if (res == null) return;

        _sections = res.Sections;
        _lblHaproxySource.Text =
            $"Gelesen von {res.Node} um {DateTime.Now:HH:mm:ss} – {_sections.Count} Abschnitte, {_sections.Count(s => s.TerminatesTls)} mit TLS-Zertifikat";
        FillSectionList();

        if (_lstSections.SelectedIndex < 0)
        {
            var host = _cmbHostname.Text.Trim();
            var pick = _lstSections.Items.Cast<HaproxySectionDto>()
                           .FirstOrDefault(s => host.Length > 0 && s.Hostnames.Any(x => HostMatcher.Matches(x, host)))
                       ?? _lstSections.Items.Cast<HaproxySectionDto>().FirstOrDefault(s => s.TerminatesTls);
            if (pick != null) _lstSections.SelectedItem = pick;
        }
        _status.Text = "HAProxy-Konfiguration eingelesen – Abschnitt wählen und 'Zertifikat ermitteln'.";
    }

    private void FillSectionList()
    {
        var selectedKey = (_lstSections.SelectedItem as HaproxySectionDto)?.Key ?? _cfg.Selection.SectionKey;
        _lstSections.BeginUpdate();
        _lstSections.Items.Clear();
        var items = _chkAllSections.Checked ? _sections : _sections.Where(s => s.CanCarryCertificate).ToList();
        foreach (var s in items) _lstSections.Items.Add(s);
        var match = items.FirstOrDefault(s => s.Key == selectedKey);
        if (match != null) _lstSections.SelectedItem = match;
        _lstSections.EndUpdate();
    }

    private void OnSectionSelected()
    {
        if (_lstSections.SelectedItem is not HaproxySectionDto sec) return;
        _txtSection.Text = sec.Text.Replace("\r\n", "\n").Replace("\n", Environment.NewLine);

        var current = _cmbHostname.Text;
        _cmbHostname.Items.Clear();
        var hosts = sec.Hostnames;
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
    }

    private async Task ResolveCertificateAsync()
    {
        if (string.IsNullOrWhiteSpace(_cmbHostname.Text))
        {
            MessageBox.Show(this, "Bitte den externen Exchange-Hostnamen angeben (z.B. mail.domain.de).", "Zertifikat",
                MessageBoxButtons.OK, MessageBoxIcon.Information);
            return;
        }
        var view = await OpAsync<ResolveResultDto>("Dienst ermittelt Zertifikat", Commands.ResolveCertificate, null);
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
        foreach (var e in view.Errors.Concat(view.ValidationErrors)) sb.AppendLine("FEHLER:  " + e);
        foreach (var w in view.ValidationWarnings.Concat(view.Warnings)) sb.AppendLine("Hinweis: " + w);
        _txtCertInfo.Text = sb.ToString();

        _status.Text = view.Info != null && view.ValidationErrors.Count == 0
            ? $"Zertifikat gefunden: {view.Info.ShortDescription}"
            : "Kein gültiges Zertifikat gefunden – Details siehe unten.";
    }

    // ───────────────────────── Exchange ─────────────────────────

    private async Task DiscoverServersAsync()
    {
        var res = await OpAsync<DiscoveryResultDto>("Dienst ermittelt Exchange-Server aus dem AD", Commands.DiscoverServers, null);
        if (res != null) _status.Text = $"{res.Found.Count} Exchange-Server im AD, {res.Added} neu hinzugefügt.";
    }

    private async Task TestServersAsync()
    {
        var fqdns = _gridServers.SelectedRows.Cast<DataGridViewRow>()
            .Where(r => !r.IsNewRow).Select(r => Cell(r, "Fqdn")).Where(f => f.Length > 0).ToList();
        if (_gridServers.Rows.Cast<DataGridViewRow>().All(r => r.IsNewRow))
        {
            MessageBox.Show(this, "Keine Exchange-Server eingetragen – zuerst 'aus AD ermitteln'.", "Exchange",
                MessageBoxButtons.OK, MessageBoxIcon.Information);
            return;
        }
        var res = await OpAsync<List<ServerTestDto>>(
            fqdns.Count > 0 ? $"Dienst testet {fqdns.Count} Exchange-Server" : "Dienst testet alle Exchange-Server",
            Commands.TestServers, new TestServersRequest(fqdns));
        if (res != null) _status.Text = $"{res.Count(r => r.Ok)}/{res.Count} Exchange-Server OK.";
    }

    // ───────────────────────── Ausführung ─────────────────────────

    private async Task StartRunAsync(bool dryRun)
    {
        var cfg = CollectRequest().Config;
        var problems = new List<string>();
        if (cfg.OpnSense.Nodes.Count == 0) problems.Add("Keine OPNsense-Knoten eingetragen.");
        if (string.IsNullOrWhiteSpace(cfg.Selection.ExchangeHostname)) problems.Add("Kein Exchange-Hostname gewählt.");
        if (!cfg.Exchange.Servers.Any(s => s.Enabled)) problems.Add("Kein Exchange-Server aktiviert.");
        if (string.IsNullOrEmpty(cfg.Exchange.ServicesString())) problems.Add("Keine Exchange-Dienste ausgewählt.");
        if (problems.Count > 0)
        {
            MessageBox.Show(this, string.Join("\n", problems), "Konfiguration unvollständig", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            return;
        }
        if (!dryRun && MessageBox.Show(this,
                $"Zertifikat für {cfg.Selection.ExchangeHostname} jetzt auf {cfg.Exchange.Servers.Count(s => s.Enabled)} Exchange-Server verteilen?\n\n" +
                "Getauscht wird nur, wo das OPNsense-Zertifikat wirklich neuer ist.",
                "Austausch starten", MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes) return;

        _tabs.SelectedTab = _pageRun;
        var since = DateTime.Now;
        var ok = await RunBusyAsync(dryRun ? "Starte Dry-Run im Dienst" : "Starte Austausch im Dienst", async ct =>
        {
            await SaveCoreAsync(ct);
            await _client.CallAsync<object>(Commands.StartRun, new StartRunRequest(dryRun), ct);
            return true;
        }, reloadAfter: false);
        if (!ok) return;

        _watchRunSince = since;
        _gridResults.Rows.Clear();
        _shownRunKey = null;
        _lblRunCert.Text = dryRun ? "Dry-Run läuft im Dienst …" : "Austausch läuft im Dienst …";
        _lblRunCert.ForeColor = SystemColors.ControlText;
        await PollStatusAsync();
    }

    /// <summary>Alle 2 s: Status vom Dienst holen (Live-Fortschritt, Zeitplan, Verbindung).</summary>
    private async Task PollStatusAsync()
    {
        if (_pollingStatus) return;
        if (!_connected)
        {
            // Selbstheilend: alle ~10 s still neu verbinden (z.B. nach Dienst-Neustart)
            if (++_reconnectTick % 5 == 0 && !_busy) await ConnectAsync(showErrors: false);
            return;
        }

        _pollingStatus = true;
        try
        {
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            var st = await _client.CallAsync<StatusDto>(Commands.GetStatus, null, cts.Token);
            if (st == null) return;
            ShowStatus(st);
        }
        catch (Exception ex)
        {
            _connected = false;
            SetConnectedUi(false);
            _statusConn.Text = "Dienst: getrennt";
            _lblConn.Text = "Verbindung verloren: " + ex.Message;
            _lblConn.ForeColor = Color.Firebrick;
            Log.Warn("Verbindung zum Dienst verloren: " + ex.Message);
        }
        finally { _pollingStatus = false; }
    }

    private void ShowStatus(StatusDto st)
    {
        var s = st.State;
        _statusConn.Text = $"Dienst: {st.MachineName} ({st.Account})";

        bool opRunning = st.CurrentOperation != null;
        if (!_busy)
        {
            _btnDryRun.Enabled = _btnRunNow.Enabled = !opRunning;
            _btnCancel.Enabled = opRunning;
            _progress.Visible = opRunning;
            _progress.MarqueeAnimationSpeed = opRunning ? 30 : 0;
            if (opRunning) _status.Text = $"Dienst: {st.CurrentOperation} läuft seit {st.OperationStarted:HH:mm:ss} …";
        }

        if (st.Auto.Enabled && s.NextRun is { } next)
        {
            var text = next <= DateTime.Now ? "jetzt" : next.ToString("ddd dd.MM.yyyy HH:mm");
            _lblNextRun.Text = text + (st.Auto.DryRun ? "  (Dry-Run)" : "");
            _statusNext.Text = "Auto: " + text;
        }
        else
        {
            _lblNextRun.Text = "– (Automatik aus)";
            _statusNext.Text = "Auto-Modus aus";
        }
        _lblLastRun.Text = s.LastRun.HasValue ? $"{s.LastRun:dd.MM.yyyy HH:mm} – {s.LastResult} [{s.LastTrigger}]" : "–";
        _lblLastRun.ForeColor = s.LastRun.HasValue && !s.LastSuccess ? Color.Firebrick : SystemColors.ControlText;
        _lblRetry.Text = s.RetryAt is { } r ? $"Wiederholung {s.RetryCount}/3 geplant um {r:HH:mm}" : "";
        if (s.ConfigError != null) _lblRetry.Text = "Konfigurationsfehler im Dienst: " + s.ConfigError;

        // Ergebnisliste: live während des Laufs, sonst letzter Lauf
        var run = st.RunInProgress ? st.CurrentRun : st.LastRunResult;
        if (run != null)
        {
            var key = $"{run.StartedAt:o}|{run.Servers.Count}|{run.Duration}|{st.RunInProgress}";
            if (key != _shownRunKey)
            {
                _shownRunKey = key;
                ShowRun(run, st.RunInProgress);
            }
        }

        // Ein von hier gestarteter Lauf ist fertig
        if (_watchRunSince is { } since && !st.RunInProgress && st.LastRunResult is { } done && done.StartedAt >= since.AddSeconds(-5))
        {
            _watchRunSince = null;
            _status.Text = done.Summary;
            if (!done.Success)
                MessageBox.Show(this, done.Summary + (done.FatalError != null ? "" : "\n\nDetails siehe Ergebnisliste und Log."),
                    "Ergebnis", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            _ = ReloadConfigAsync();
        }
    }

    private void ShowRun(RunResult r, bool live)
    {
        _gridResults.Rows.Clear();
        foreach (var sr in r.Servers)
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

        var sb = new StringBuilder();
        if (live) sb.Append($"{(r.DryRun ? "Dry-Run" : "Austausch")} läuft seit {r.StartedAt:HH:mm:ss} – {r.Servers.Count} Server bearbeitet …");
        else
        {
            sb.Append($"{r.StartedAt:dd.MM.yyyy HH:mm:ss}  –  {r.Summary}  ({r.Duration.TotalSeconds:0.0}s)");
            if (r.Certificate != null) sb.Append($"\nZertifikat: {r.Certificate.ShortDescription}   Quelle: {r.CertificateSource}");
            if (r.FatalError != null) sb.Append("\nFEHLER: " + r.FatalError);
            foreach (var w in r.Warnings.Take(4)) sb.Append("\nHinweis: " + w);
        }
        _lblRunCert.Text = sb.ToString();
        _lblRunCert.ForeColor = live || r.Success ? SystemColors.ControlText : Color.Firebrick;
    }

    // ───────────────────────── Log (vom Dienst) ─────────────────────────

    private sealed record LogFileItem(string Name, long Size)
    {
        public override string ToString() => $"{Name}  ({Size / 1024.0:0.#} KB)";
    }

    private string? _logFile;
    private long _logOffset;
    private bool _pollingLog;
    private DateTime _lastLogListRefresh;
    private string? _currentLogName;

    private async Task RefreshLogFilesAsync()
    {
        if (!_connected) return;
        try
        {
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            var list = await _client.CallAsync<LogListDto>(Commands.ListLogs, null, cts.Token);
            if (list == null) return;
            _lastLogListRefresh = DateTime.Now;

            // Tageswechsel: wer die aktuelle Datei angesehen hat, bekommt automatisch die neue
            bool followCurrent = _logFile == null || _logFile == _currentLogName;
            _currentLogName = list.Current;
            var keep = followCurrent ? list.Current : _logFile;

            _lstLogFiles.BeginUpdate();
            _lstLogFiles.Items.Clear();
            foreach (var f in list.Files) _lstLogFiles.Items.Add(new LogFileItem(f.Name, f.Size));
            _lstLogFiles.EndUpdate();

            var idx = list.Files.FindIndex(f => f.Name == keep);
            if (idx >= 0 && (_logFile != keep || _lstLogFiles.SelectedIndex != idx)) _lstLogFiles.SelectedIndex = idx;
        }
        catch (Exception ex) { Log.Debug("Logliste nicht abrufbar: " + ex.Message); }
    }

    private void LoadSelectedLog()
    {
        if (_lstLogFiles.SelectedItem is not LogFileItem item || item.Name == _logFile) return;
        _logFile = item.Name;
        _logOffset = 0;
        _txtLog.Clear();
        _ = PollLogAsync();
    }

    private async Task PollLogAsync()
    {
        if (_pollingLog || !_connected || _tabs.SelectedTab != _pageLog) return;
        _pollingLog = true;
        try
        {
            if (_logFile == null || (DateTime.Now - _lastLogListRefresh).TotalSeconds > 30)
                await RefreshLogFilesAsync();
            if (_logFile == null) return;

            for (int round = 0; round < 8; round++) // große Dateien in Stücken nachladen
            {
                using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
                var chunk = await _client.CallAsync<LogChunkDto>(Commands.ReadLog, new ReadLogRequest(_logFile, _logOffset), cts.Token);
                if (chunk == null || chunk.Name != _logFile) return;
                if (chunk.Reset) _txtLog.Clear();
                _logOffset = chunk.NewOffset;
                if (chunk.Text.Length > 0)
                {
                    if (_txtLog.TextLength > 3_000_000) _txtLog.Clear();
                    var text = chunk.Text.Replace("\r\n", "\n").Replace("\n", Environment.NewLine);
                    if (_chkAutoScroll.Checked) _txtLog.AppendText(text);
                    else
                    {
                        var sel = _txtLog.SelectionStart;
                        _txtLog.Text += text;
                        _txtLog.SelectionStart = sel;
                        _txtLog.ScrollToCaret();
                    }
                }
                if (_logOffset >= chunk.Length) break;
            }
        }
        catch (Exception ex) { Log.Debug("Log nicht abrufbar: " + ex.Message); }
        finally { _pollingLog = false; }
    }

    // ───────────────────────── Dienstverwaltung (lokal, erhöht) ─────────────────────────

    private void RefreshInstalledInfo()
    {
        var info = AdminActions.QueryInstalled();
        if (!info.Installed)
        {
            _lblSvcInstalled.Text = "Nicht installiert.";
            _btnSvcInstall.Text = "Installieren";
        }
        else
        {
            _lblSvcInstalled.Text = $"{info.Status} – Konto: {info.Account} – {info.ImagePath}";
            _btnSvcInstall.Text = "Neu installieren / Konto ändern";
            if (string.IsNullOrWhiteSpace(_txtSvcAccount.Text) && !string.IsNullOrWhiteSpace(info.Account)
                && !info.Account.Equals("LocalSystem", StringComparison.OrdinalIgnoreCase))
                _txtSvcAccount.Text = info.Account;
        }
        _btnSvcUpdate.Enabled = _btnSvcUninstall.Enabled = _btnSvcAccess.Enabled = info.Installed && !_busy;
        _btnSvcStart.Enabled = info.Installed && info.Status != System.ServiceProcess.ServiceControllerStatus.Running && !_busy;
        _btnSvcStop.Enabled = info.Installed && info.Status == System.ServiceProcess.ServiceControllerStatus.Running && !_busy;
    }

    private async Task AdminAsync(AdminAction action)
    {
        var req = new AdminRequest
        {
            Action = action,
            Account = _txtSvcAccount.Text.Trim(),
            Password = _txtSvcPassword.Text,
            ExtraPrincipals = _txtSvcAccess.Text.Split(new[] { ',', ';' }, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).ToList()
        };

        if (action == AdminAction.Install)
        {
            if (req.Account.Length == 0 &&
                MessageBox.Show(this,
                    "Ohne Dienstkonto läuft der Dienst als LocalSystem und spricht Exchange als Computerkonto an – das hat normalerweise keine Exchange-Rechte.\n\n" +
                    "Trotzdem als LocalSystem installieren?", "Dienstkonto", MessageBoxButtons.YesNo, MessageBoxIcon.Warning) != DialogResult.Yes)
                return;
        }
        if (action == AdminAction.Uninstall &&
            MessageBox.Show(this, "Dienst wirklich entfernen? Konfiguration und Logs bleiben erhalten.", "Deinstallieren",
                MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes)
            return;

        var result = await RunBusyAsync("Dienstverwaltung (Administratorrechte)", _ => AdminActions.RunElevatedAsync(req), reloadAfter: false);
        _txtSvcPassword.Clear();
        if (result == null) { RefreshInstalledInfo(); return; }

        var sb = new StringBuilder();
        sb.AppendLine($"[{DateTime.Now:HH:mm:ss}] {action}: {(result.Ok ? "OK" : "FEHLER")} – {result.Message}");
        foreach (var step in result.Steps) sb.AppendLine("    " + step);
        _txtSvcLog.AppendText(sb.ToString() + Environment.NewLine);
        Log.Info($"Dienstverwaltung {action}: {result.Message}");
        RefreshInstalledInfo();

        if (!result.Ok)
        {
            MessageBox.Show(this, result.Message, "Dienstverwaltung", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            return;
        }
        if (action is AdminAction.Install or AdminAction.Update or AdminAction.Start)
        {
            if (string.IsNullOrWhiteSpace(_txtServiceHost.Text)) _txtServiceHost.Text = ".";
            await Task.Delay(1500);
            await ConnectAsync(showErrors: true);
        }
        else if (action is AdminAction.Stop or AdminAction.Uninstall)
        {
            _connected = false;
            SetConnectedUi(false);
            _statusConn.Text = "Dienst: nicht verbunden";
        }
    }
}
