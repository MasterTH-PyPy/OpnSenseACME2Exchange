using OpnSenseACME2Exchange.Core.Config;
using OpnSenseACME2Exchange.Core.Logging;
using OpnSenseACME2Exchange.Core.Scheduling;
using OpnSenseACME2Exchange.Infrastructure;

namespace OpnSenseACME2Exchange.UI;

/// <summary>Hauptfenster: Grundgerüst, Konfiguration ↔ Oberfläche, Busy-Handling, Infobereich, Auto-Modus.</summary>
public sealed partial class MainForm : Form
{
    private readonly AppServices _services;
    private AppConfig _cfg;
    private readonly bool _configLoadFailed;
    private CancellationTokenSource? _cts;
    private bool _busy;
    private volatile bool _unattended;
    private volatile bool _learned;
    private bool _exitRequested;
    private bool _trayHintShown;
    private bool _binding;

    public MainForm(AppServices services)
    {
        _services = services;
        try
        {
            _cfg = services.Store.Load();
        }
        catch (Exception ex)
        {
            _cfg = new AppConfig();
            _configLoadFailed = true;
            MessageBox.Show(
                "Die Konfiguration konnte nicht gelesen werden:\n\n" + ex.Message +
                "\n\nTypische Ursache: config.dat/key.bin stammen von einem anderen Rechner.\n" +
                "Es wird mit einer leeren Konfiguration gestartet. Beim Speichern wird die alte Datei vorher gesichert.",
                "Konfiguration", MessageBoxButtons.OK, MessageBoxIcon.Warning);
        }
        services.ApplyLogging(_cfg);

        BuildUi();
        BindConfig();

        Log.EntryWritten += OnLogEntry;
        Load += OnFormLoad;
        Resize += OnFormResize;
        FormClosing += OnFormClosing;

        Log.Info($"OpnSenseACME2Exchange {Program.Version} gestartet ({Environment.UserDomainName}\\{Environment.UserName}).");
    }

    private void OnFormLoad(object? sender, EventArgs e)
    {
        TrySetSplitter(_splitHaproxy, 320);
        TrySetSplitter(_splitLog, 270);
        RefreshLogFiles();
        _schedulerTimer.Start();
        _logTimer.Start();
        UpdateNextRunLabel();

        if (_cfg.OpnSense.Nodes.Count == 0)
        {
            _tabs.SelectedTab = _pageOpn;
            _status.Text = "Ersteinrichtung: OPNsense-Knoten eintragen → HAProxy einlesen → Exchange-Server ermitteln → Dry-Run.";
        }
        else _tabs.SelectedTab = _pageRun;
    }

    private static void TrySetSplitter(SplitContainer split, int distance)
    {
        try
        {
            if (split.Width > distance + split.Panel2MinSize) split.SplitterDistance = distance;
        }
        catch (InvalidOperationException) { /* Fenster zu klein – Standard behalten */ }
    }

    // ───────────────────────── Konfiguration ↔ Oberfläche ─────────────────────────

    private string? RevealSafe(string? value)
    {
        try { return _services.Store.Reveal(value); }
        catch (Exception ex)
        {
            Log.Warn("Gespeichertes Passwort nicht entschlüsselbar: " + Log.Describe(ex));
            return null;
        }
    }

    private void BindConfig()
    {
        _binding = true;
        try { BindConfigCore(); }
        finally { _binding = false; }
    }

    private void BindConfigCore()
    {
        var o = _cfg.OpnSense;
        _gridNodes.Rows.Clear();
        foreach (var n in o.Nodes)
        {
            var i = _gridNodes.Rows.Add(n.Name, n.Host, n.Port.ToString(), n.HostKeyFingerprint ?? "", "");
            _gridNodes.Rows[i].Tag = n;
        }
        _txtSshUser.Text = o.Username;
        _rbSshPassword.Checked = o.AuthMode == SshAuthMode.Password;
        _rbSshKey.Checked = o.AuthMode == SshAuthMode.PrivateKey;
        _txtSshPassword.Text = RevealSafe(o.PasswordProtected) ?? "";
        _txtKeyPath.Text = o.PrivateKeyPath ?? "";
        _txtKeyPassphrase.Text = RevealSafe(o.PrivateKeyPassphraseProtected) ?? "";
        _chkSudo.Checked = o.UseSudo;
        _chkPreferMaster.Checked = o.PreferCarpMaster;
        _txtHaproxyPath.Text = o.HaproxyConfigPath;
        _numSshTimeout.Value = Math.Clamp(o.TimeoutSeconds, (int)_numSshTimeout.Minimum, (int)_numSshTimeout.Maximum);
        UpdateSshAuthUi();

        _cmbHostname.Text = _cfg.Selection.ExchangeHostname;
        _txtAdditionalNames.Text = string.Join(", ", _cfg.Selection.AdditionalRequiredNames);

        BindServersGrid();
        var e = _cfg.Exchange;
        _rbExCurrentUser.Checked = e.UseCurrentUser;
        _rbExOtherUser.Checked = !e.UseCurrentUser;
        _txtExUser.Text = e.Username ?? "";
        _txtExPassword.Text = RevealSafe(e.PasswordProtected) ?? "";
        _cmbExAuth.SelectedItem = _cmbExAuth.Items.Contains(e.Authentication) ? e.Authentication : "Kerberos";
        _chkIis.Checked = e.ServiceIis;
        _chkSmtp.Checked = e.ServiceSmtp;
        _chkImap.Checked = e.ServiceImap;
        _chkPop.Checked = e.ServicePop;
        _chkExportable.Checked = e.PrivateKeyExportable;
        _chkVerify.Checked = e.VerifyAfterDeploy;
        _chkIisReset.Checked = e.IisResetOnMismatch;
        _chkRemoveOld.Checked = e.RemoveReplacedCertificate;
        UpdateExchangeAuthUi();

        var a = _cfg.Auto;
        _chkAuto.Checked = a.Enabled;
        _dtpAutoTime.Value = DateTime.Today + (DailySchedule.TryParseTime(a.Time, out var t) ? t.ToTimeSpan() : new TimeSpan(3, 30, 0));
        _chkAutoDryRun.Checked = a.DryRun;
        UpdateLastRunLabel();

        _txtLogDir.Text = _cfg.Logging.Directory ?? "";
        _numRetain.Value = Math.Clamp(_cfg.Logging.RetainDays, 1, 3650);
        _chkDebug.Checked = _cfg.Logging.Debug;
    }

    private void BindServersGrid()
    {
        _gridServers.Rows.Clear();
        foreach (var s in _cfg.Exchange.Servers)
        {
            var i = _gridServers.Rows.Add(s.Enabled, s.Name, s.Fqdn, s.Version ?? "", s.Dag ?? "", s.Site ?? "",
                s.PowerShellUri ?? "", s.CurrentCertificate ?? "", s.LastStatus ?? "");
            _gridServers.Rows[i].Tag = s;
            ColorStatusRow(_gridServers.Rows[i], s.LastStatus);
        }
    }

    private static void ColorStatusRow(DataGridViewRow row, string? status)
    {
        var c = status switch
        {
            null or "" => SystemColors.Window,
            _ when status.StartsWith("OK", StringComparison.Ordinal) => System.Drawing.Color.FromArgb(220, 245, 220),
            _ when status.StartsWith("Skipped", StringComparison.Ordinal) => SystemColors.Window,
            _ when status.StartsWith("FEHLER", StringComparison.Ordinal) || status.StartsWith("Failed", StringComparison.Ordinal)
                => System.Drawing.Color.FromArgb(250, 215, 215),
            _ when status.StartsWith("Warning", StringComparison.Ordinal) => System.Drawing.Color.FromArgb(255, 243, 205),
            _ => SystemColors.Window
        };
        row.DefaultCellStyle.BackColor = c;
    }

    /// <summary>Überträgt alle Eingaben in die Konfiguration (ohne zu speichern).</summary>
    private void CollectConfig()
    {
        _gridNodes.EndEdit();
        _gridServers.EndEdit();

        var o = _cfg.OpnSense;
        var nodes = new List<OpnSenseNode>();
        foreach (DataGridViewRow row in _gridNodes.Rows)
        {
            if (row.IsNewRow) continue;
            var host = Cell(row, "Host");
            if (host.Length == 0) continue;
            var node = row.Tag as OpnSenseNode ?? new OpnSenseNode();
            if (!string.Equals(node.Host, host, StringComparison.OrdinalIgnoreCase)) node.HostKeyFingerprint = null; // anderer Host = anderer Key
            node.Host = host;
            node.Name = Cell(row, "Name");
            node.Port = int.TryParse(Cell(row, "Port"), out var p) && p is > 0 and < 65536 ? p : 22;
            row.Tag = node;
            nodes.Add(node);
        }
        o.Nodes = nodes;
        o.Username = _txtSshUser.Text.Trim();
        o.AuthMode = _rbSshKey.Checked ? SshAuthMode.PrivateKey : SshAuthMode.Password;
        o.PasswordProtected = _services.Store.Hide(_txtSshPassword.Text);
        o.PrivateKeyPath = string.IsNullOrWhiteSpace(_txtKeyPath.Text) ? null : _txtKeyPath.Text.Trim();
        o.PrivateKeyPassphraseProtected = _services.Store.Hide(_txtKeyPassphrase.Text);
        o.UseSudo = _chkSudo.Checked;
        o.PreferCarpMaster = _chkPreferMaster.Checked;
        o.HaproxyConfigPath = string.IsNullOrWhiteSpace(_txtHaproxyPath.Text) ? "/usr/local/etc/haproxy.conf" : _txtHaproxyPath.Text.Trim();
        o.TimeoutSeconds = (int)_numSshTimeout.Value;

        if (_lstSections.SelectedItem is Core.Haproxy.HaproxySection sec) _cfg.Selection.SectionKey = sec.Key;
        _cfg.Selection.ExchangeHostname = _cmbHostname.Text.Trim().ToLowerInvariant();
        _cfg.Selection.AdditionalRequiredNames = _txtAdditionalNames.Text
            .Split(new[] { ',', ';', ' ' }, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(n => n.ToLowerInvariant()).Distinct().ToList();

        var servers = new List<ExchangeServerEntry>();
        foreach (DataGridViewRow row in _gridServers.Rows)
        {
            if (row.IsNewRow) continue;
            var fqdn = Cell(row, "Fqdn");
            var name = Cell(row, "Name");
            if (fqdn.Length == 0 && name.Length == 0) continue;
            var s = row.Tag as ExchangeServerEntry ?? new ExchangeServerEntry();
            if (!string.Equals(s.Fqdn, fqdn, StringComparison.OrdinalIgnoreCase)) s.PowerShellUri = null;
            s.Fqdn = fqdn.Length > 0 ? fqdn : name;
            s.Name = name.Length > 0 ? name : s.Fqdn.Split('.')[0];
            s.Enabled = row.Cells["Enabled"].Value is true;
            row.Tag = s;
            servers.Add(s);
        }
        _cfg.Exchange.Servers = servers;

        var e = _cfg.Exchange;
        e.UseCurrentUser = _rbExCurrentUser.Checked;
        e.Username = string.IsNullOrWhiteSpace(_txtExUser.Text) ? null : _txtExUser.Text.Trim();
        e.PasswordProtected = _services.Store.Hide(_txtExPassword.Text);
        e.Authentication = _cmbExAuth.SelectedItem as string ?? "Kerberos";
        e.ServiceIis = _chkIis.Checked;
        e.ServiceSmtp = _chkSmtp.Checked;
        e.ServiceImap = _chkImap.Checked;
        e.ServicePop = _chkPop.Checked;
        e.PrivateKeyExportable = _chkExportable.Checked;
        e.VerifyAfterDeploy = _chkVerify.Checked;
        e.IisResetOnMismatch = _chkIisReset.Checked;
        e.RemoveReplacedCertificate = _chkRemoveOld.Checked;

        _cfg.Auto.Enabled = _chkAuto.Checked;
        _cfg.Auto.Time = _dtpAutoTime.Value.ToString("HH:mm");
        _cfg.Auto.DryRun = _chkAutoDryRun.Checked;

        var newDir = string.IsNullOrWhiteSpace(_txtLogDir.Text) ? null : _txtLogDir.Text.Trim();
        var logChanged = newDir != _cfg.Logging.Directory || (int)_numRetain.Value != _cfg.Logging.RetainDays || _chkDebug.Checked != _cfg.Logging.Debug;
        _cfg.Logging.Directory = newDir;
        _cfg.Logging.RetainDays = (int)_numRetain.Value;
        _cfg.Logging.Debug = _chkDebug.Checked;
        if (logChanged)
        {
            _services.ApplyLogging(_cfg);
            RefreshLogFiles();
        }
    }

    private static string Cell(DataGridViewRow row, string column) => (row.Cells[column].Value?.ToString() ?? "").Trim();

    private bool SaveConfig(bool showMessage)
    {
        try
        {
            CollectConfig();
            if (_configLoadFailed && File.Exists(_services.Store.FilePath))
            {
                var backup = _services.Store.FilePath + $".bak-{DateTime.Now:yyyyMMdd-HHmmss}";
                if (!File.Exists(backup)) File.Copy(_services.Store.FilePath, backup);
            }
            _services.Store.Save(_cfg);
            _status.Text = $"Konfiguration gespeichert ({DateTime.Now:HH:mm:ss}).";
            if (showMessage) Log.Info("Konfiguration gespeichert.");
            return true;
        }
        catch (Exception ex)
        {
            Log.Error("Konfiguration konnte nicht gespeichert werden", ex);
            if (showMessage) MessageBox.Show(this, ex.Message, "Speichern fehlgeschlagen", MessageBoxButtons.OK, MessageBoxIcon.Error);
            return false;
        }
    }

    /// <summary>Speichert still (z.B. gelernte Hostkeys/URIs, Auto-Lauf-Status).</summary>
    private void SaveQuiet()
    {
        try { _services.Store.Save(_cfg); }
        catch (Exception ex) { Log.Warn("Konfiguration konnte nicht gespeichert werden: " + Log.Describe(ex)); }
    }

    private void UpdateSshAuthUi()
    {
        bool key = _rbSshKey.Checked;
        _txtSshPassword.Enabled = !key;
        _txtKeyPath.Enabled = key;
        _txtKeyPassphrase.Enabled = key;
    }

    private void UpdateExchangeAuthUi()
    {
        bool other = _rbExOtherUser.Checked;
        _txtExUser.Enabled = other;
        _txtExPassword.Enabled = other;
    }

    // ───────────────────────── Busy-Handling ─────────────────────────

    private async Task<T?> RunBusyAsync<T>(string status, Func<CancellationToken, T> work, bool showErrors = true)
    {
        if (_busy)
        {
            _status.Text = "Bitte warten – es läuft bereits eine Aktion.";
            return default;
        }
        _busy = true;
        _learned = false;
        _cts = new CancellationTokenSource();
        SetBusyUi(true, status);
        try
        {
            var token = _cts.Token;
            return await Task.Run(() => work(token));
        }
        catch (OperationCanceledException)
        {
            _status.Text = "Abgebrochen.";
            return default;
        }
        catch (Exception ex)
        {
            Log.Error($"{status} fehlgeschlagen", ex);
            _status.Text = "Fehler: " + ex.Message;
            if (showErrors && !_unattended)
                MessageBox.Show(this, ex.Message, status, MessageBoxButtons.OK, MessageBoxIcon.Error);
            return default;
        }
        finally
        {
            SetBusyUi(false, null);
            _cts.Dispose();
            _cts = null;
            _busy = false;
            if (_learned) { SaveQuiet(); RefreshNodeHostKeys(); }
        }
    }

    private void SetBusyUi(bool busy, string? status)
    {
        _pageOpn.Enabled = _pageHaproxy.Enabled = _pageExchange.Enabled = !busy;
        _btnDryRun.Enabled = _btnRunNow.Enabled = _btnSave.Enabled = !busy;
        _btnCancel.Enabled = busy;
        _progress.Visible = busy;
        _progress.MarqueeAnimationSpeed = busy ? 30 : 0;
        if (status != null) _status.Text = status + " …";
        UseWaitCursor = false;
    }

    private void MarkLearned() => _learned = true;

    /// <summary>Hostkey-Bestätigung (kommt aus dem Hintergrund-Thread).</summary>
    private bool ConfirmHostKey(OpnSenseNode node, string fingerprint)
    {
        if (_unattended) return false;
        return (bool)Invoke(new Func<bool>(() =>
            MessageBox.Show(this,
                $"Unbekannter SSH-Hostkey für {node}:\n\n{fingerprint}\n\n" +
                "Bitte mit dem Fingerprint auf der OPNsense vergleichen (Konsole: ssh-keygen -lf /conf/sshd/ssh_host_ed25519_key.pub).\n\n" +
                "Diesem Schlüssel dauerhaft vertrauen?",
                "SSH-Hostkey bestätigen", MessageBoxButtons.YesNo, MessageBoxIcon.Warning, MessageBoxDefaultButton.Button2) == DialogResult.Yes));
    }

    private void RefreshNodeHostKeys()
    {
        foreach (DataGridViewRow row in _gridNodes.Rows)
            if (row.Tag is OpnSenseNode n) row.Cells["HostKey"].Value = n.HostKeyFingerprint ?? "";
    }

    // ───────────────────────── Auto-Modus ─────────────────────────

    private async Task SchedulerTickAsync()
    {
        UpdateNextRunLabel();
        if (!_cfg.Auto.Enabled || _busy) return;
        if (!DailySchedule.TryParseTime(_cfg.Auto.Time, out var t)) return;
        if (!DailySchedule.IsDue(DateTime.Now, t, _cfg.Auto.LastRun)) return;

        Log.Info($"Auto-Modus: geplanter Lauf ({_cfg.Auto.Time}{(_cfg.Auto.DryRun ? ", Dry-Run" : "")}).");
        await StartRunAsync(_cfg.Auto.DryRun, unattended: true);
    }

    private void OnAutoSettingsChanged()
    {
        if (_binding) return;
        var wasEnabled = _cfg.Auto.Enabled;
        _cfg.Auto.Enabled = _chkAuto.Checked;
        _cfg.Auto.Time = _dtpAutoTime.Value.ToString("HH:mm");
        _cfg.Auto.DryRun = _chkAutoDryRun.Checked;
        if (wasEnabled != _cfg.Auto.Enabled)
        {
            Log.Info(_cfg.Auto.Enabled ? $"Auto-Modus aktiviert ({_cfg.Auto.Time})." : "Auto-Modus deaktiviert.");
            SaveQuiet();
        }
        UpdateNextRunLabel();
    }

    private void UpdateNextRunLabel()
    {
        if (_cfg.Auto.Enabled && DailySchedule.TryParseTime(_cfg.Auto.Time, out var t))
        {
            var next = DailySchedule.NextRun(DateTime.Now, t, _cfg.Auto.LastRun);
            var text = next <= DateTime.Now ? "jetzt (nachholen)" : next.ToString("dddd, dd.MM.yyyy HH:mm");
            _lblNextRun.Text = text + (_cfg.Auto.DryRun ? "  (Dry-Run)" : "");
            _statusNext.Text = "Auto: " + text;
        }
        else
        {
            _lblNextRun.Text = "– (Auto-Modus aus)";
            _statusNext.Text = "Auto-Modus aus";
        }
    }

    private void UpdateLastRunLabel() =>
        _lblLastRun.Text = _cfg.Auto.LastRun.HasValue
            ? $"{_cfg.Auto.LastRun:dd.MM.yyyy HH:mm} – {_cfg.Auto.LastResult}"
            : "–";

    // ───────────────────────── Fenster / Infobereich ─────────────────────────

    private void OnFormResize(object? sender, EventArgs e)
    {
        if (WindowState != FormWindowState.Minimized || !_cfg.Auto.Enabled) return;
        Hide();
        if (!_trayHintShown)
        {
            _tray.ShowBalloonTip(4000, "OpnSenseACME2Exchange", "Läuft im Infobereich weiter – der Auto-Modus bleibt aktiv.", ToolTipIcon.Info);
            _trayHintShown = true;
        }
    }

    private void RestoreFromTray()
    {
        Show();
        if (WindowState == FormWindowState.Minimized) WindowState = FormWindowState.Normal;
        Activate();
    }

    private void OnFormClosing(object? sender, FormClosingEventArgs e)
    {
        if (e.CloseReason == CloseReason.UserClosing && !_exitRequested && _cfg.Auto.Enabled)
        {
            var answer = MessageBox.Show(this,
                "Der Auto-Modus ist aktiv. Nach dem Beenden findet kein automatischer Austausch mehr statt.\n\n" +
                "Ja = in den Infobereich minimieren\nNein = wirklich beenden",
                "Beenden", MessageBoxButtons.YesNoCancel, MessageBoxIcon.Question);
            if (answer == DialogResult.Yes) { e.Cancel = true; WindowState = FormWindowState.Minimized; return; }
            if (answer == DialogResult.Cancel) { e.Cancel = true; return; }
        }
        if (_busy)
        {
            if (MessageBox.Show(this, "Es läuft noch eine Aktion. Trotzdem beenden?", "Beenden",
                    MessageBoxButtons.YesNo, MessageBoxIcon.Warning) != DialogResult.Yes)
            {
                e.Cancel = true;
                _exitRequested = false;
                return;
            }
            _cts?.Cancel();
        }

        if (!_configLoadFailed) { CollectConfig(); SaveQuiet(); }
        Log.EntryWritten -= OnLogEntry;
        _schedulerTimer.Stop();
        _logTimer.Stop();
        _tray.Visible = false;
        _tray.Dispose();
        Log.Info("Programm beendet.");
    }
}
