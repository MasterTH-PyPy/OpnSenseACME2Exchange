using System.Text.Json;
using OpnSenseACME2Exchange.Client;
using OpnSenseACME2Exchange.Core.Config;
using OpnSenseACME2Exchange.Core.Ipc;
using OpnSenseACME2Exchange.Core.Logging;
using OpnSenseACME2Exchange.Core.Scheduling;
using OpnSenseACME2Exchange.Infrastructure;

namespace OpnSenseACME2Exchange.UI;

/// <summary>
/// Hauptfenster = reine Bedienoberfläche. Alles Fachliche (SSH, AD, Exchange, Läufe, Zeitplan) macht der Dienst;
/// die GUI schickt ihm Konfiguration und Befehle über die Named Pipe und zeigt Status/Logs live an.
/// </summary>
public sealed partial class MainForm : Form
{
    private readonly ServiceClient _client = new();
    private AppConfig _cfg = new();
    private ConfigDto? _dto;
    private bool _connected;
    private bool _busy;
    private bool _binding;
    private CancellationTokenSource? _cts;
    private string _boundJson = "";
    private int _reconnectTick;
    private GuiSettings _gui = GuiSettings.Load();

    public MainForm()
    {
        BuildUi();
        SetConnectedUi(false);
        Load += OnFormLoad;
        FormClosing += OnFormClosing;
        _tabs.SelectedIndexChanged += async (_, _) =>
        {
            if (_tabs.SelectedTab == _pageLog && _connected) await RefreshLogFilesAsync();
            if (_tabs.SelectedTab == _pageService) RefreshInstalledInfo();
        };
    }

    private async void OnFormLoad(object? sender, EventArgs e)
    {
        TrySetSplitter(_splitHaproxy, 320);
        TrySetSplitter(_splitLog, 270);
        _txtServiceHost.Text = _gui.ServiceHost ?? "";
        _txtSvcAccount.Text = _gui.ServiceAccount ?? "";
        _txtSvcAccess.Text = _gui.ExtraAccess ?? "";
        RefreshInstalledInfo();

        await ConnectAsync(showErrors: false);
        _statusTimer.Start();
        _logTimer.Start();
    }

    private static void TrySetSplitter(SplitContainer split, int distance)
    {
        try { if (split.Width > distance + split.Panel2MinSize) split.SplitterDistance = distance; }
        catch (InvalidOperationException) { /* Fenster zu klein */ }
    }

    // ───────────────────────── Verbindung ─────────────────────────

    private async Task ConnectAsync(bool showErrors)
    {
        _client.Server = string.IsNullOrWhiteSpace(_txtServiceHost.Text) ? "." : _txtServiceHost.Text.Trim();
        try
        {
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(15));
            var dto = await _client.CallAsync<ConfigDto>(Commands.GetConfig, null, cts.Token)
                      ?? throw new ServiceCallException("Leere Antwort vom Dienst.");
            ApplyConfigDto(dto);
            _connected = true;
            SetConnectedUi(true);
            _lblConn.Text = $"Verbunden mit {dto.MachineName} – Dienstkonto {dto.ServiceAccount} – Daten {dto.DataDirectory}";
            _lblConn.ForeColor = SystemColors.ControlText;
            _statusConn.Text = $"Dienst: {dto.MachineName} ({dto.ServiceAccount})";
            Log.Info($"Verbunden mit Dienst auf {_client.Display}.");

            if (_cfg.OpnSense.Nodes.Count == 0)
            {
                _tabs.SelectedTab = _pageOpn;
                _status.Text = "Ersteinrichtung: OPNsense-Knoten eintragen → HAProxy einlesen → Exchange-Server ermitteln → Dry-Run.";
            }
            await PollStatusAsync();
        }
        catch (Exception ex)
        {
            _connected = false;
            SetConnectedUi(false);
            _lblConn.Text = ex.Message;
            _lblConn.ForeColor = Color.Firebrick;
            _statusConn.Text = "Dienst: nicht verbunden";
            _status.Text = "Kein Dienst erreichbar – im Reiter 'Dienst' installieren oder verbinden.";
            _tabs.SelectedTab = _pageService;
            if (showErrors) MessageBox.Show(this, ex.Message, "Verbindung zum Dienst", MessageBoxButtons.OK, MessageBoxIcon.Warning);
        }
    }

    private void SetConnectedUi(bool connected)
    {
        foreach (var p in new[] { _pageOpn, _pageHaproxy, _pageExchange, _pageRun, _pageLog })
            p.Enabled = connected && !_busy;
        _btnSave.Enabled = connected && !_busy;
    }

    private void ApplyConfigDto(ConfigDto dto)
    {
        _dto = dto;
        _cfg = dto.Config;
        BindConfig();
    }

    private async Task ReloadConfigAsync()
    {
        if (!_connected) return;
        try
        {
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(15));
            var dto = await _client.CallAsync<ConfigDto>(Commands.GetConfig, null, cts.Token);
            if (dto != null) ApplyConfigDto(dto);
        }
        catch (Exception ex) { Log.Warn("Konfiguration nicht neu ladbar: " + ex.Message); }
    }

    // ───────────────────────── Konfiguration ↔ Oberfläche ─────────────────────────

    private void BindConfig()
    {
        _binding = true;
        try { BindConfigCore(); }
        finally { _binding = false; }
        _boundJson = JsonSerializer.Serialize(CollectRequest().Config, ConfigStore.JsonOptions);
    }

    private void BindConfigCore()
    {
        var o = _cfg.OpnSense;
        _gridNodes.Rows.Clear();
        foreach (var n in o.Nodes)
        {
            var i = _gridNodes.Rows.Add(n.Name, n.Host, n.Port.ToString(), n.HostKeyFingerprint ?? "(noch nicht bestätigt)", "");
            _gridNodes.Rows[i].Tag = n;
        }
        _txtSshUser.Text = o.Username;
        _rbSshPassword.Checked = o.AuthMode == SshAuthMode.Password;
        _rbSshKey.Checked = o.AuthMode == SshAuthMode.PrivateKey;
        SetSecretBox(_txtSshPassword, _dto?.HasSshPassword == true);
        _txtKeyPath.Text = o.PrivateKeyPath ?? "";
        SetSecretBox(_txtKeyPassphrase, _dto?.HasKeyPassphrase == true);
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
        SetSecretBox(_txtExPassword, _dto?.HasExchangePassword == true);
        _cmbExAuth.SelectedItem = _cmbExAuth.Items.Contains(e.Authentication) ? e.Authentication : "Kerberos";
        _chkIis.Checked = e.ServiceIis;
        _chkSmtp.Checked = e.ServiceSmtp;
        _chkImap.Checked = e.ServiceImap;
        _chkPop.Checked = e.ServicePop;
        _chkExportable.Checked = e.PrivateKeyExportable;
        _chkVerify.Checked = e.VerifyAfterDeploy;
        _chkIisReset.Checked = e.IisResetOnMismatch;
        _chkRemoveOld.Checked = e.RemoveReplacedCertificate;
        _chkAutoDiscover.Checked = e.AutoDiscoverBeforeRun;
        UpdateExchangeAuthUi();

        var a = _cfg.Auto;
        _chkAuto.Checked = a.Enabled;
        _dtpAutoTime.Value = DateTime.Today + (DailySchedule.TryParseTime(a.Time, out var t) ? t.ToTimeSpan() : new TimeSpan(3, 30, 0));
        _chkAutoDryRun.Checked = a.DryRun;

        _txtLogDir.Text = _cfg.Logging.Directory ?? "";
        _numRetain.Value = Math.Clamp(_cfg.Logging.RetainDays, 1, 3650);
        _chkDebug.Checked = _cfg.Logging.Debug;
    }

    private static void SetSecretBox(TextBox box, bool stored)
    {
        box.Text = "";
        box.PlaceholderText = stored ? "gespeichert – nur zum Ändern neu eingeben" : "";
    }

    private static void ColorStatusRow(DataGridViewRow row, string? status)
    {
        row.DefaultCellStyle.BackColor = status switch
        {
            null or "" => SystemColors.Window,
            _ when status.StartsWith("OK", StringComparison.Ordinal) => Color.FromArgb(220, 245, 220),
            _ when status.StartsWith("FEHLER", StringComparison.Ordinal) || status.StartsWith("Failed", StringComparison.Ordinal)
                => Color.FromArgb(250, 215, 215),
            _ when status.StartsWith("Warning", StringComparison.Ordinal) => Color.FromArgb(255, 243, 205),
            _ => SystemColors.Window
        };
    }

    /// <summary>Baut aus den Eingaben die Speicher-Anfrage (Passwörter nur, wenn neu eingegeben).</summary>
    private SaveConfigRequest CollectRequest()
    {
        _gridNodes.EndEdit();
        _gridServers.EndEdit();
        var cfg = JsonSerializer.Deserialize<AppConfig>(JsonSerializer.Serialize(_cfg, ConfigStore.JsonOptions), ConfigStore.JsonOptions)!;

        var o = cfg.OpnSense;
        o.Nodes = new List<OpnSenseNode>();
        foreach (DataGridViewRow row in _gridNodes.Rows)
        {
            if (row.IsNewRow) continue;
            var host = Cell(row, "Host");
            if (host.Length == 0) continue;
            o.Nodes.Add(new OpnSenseNode
            {
                Host = host,
                Name = Cell(row, "Name"),
                Port = int.TryParse(Cell(row, "Port"), out var p) && p is > 0 and < 65536 ? p : 22,
                HostKeyFingerprint = (row.Tag as OpnSenseNode)?.Host.Equals(host, StringComparison.OrdinalIgnoreCase) == true
                    ? ((OpnSenseNode)row.Tag!).HostKeyFingerprint : null
            });
        }
        o.Username = _txtSshUser.Text.Trim();
        o.AuthMode = _rbSshKey.Checked ? SshAuthMode.PrivateKey : SshAuthMode.Password;
        o.PrivateKeyPath = string.IsNullOrWhiteSpace(_txtKeyPath.Text) ? null : _txtKeyPath.Text.Trim();
        o.UseSudo = _chkSudo.Checked;
        o.PreferCarpMaster = _chkPreferMaster.Checked;
        o.HaproxyConfigPath = string.IsNullOrWhiteSpace(_txtHaproxyPath.Text) ? "/usr/local/etc/haproxy.conf" : _txtHaproxyPath.Text.Trim();
        o.TimeoutSeconds = (int)_numSshTimeout.Value;

        if (_lstSections.SelectedItem is HaproxySectionDto sec) cfg.Selection.SectionKey = sec.Key;
        cfg.Selection.ExchangeHostname = _cmbHostname.Text.Trim().ToLowerInvariant();
        cfg.Selection.AdditionalRequiredNames = _txtAdditionalNames.Text
            .Split(new[] { ',', ';', ' ' }, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(n => n.ToLowerInvariant()).Distinct().ToList();

        cfg.Exchange.Servers = new List<ExchangeServerEntry>();
        foreach (DataGridViewRow row in _gridServers.Rows)
        {
            if (row.IsNewRow || row.Tag is ServerGroupHeader) continue;
            var fqdn = Cell(row, "Fqdn");
            var name = Cell(row, "Name");
            if (fqdn.Length == 0 && name.Length == 0) continue;
            var old = row.Tag as ExchangeServerEntry;
            var s = new ExchangeServerEntry
            {
                Fqdn = fqdn.Length > 0 ? fqdn : name,
                Enabled = row.Cells["Enabled"].Value is true || (old == null && row.Cells["Enabled"].Value == null)
            };
            s.Name = name.Length > 0 ? name : s.Fqdn.Split('.')[0];
            if (old != null && old.Fqdn.Equals(s.Fqdn, StringComparison.OrdinalIgnoreCase))
            {
                s.Version = old.Version; s.Dag = old.Dag; s.Site = old.Site;
                s.PowerShellUri = old.PowerShellUri; s.CurrentCertificate = old.CurrentCertificate; s.LastStatus = old.LastStatus;
                s.IsEdge = old.IsEdge; s.MissingInAd = old.MissingInAd;
            }
            cfg.Exchange.Servers.Add(s);
        }

        var e = cfg.Exchange;
        e.UseCurrentUser = _rbExCurrentUser.Checked;
        e.Username = string.IsNullOrWhiteSpace(_txtExUser.Text) ? null : _txtExUser.Text.Trim();
        e.Authentication = _cmbExAuth.SelectedItem as string ?? "Kerberos";
        e.ServiceIis = _chkIis.Checked;
        e.ServiceSmtp = _chkSmtp.Checked;
        e.ServiceImap = _chkImap.Checked;
        e.ServicePop = _chkPop.Checked;
        e.PrivateKeyExportable = _chkExportable.Checked;
        e.VerifyAfterDeploy = _chkVerify.Checked;
        e.IisResetOnMismatch = _chkIisReset.Checked;
        e.RemoveReplacedCertificate = _chkRemoveOld.Checked;
        e.AutoDiscoverBeforeRun = _chkAutoDiscover.Checked;

        cfg.Auto.Enabled = _chkAuto.Checked;
        cfg.Auto.Time = _dtpAutoTime.Value.ToString("HH:mm");
        cfg.Auto.DryRun = _chkAutoDryRun.Checked;

        cfg.Logging.Directory = string.IsNullOrWhiteSpace(_txtLogDir.Text) ? null : _txtLogDir.Text.Trim();
        cfg.Logging.RetainDays = (int)_numRetain.Value;
        cfg.Logging.Debug = _chkDebug.Checked;

        return new SaveConfigRequest
        {
            Config = cfg,
            SshPassword = NullIfEmpty(_txtSshPassword.Text),
            KeyPassphrase = NullIfEmpty(_txtKeyPassphrase.Text),
            ExchangePassword = NullIfEmpty(_txtExPassword.Text)
        };
    }

    private static string? NullIfEmpty(string s) => string.IsNullOrEmpty(s) ? null : s;

    private static string Cell(DataGridViewRow row, string column) => (row.Cells[column].Value?.ToString() ?? "").Trim();

    private bool HasUnsavedChanges()
    {
        if (!_connected) return false;
        var req = CollectRequest();
        return req.SshPassword != null || req.KeyPassphrase != null || req.ExchangePassword != null
               || JsonSerializer.Serialize(req.Config, ConfigStore.JsonOptions) != _boundJson;
    }

    /// <summary>Konfiguration an den Dienst senden (Aufrufer kümmert sich um Busy-Status).</summary>
    private async Task SaveCoreAsync(CancellationToken ct)
    {
        var dto = await _client.CallAsync<ConfigDto>(Commands.SaveConfig, CollectRequest(), ct)
                  ?? throw new ServiceCallException("Dienst lieferte keine Konfiguration zurück.");
        ApplyConfigDto(dto);
    }

    private async Task<bool> SaveConfigAsync(bool showMessage)
    {
        var ok = await RunBusyAsync("Speichere Konfiguration im Dienst", async ct => { await SaveCoreAsync(ct); return true; }, reloadAfter: false);
        if (ok)
        {
            _status.Text = $"Konfiguration im Dienst gespeichert ({DateTime.Now:HH:mm:ss}).";
            if (showMessage) Log.Info("Konfiguration gespeichert.");
        }
        return ok;
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

    private async Task<T?> RunBusyAsync<T>(string status, Func<CancellationToken, Task<T>> work, bool reloadAfter = true)
    {
        if (_busy)
        {
            _status.Text = "Bitte warten – es läuft bereits eine Aktion.";
            return default;
        }
        _busy = true;
        _cts = new CancellationTokenSource();
        SetBusyUi(true, status);
        try
        {
            return await work(_cts.Token);
        }
        catch (OperationCanceledException)
        {
            _status.Text = "Abgebrochen.";
            return default;
        }
        catch (Exception ex)
        {
            Log.Warn($"{status} fehlgeschlagen: {ex.Message}");
            _status.Text = "Fehler: " + ex.Message;
            if (ex is ServiceCallException || ex is IOException || ex is TimeoutException)
                MessageBox.Show(this, ex.Message, status, MessageBoxButtons.OK, MessageBoxIcon.Warning);
            else
                MessageBox.Show(this, ex.ToString(), status, MessageBoxButtons.OK, MessageBoxIcon.Error);
            return default;
        }
        finally
        {
            _cts.Dispose();
            _cts = null;
            _busy = false;
            SetBusyUi(false, null);
            if (reloadAfter) await ReloadConfigAsync();
        }
    }

    private void SetBusyUi(bool busy, string? status)
    {
        SetConnectedUi(_connected);
        _btnDryRun.Enabled = _btnRunNow.Enabled = !busy && _connected;
        _btnCancel.Enabled = busy;
        foreach (var b in new[] { _btnSvcInstall, _btnSvcUpdate, _btnSvcStart, _btnSvcStop, _btnSvcUninstall, _btnSvcAccess, _btnConnect })
            b.Enabled = !busy;
        _progress.Visible = busy;
        _progress.MarqueeAnimationSpeed = busy ? 30 : 0;
        if (status != null) _status.Text = status + " …";
    }

    private async Task CancelAsync()
    {
        try
        {
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            var resp = await _client.SendAsync(Commands.Cancel, null, cts.Token);
            _status.Text = "Abbruch angefordert …";
        }
        catch (Exception ex) { _status.Text = "Abbruch nicht möglich: " + ex.Message; }
    }

    // ───────────────────────── Fenster ─────────────────────────

    private void OnFormClosing(object? sender, FormClosingEventArgs e)
    {
        if (e.CloseReason == CloseReason.UserClosing && !_busy && HasUnsavedChanges())
        {
            var answer = MessageBox.Show(this, "Es gibt nicht gespeicherte Änderungen. Vor dem Beenden im Dienst speichern?",
                "Beenden", MessageBoxButtons.YesNoCancel, MessageBoxIcon.Question);
            if (answer == DialogResult.Cancel) { e.Cancel = true; return; }
            if (answer == DialogResult.Yes)
            {
                e.Cancel = true;
                BeginInvoke(new Action(async () =>
                {
                    if (await SaveConfigAsync(showMessage: false)) { _boundJson = ""; ForceClose(); }
                }));
                return;
            }
        }
        _gui.ServiceHost = _txtServiceHost.Text.Trim();
        _gui.ServiceAccount = _txtSvcAccount.Text.Trim();
        _gui.ExtraAccess = _txtSvcAccess.Text.Trim();
        _gui.Save();
        _statusTimer.Stop();
        _logTimer.Stop();
    }

    private void ForceClose()
    {
        _connected = false; // keine Rückfrage mehr
        Close();
    }
}

/// <summary>Persönliche GUI-Einstellungen (pro Benutzer, ohne Geheimnisse).</summary>
public sealed class GuiSettings
{
    public string? ServiceHost { get; set; }
    public string? ServiceAccount { get; set; }
    public string? ExtraAccess { get; set; }

    private static string FilePath => Path.Combine(Path.GetDirectoryName(AppPaths.GuiLogDirectory)!, "gui.json");

    public static GuiSettings Load()
    {
        try { return File.Exists(FilePath) ? JsonSerializer.Deserialize<GuiSettings>(File.ReadAllText(FilePath)) ?? new() : new(); }
        catch { return new(); }
    }

    public void Save()
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(FilePath)!);
            File.WriteAllText(FilePath, JsonSerializer.Serialize(this));
        }
        catch { /* nicht kritisch */ }
    }
}
