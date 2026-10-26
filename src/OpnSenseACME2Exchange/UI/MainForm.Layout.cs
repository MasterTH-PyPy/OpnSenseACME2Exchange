using static OpnSenseACME2Exchange.UI.UiKit;

namespace OpnSenseACME2Exchange.UI;

partial class MainForm
{
    // Grundgerüst
    private TabControl _tabs = null!;
    private TabPage _pageOpn = null!, _pageHaproxy = null!, _pageExchange = null!, _pageRun = null!, _pageLog = null!;
    private ToolStripStatusLabel _status = null!, _statusNext = null!;
    private ToolStripProgressBar _progress = null!;
    private NotifyIcon _tray = null!;
    private System.Windows.Forms.Timer _schedulerTimer = null!, _logTimer = null!;

    // OPNsense
    private DataGridView _gridNodes = null!;
    private TextBox _txtSshUser = null!, _txtSshPassword = null!, _txtKeyPath = null!, _txtKeyPassphrase = null!, _txtHaproxyPath = null!;
    private RadioButton _rbSshPassword = null!, _rbSshKey = null!;
    private CheckBox _chkSudo = null!, _chkPreferMaster = null!;
    private NumericUpDown _numSshTimeout = null!;
    private Button _btnTestNodes = null!, _btnResetHostKey = null!;

    // HAProxy / Zertifikat
    private Button _btnReadHaproxy = null!, _btnResolveCert = null!;
    private Label _lblHaproxySource = null!;
    private CheckBox _chkAllSections = null!;
    private ListBox _lstSections = null!;
    private TextBox _txtSection = null!, _txtAdditionalNames = null!, _txtCertInfo = null!;
    private ComboBox _cmbHostname = null!;
    private ListView _lvCandidates = null!;

    // Exchange
    private DataGridView _gridServers = null!;
    private Button _btnDiscover = null!, _btnTestServers = null!;
    private RadioButton _rbExCurrentUser = null!, _rbExOtherUser = null!;
    private TextBox _txtExUser = null!, _txtExPassword = null!;
    private ComboBox _cmbExAuth = null!;
    private CheckBox _chkIis = null!, _chkSmtp = null!, _chkImap = null!, _chkPop = null!;
    private CheckBox _chkExportable = null!, _chkVerify = null!, _chkIisReset = null!, _chkRemoveOld = null!;

    // Ausführung
    private Button _btnDryRun = null!, _btnRunNow = null!, _btnCancel = null!;
    private CheckBox _chkAuto = null!, _chkAutoDryRun = null!;
    private DateTimePicker _dtpAutoTime = null!;
    private Label _lblNextRun = null!, _lblLastRun = null!, _lblRunCert = null!;
    private DataGridView _gridResults = null!;

    // Log
    private ListBox _lstLogFiles = null!;
    private TextBox _txtLog = null!, _txtLogDir = null!;
    private NumericUpDown _numRetain = null!;
    private CheckBox _chkDebug = null!, _chkAutoScroll = null!;

    private Button _btnSave = null!;
    private SplitContainer _splitHaproxy = null!, _splitLog = null!;

    private void BuildUi()
    {
        Text = $"OpnSenseACME2Exchange {Program.Version}";
        Icon = AppIcon();
        Font = new Font("Segoe UI", 9F);
        BackColor = SystemColors.Control;
        StartPosition = FormStartPosition.CenterScreen;
        Size = new Size(1180, 800);
        MinimumSize = new Size(1000, 680);

        _tabs = new TabControl { Dock = DockStyle.Fill, Padding = new Point(12, 4) };
        _pageOpn = new TabPage("OPNsense") { Padding = new Padding(8), UseVisualStyleBackColor = true };
        _pageHaproxy = new TabPage("HAProxy / Zertifikat") { Padding = new Padding(8), UseVisualStyleBackColor = true };
        _pageExchange = new TabPage("Exchange") { Padding = new Padding(8), UseVisualStyleBackColor = true };
        _pageRun = new TabPage("Ausführung") { Padding = new Padding(8), UseVisualStyleBackColor = true };
        _pageLog = new TabPage("Log") { Padding = new Padding(8), UseVisualStyleBackColor = true };
        _tabs.TabPages.AddRange(new[] { _pageOpn, _pageHaproxy, _pageExchange, _pageRun, _pageLog });

        BuildOpnSensePage();
        BuildHaproxyPage();
        BuildExchangePage();
        BuildRunPage();
        BuildLogPage();

        // Fußzeile
        _btnSave = Btn("Konfiguration speichern", (_, _) => SaveConfig(showMessage: true));
        var footer = new FlowLayoutPanel
        {
            Dock = DockStyle.Bottom,
            FlowDirection = FlowDirection.RightToLeft,
            AutoSize = true,
            Padding = new Padding(6, 4, 6, 4)
        };
        footer.Controls.Add(_btnSave);

        var strip = new StatusStrip { SizingGrip = true };
        _status = new ToolStripStatusLabel("Bereit") { Spring = true, TextAlign = ContentAlignment.MiddleLeft };
        _statusNext = new ToolStripStatusLabel("Auto-Modus aus");
        _progress = new ToolStripProgressBar { Style = ProgressBarStyle.Marquee, MarqueeAnimationSpeed = 0, Visible = false, Width = 140 };
        strip.Items.AddRange(new ToolStripItem[] { _status, _progress, _statusNext });

        Controls.Add(_tabs);
        Controls.Add(footer);
        Controls.Add(strip);

        // Infobereich
        var menu = new ContextMenuStrip();
        menu.Items.Add("Öffnen", null, (_, _) => RestoreFromTray());
        menu.Items.Add("Jetzt prüfen (Dry-Run)", null, async (_, _) => { RestoreFromTray(); await StartRunAsync(dryRun: true, unattended: false); });
        menu.Items.Add(new ToolStripSeparator());
        menu.Items.Add("Beenden", null, (_, _) => { _exitRequested = true; Close(); });
        _tray = new NotifyIcon { Icon = Icon, Text = "OpnSenseACME2Exchange", ContextMenuStrip = menu, Visible = true };
        _tray.DoubleClick += (_, _) => RestoreFromTray();

        _schedulerTimer = new System.Windows.Forms.Timer { Interval = 30_000 };
        _schedulerTimer.Tick += async (_, _) => await SchedulerTickAsync();
        _logTimer = new System.Windows.Forms.Timer { Interval = 1500 };
        _logTimer.Tick += (_, _) => PollLog();
    }

    private void BuildOpnSensePage()
    {
        _gridNodes = Grid();
        _gridNodes.AllowUserToAddRows = true;
        _gridNodes.AllowUserToDeleteRows = true;
        _gridNodes.Columns.Add(Col("Name", "Name", 18));
        _gridNodes.Columns.Add(Col("Host", "Host / IP", 22));
        _gridNodes.Columns.Add(Col("Port", "Port", 7));
        _gridNodes.Columns.Add(Col("HostKey", "SSH-Hostkey (SHA256)", 30, readOnly: true));
        _gridNodes.Columns.Add(Col("Status", "Status", 40, readOnly: true));

        _btnTestNodes = Btn("Verbindung testen", async (_, _) => await TestNodesAsync());
        _btnResetHostKey = Btn("Hostkey der Auswahl zurücksetzen", (_, _) => ResetHostKeys());
        var nodePanel = new TableLayoutPanel { ColumnCount = 1, RowCount = 2 };
        nodePanel.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        nodePanel.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        nodePanel.Controls.Add(_gridNodes, 0, 0);
        nodePanel.Controls.Add(Flow(_btnTestNodes, _btnResetHostKey,
            Lbl("Beide Cluster-Knoten eintragen – der CARP-Master wird automatisch bevorzugt, fällt er aus, übernimmt der andere.")), 0, 1);
        var grpNodes = Grp("Firewall-Cluster (OPNsense-Knoten)", nodePanel, DockStyle.Fill);

        _txtSshUser = Txt(200);
        _rbSshPassword = new RadioButton { Text = "Passwort", AutoSize = true, Checked = true };
        _rbSshKey = new RadioButton { Text = "Private Key", AutoSize = true };
        _rbSshPassword.CheckedChanged += (_, _) => UpdateSshAuthUi();
        _txtSshPassword = Txt(200, password: true);
        _txtKeyPath = Txt(380);
        var btnKey = Btn("…", (_, _) =>
        {
            using var dlg = new OpenFileDialog { Title = "SSH-Private-Key wählen", Filter = "Alle Dateien|*.*" };
            if (dlg.ShowDialog(this) == DialogResult.OK) _txtKeyPath.Text = dlg.FileName;
        });
        _txtKeyPassphrase = Txt(200, password: true);
        _chkSudo = Chk("Befehle mit sudo ausführen (wenn nicht root)");
        _chkPreferMaster = Chk("CARP-Master bevorzugen");
        _txtHaproxyPath = Txt(380);
        _numSshTimeout = new NumericUpDown { Minimum = 5, Maximum = 300, Width = 70 };

        var auth = Rows(
            ("Benutzer:", _txtSshUser),
            ("Anmeldung:", Flow(_rbSshPassword, _rbSshKey)),
            ("Passwort:", _txtSshPassword),
            ("Key-Datei:", Flow(_txtKeyPath, btnKey)),
            ("Key-Passphrase:", _txtKeyPassphrase),
            ("", Flow(_chkSudo, _chkPreferMaster)),
            ("HAProxy-Konfiguration:", _txtHaproxyPath),
            ("Timeout (s):", _numSshTimeout));
        var grpAuth = Grp("SSH-Anmeldung", auth);

        _pageOpn.Controls.Add(grpNodes);
        _pageOpn.Controls.Add(grpAuth);
    }

    private void BuildHaproxyPage()
    {
        _btnReadHaproxy = Btn("HAProxy-Konfiguration einlesen", async (_, _) => await ReadHaproxyAsync());
        _lblHaproxySource = Lbl("Noch nicht eingelesen.");
        _chkAllSections = Chk("alle Abschnitte anzeigen");
        _chkAllSections.CheckedChanged += (_, _) => FillSectionList();
        var top = Flow(_btnReadHaproxy, _chkAllSections, _lblHaproxySource);
        top.Dock = DockStyle.Top;

        _lstSections = new ListBox { Dock = DockStyle.Fill, IntegralHeight = false };
        _lstSections.SelectedIndexChanged += (_, _) => OnSectionSelected();
        _txtSection = new TextBox
        {
            Dock = DockStyle.Fill, Multiline = true, ReadOnly = true, ScrollBars = ScrollBars.Both,
            WordWrap = false, Font = MonoFont, BackColor = SystemColors.Window
        };
        var split = _splitHaproxy = new SplitContainer { Dock = DockStyle.Fill, FixedPanel = FixedPanel.Panel1 };
        split.Panel1.Controls.Add(Grp("Abschnitte (Frontends)", _lstSections, DockStyle.Fill));
        split.Panel2.Controls.Add(Grp("Konfiguration des Abschnitts", _txtSection, DockStyle.Fill));

        _cmbHostname = new ComboBox { Width = 300, DropDownStyle = ComboBoxStyle.DropDown };
        _txtAdditionalNames = Txt(420);
        _btnResolveCert = Btn("Zertifikat ermitteln", async (_, _) => await ResolveCertificateAsync());

        _lvCandidates = new ListView
        {
            View = View.Details, FullRowSelect = true, GridLines = true, Height = 120, Dock = DockStyle.Top, HideSelection = false
        };
        _lvCandidates.Columns.Add("Datei auf der OPNsense", 300);
        _lvCandidates.Columns.Add("Zertifikat / Namen", 380);
        _lvCandidates.Columns.Add("gültig bis", 120);
        _lvCandidates.Columns.Add("passt", 60);
        _lvCandidates.Columns.Add("Hinweis", 200);

        _txtCertInfo = new TextBox
        {
            Dock = DockStyle.Top, Multiline = true, ReadOnly = true, Height = 110, Font = MonoFont,
            ScrollBars = ScrollBars.Vertical, BackColor = SystemColors.Window
        };

        var form = Rows(
            ("Exchange-Hostname (extern):", _cmbHostname),
            ("Weitere Pflichtnamen:", Flow(_txtAdditionalNames, Lbl("(kommagetrennt, z.B. autodiscover.domain.de)"))),
            ("", _btnResolveCert));
        var certPanel = new Panel { Dock = DockStyle.Bottom, Height = 330 };
        var inner = new Panel { Dock = DockStyle.Fill };
        inner.Controls.Add(_txtCertInfo);
        inner.Controls.Add(_lvCandidates);
        form.Dock = DockStyle.Top;
        inner.Controls.Add(form);
        // Reihenfolge der Dock=Top-Controls: zuletzt hinzugefügt liegt oben
        certPanel.Controls.Add(Grp("Zertifikat für Exchange", inner, DockStyle.Fill));

        _pageHaproxy.Controls.Add(split);
        _pageHaproxy.Controls.Add(certPanel);
        _pageHaproxy.Controls.Add(top);
    }

    private void BuildExchangePage()
    {
        _gridServers = Grid();
        _gridServers.AllowUserToAddRows = true;
        _gridServers.AllowUserToDeleteRows = true;
        _gridServers.Columns.Add(new DataGridViewCheckBoxColumn { Name = "Enabled", HeaderText = "Aktiv", FillWeight = 6 });
        _gridServers.Columns.Add(Col("Name", "Name", 12));
        _gridServers.Columns.Add(Col("Fqdn", "FQDN", 22));
        _gridServers.Columns.Add(Col("Version", "Version", 14, readOnly: true));
        _gridServers.Columns.Add(Col("Dag", "DAG", 9, readOnly: true));
        _gridServers.Columns.Add(Col("Site", "Site", 10, readOnly: true));
        _gridServers.Columns.Add(Col("Uri", "Remote-PowerShell", 18, readOnly: true));
        _gridServers.Columns.Add(Col("Cert", "Aktuelles IIS-Zertifikat", 24, readOnly: true));
        _gridServers.Columns.Add(Col("Status", "Status", 30, readOnly: true));

        _btnDiscover = Btn("Exchange-Server aus AD ermitteln", async (_, _) => await DiscoverServersAsync());
        _btnTestServers = Btn("Verbindung testen (Auswahl / alle)", async (_, _) => await TestServersAsync());
        var gridPanel = new TableLayoutPanel { ColumnCount = 1, RowCount = 2 };
        gridPanel.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        gridPanel.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        gridPanel.Controls.Add(Flow(_btnDiscover, _btnTestServers), 0, 0);
        gridPanel.Controls.Add(_gridServers, 0, 1);
        var grpServers = Grp("Exchange-Server im Cluster", gridPanel, DockStyle.Fill);

        _rbExCurrentUser = new RadioButton { Text = "Angemeldeter Benutzer (Kerberos/SSO)", AutoSize = true, Checked = true };
        _rbExOtherUser = new RadioButton { Text = "Anderes Konto:", AutoSize = true };
        _rbExCurrentUser.CheckedChanged += (_, _) => UpdateExchangeAuthUi();
        _txtExUser = Txt(220);
        _txtExUser.PlaceholderText = "DOMÄNE\\benutzer";
        _txtExPassword = Txt(200, password: true);
        _cmbExAuth = new ComboBox { DropDownStyle = ComboBoxStyle.DropDownList, Width = 120 };
        _cmbExAuth.Items.AddRange(new object[] { "Kerberos", "Negotiate", "Default" });

        var auth = Rows(
            ("Konto:", Flow(_rbExCurrentUser, _rbExOtherUser)),
            ("Benutzer:", _txtExUser),
            ("Passwort:", _txtExPassword),
            ("Authentifizierung:", _cmbExAuth));

        _chkIis = Chk("IIS");
        _chkSmtp = Chk("SMTP");
        _chkImap = Chk("IMAP");
        _chkPop = Chk("POP");
        _chkExportable = Chk("Private Key auf Exchange exportierbar");
        _chkVerify = Chk("Nach dem Tausch per TLS prüfen, was IIS ausliefert (inkl. Selbstheilung)");
        _chkIisReset = Chk("Bei Abweichung iisreset /noforce ausführen");
        _chkRemoveOld = Chk("Ersetztes altes Zertifikat entfernen (nur eindeutige Vorgänger)");
        var opts = Rows(
            ("Dienste:", Flow(_chkIis, _chkSmtp, _chkImap, _chkPop)),
            ("", _chkExportable),
            ("", _chkVerify),
            ("", _chkIisReset),
            ("", _chkRemoveOld));

        var bottom = new TableLayoutPanel { ColumnCount = 2, Dock = DockStyle.Bottom, AutoSize = true };
        bottom.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 45));
        bottom.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 55));
        var gA = Grp("Anmeldung an Exchange", auth);
        var gO = Grp("Optionen", opts);
        bottom.Controls.Add(gA, 0, 0);
        bottom.Controls.Add(gO, 1, 0);

        _pageExchange.Controls.Add(grpServers);
        _pageExchange.Controls.Add(bottom);
    }

    private void BuildRunPage()
    {
        _btnDryRun = Btn("Prüfen (Dry-Run)", async (_, _) => await StartRunAsync(dryRun: true, unattended: false), 170);
        _btnRunNow = Btn("Jetzt austauschen", async (_, _) => await StartRunAsync(dryRun: false, unattended: false), 170);
        _btnCancel = Btn("Abbrechen", (_, _) => _cts?.Cancel(), 110);
        _btnCancel.Enabled = false;
        _btnRunNow.Font = BoldFont;

        _chkAuto = Chk("Auto-Modus: einmal täglich um");
        _dtpAutoTime = new DateTimePicker { Format = DateTimePickerFormat.Custom, CustomFormat = "HH:mm", ShowUpDown = true, Width = 70 };
        _chkAutoDryRun = Chk("nur Dry-Run");
        _chkAuto.CheckedChanged += (_, _) => OnAutoSettingsChanged();
        _dtpAutoTime.ValueChanged += (_, _) => OnAutoSettingsChanged();
        _chkAutoDryRun.CheckedChanged += (_, _) => OnAutoSettingsChanged();
        _lblNextRun = Lbl("");
        _lblLastRun = Lbl("");
        var cliHint = Lbl("Alternativ über die Windows-Aufgabenplanung: OpnSenseACME2Exchange.exe --run   (bzw. --run --dry-run)");
        var btnCopy = Btn("Befehl kopieren", (_, _) =>
        {
            Clipboard.SetText($"\"{Path.Combine(AppContext.BaseDirectory, "OpnSenseACME2Exchange.exe")}\" --run");
            _status.Text = "Befehl in die Zwischenablage kopiert.";
        });

        var auto = Rows(
            ("", Flow(_chkAuto, _dtpAutoTime, _chkAutoDryRun)),
            ("Nächster Lauf:", _lblNextRun),
            ("Letzter Auto-Lauf:", _lblLastRun),
            ("", Flow(cliHint, btnCopy)),
            ("", Lbl("Der Auto-Modus läuft, solange das Programm geöffnet ist (minimiert im Infobereich).")));

        var actions = Flow(_btnDryRun, _btnRunNow, _btnCancel);
        var grpAction = Grp("Manuell", actions);
        var grpAuto = Grp("Automatik", auto);

        _lblRunCert = Lbl("");
        _lblRunCert.Dock = DockStyle.Top;
        _lblRunCert.Padding = new Padding(2, 4, 2, 4);
        _gridResults = Grid();
        _gridResults.ReadOnly = true;
        _gridResults.AllowUserToAddRows = false;
        _gridResults.Columns.Add(Col("Server", "Server", 14));
        _gridResults.Columns.Add(Col("Action", "Aktion", 18));
        _gridResults.Columns.Add(Col("Outcome", "Ergebnis", 10));
        _gridResults.Columns.Add(Col("Details", "Details", 58));
        _gridResults.DefaultCellStyle.WrapMode = DataGridViewTriState.True;
        _gridResults.AutoSizeRowsMode = DataGridViewAutoSizeRowsMode.AllCells;
        var resPanel = new Panel { Dock = DockStyle.Fill };
        resPanel.Controls.Add(_gridResults);
        resPanel.Controls.Add(_lblRunCert);
        var grpRes = Grp("Ergebnis des letzten Laufs", resPanel, DockStyle.Fill);

        _pageRun.Controls.Add(grpRes);
        _pageRun.Controls.Add(grpAuto);
        _pageRun.Controls.Add(grpAction);
    }

    private void BuildLogPage()
    {
        _lstLogFiles = new ListBox { Dock = DockStyle.Fill, IntegralHeight = false };
        _lstLogFiles.SelectedIndexChanged += (_, _) => LoadSelectedLog();
        var btnRefresh = Btn("Aktualisieren", (_, _) => RefreshLogFiles());
        var btnOpen = Btn("Ordner öffnen", (_, _) =>
        {
            Directory.CreateDirectory(Core.Logging.Log.Directory);
            System.Diagnostics.Process.Start("explorer.exe", Core.Logging.Log.Directory);
        });
        var left = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 2 };
        left.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        left.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        left.Controls.Add(_lstLogFiles, 0, 0);
        left.Controls.Add(Flow(btnRefresh, btnOpen), 0, 1);

        _txtLog = new TextBox
        {
            Dock = DockStyle.Fill, Multiline = true, ReadOnly = true, ScrollBars = ScrollBars.Both,
            WordWrap = false, Font = MonoFont, BackColor = SystemColors.Window
        };
        _chkAutoScroll = Chk("Automatisch ans Ende scrollen");
        _chkAutoScroll.Checked = true;
        _chkAutoScroll.Dock = DockStyle.Bottom;
        var right = new Panel { Dock = DockStyle.Fill };
        right.Controls.Add(_txtLog);
        right.Controls.Add(_chkAutoScroll);

        var split = _splitLog = new SplitContainer { Dock = DockStyle.Fill, FixedPanel = FixedPanel.Panel1 };
        split.Panel1.Controls.Add(Grp("Logdateien", left, DockStyle.Fill));
        split.Panel2.Controls.Add(Grp("Inhalt (live)", right, DockStyle.Fill));

        _txtLogDir = Txt(380);
        _txtLogDir.PlaceholderText = "leer = Ordner \"Logs\" neben der EXE";
        var btnDir = Btn("…", (_, _) =>
        {
            using var dlg = new FolderBrowserDialog { Description = "Log-Verzeichnis wählen" };
            if (dlg.ShowDialog(this) == DialogResult.OK) _txtLogDir.Text = dlg.SelectedPath;
        });
        _numRetain = new NumericUpDown { Minimum = 1, Maximum = 3650, Width = 70 };
        _chkDebug = Chk("Debug-Ausgaben");
        var settings = Rows(
            ("Log-Verzeichnis:", Flow(_txtLogDir, btnDir)),
            ("Aufbewahrung (Tage):", Flow(_numRetain, _chkDebug)));

        _pageLog.Controls.Add(split);
        _pageLog.Controls.Add(Grp("Einstellungen", settings, DockStyle.Bottom));
    }
}
