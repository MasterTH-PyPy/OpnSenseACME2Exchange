using System.Text;
using OpnSenseACME2Exchange.Core.Exchange;
using static OpnSenseACME2Exchange.UI.UiKit;

namespace OpnSenseACME2Exchange.UI;

/// <summary>
/// Ergebnis der URL-Prüfung. Ändert nichts an Exchange: der Admin korrigiert selbst (Befehle zum Kopieren),
/// prüft erneut oder akzeptiert einen Host bewusst.
/// </summary>
public sealed class UrlCheckForm : Form
{
    private readonly Func<Task<UrlCheckReport?>>? _recheck;
    private readonly Func<string, Task<UrlCheckReport?>>? _acceptHost;
    private readonly DataGridView _grid;
    private readonly Label _lblHead;
    private readonly CheckBox _chkOnlyIssues;
    private readonly Button _btnRecheck, _btnAccept, _btnCopy, _btnCopyAll;
    private UrlCheckReport? _report;

    public UrlCheckForm(UrlCheckReport report, Func<Task<UrlCheckReport?>>? recheck, Func<string, Task<UrlCheckReport?>>? acceptHost)
    {
        _recheck = recheck;
        _acceptHost = acceptHost;

        Text = "URL-Prüfung – Exchange gegen Zertifikat";
        Icon = AppIcon();
        Font = new Font("Segoe UI", 9F);
        BackColor = SystemColors.Control;
        StartPosition = FormStartPosition.CenterParent;
        Size = new Size(1150, 640);
        MinimumSize = new Size(800, 400);

        _lblHead = Lbl("");
        _lblHead.Dock = DockStyle.Top;
        _lblHead.Padding = new Padding(6);
        _lblHead.MaximumSize = new Size(1400, 0);

        _grid = Grid();
        _grid.ReadOnly = true;
        _grid.AllowUserToAddRows = false;
        _grid.AllowUserToDeleteRows = false;
        _grid.MultiSelect = true;
        _grid.Columns.Add(Col("Server", "Server", 10));
        _grid.Columns.Add(Col("Component", "Komponente", 9));
        _grid.Columns.Add(Col("Scope", "Bereich", 6));
        _grid.Columns.Add(Col("Value", "Hinterlegt", 30));
        _grid.Columns.Add(Col("Result", "Ergebnis", 9));
        _grid.Columns.Add(Col("Message", "Hinweis", 36));
        _grid.SelectionChanged += (_, _) => UpdateButtons();
        _grid.CellDoubleClick += (_, _) => CopySelected();

        _chkOnlyIssues = Chk("nur Auffälligkeiten");
        _chkOnlyIssues.Checked = true;
        _chkOnlyIssues.CheckedChanged += (_, _) => Fill();
        _btnRecheck = Btn("Erneut prüfen", async (_, _) => await RecheckAsync());
        _btnAccept = Btn("Host bewusst akzeptieren", async (_, _) => await AcceptAsync());
        _btnCopy = Btn("Korrekturbefehl kopieren", (_, _) => CopySelected());
        _btnCopyAll = Btn("Alle Korrekturbefehle kopieren", (_, _) => CopyAll());
        var btnClose = Btn("Schließen", (_, _) => Close());
        _btnRecheck.Enabled = recheck != null;
        var bar = Flow(_chkOnlyIssues, _btnRecheck, _btnAccept, _btnCopy, _btnCopyAll, btnClose);
        bar.Dock = DockStyle.Bottom;
        bar.Padding = new Padding(6);

        var hint = Lbl("Es wird nichts an Exchange geändert. Befehle in der Exchange Management Shell selbst ausführen, danach 'Erneut prüfen'. " +
                       "Danach ggf. iisreset bzw. Autodiscover-Cache der Clients beachten.");
        hint.Dock = DockStyle.Bottom;
        hint.Padding = new Padding(6, 0, 6, 0);

        Controls.Add(_grid);
        Controls.Add(_lblHead);
        Controls.Add(hint);
        Controls.Add(bar);

        ShowReport(report);
    }

    private void ShowReport(UrlCheckReport report)
    {
        _report = report;
        var blocking = report.Servers.Sum(s => s.BlockingCount);
        var sb = new StringBuilder();
        sb.Append($"Geprüft gegen: {report.CertificateSource}\nNamen im Zertifikat: {string.Join(", ", report.CertificateNames)}\n");
        sb.Append(blocking == 0
            ? $"Ergebnis: alle {report.Servers.Count} Server passen zum Zertifikat."
            : $"Ergebnis: {blocking} Abweichung(en) auf {report.Servers.Count(s => s.BlockingCount > 0)} von {report.Servers.Count} Server(n).");
        foreach (var w in report.Warnings) sb.Append("\nHinweis: " + w);
        _lblHead.Text = sb.ToString();
        _lblHead.ForeColor = blocking == 0 ? Color.DarkGreen : Color.FromArgb(150, 70, 0);
        Fill();
    }

    private void Fill()
    {
        if (_report == null) return;
        _grid.Rows.Clear();
        foreach (var server in _report.Servers)
        {
            var h = _grid.Rows.Add($"{server.Server}", "", "", server.Fqdn ?? "", "", server.Summary + (server.Dag != null ? $"  (DAG {server.Dag})" : ""));
            var hr = _grid.Rows[h];
            hr.DefaultCellStyle.Font = BoldFont;
            hr.DefaultCellStyle.BackColor = hr.DefaultCellStyle.SelectionBackColor =
                server.Ok ? Color.FromArgb(225, 228, 233) : Color.FromArgb(255, 236, 200);
            hr.DefaultCellStyle.SelectionForeColor = SystemColors.ControlText;

            if (server.Error != null) continue;
            foreach (var f in server.Findings)
            {
                if (_chkOnlyIssues.Checked && f.Kind is UrlFindingKind.Ok or UrlFindingKind.NotSet) continue;
                var i = _grid.Rows.Add("", f.Component, f.Scope, f.Value ?? "(nicht gesetzt)", KindText(f.Kind),
                    f.Message + (f.SuggestedCommand != null ? "  → Befehl verfügbar" : ""));
                var row = _grid.Rows[i];
                row.Tag = f;
                row.DefaultCellStyle.BackColor = f.Kind switch
                {
                    UrlFindingKind.Ok => Color.FromArgb(220, 245, 220),
                    UrlFindingKind.Accepted => Color.FromArgb(230, 238, 250),
                    UrlFindingKind.NotSet => SystemColors.Window,
                    UrlFindingKind.DagMismatch => Color.FromArgb(255, 243, 205),
                    _ => Color.FromArgb(250, 215, 215)
                };
            }
        }
        UpdateButtons();
    }

    private static string KindText(UrlFindingKind k) => k switch
    {
        UrlFindingKind.Ok => "passt",
        UrlFindingKind.NotSet => "leer",
        UrlFindingKind.Accepted => "akzeptiert",
        UrlFindingKind.NotCovered => "NICHT IM ZERT.",
        UrlFindingKind.Invalid => "UNGÜLTIG",
        UrlFindingKind.DagMismatch => "DAG-Abweichung",
        _ => k.ToString()
    };

    private IEnumerable<UrlFinding> Selected() =>
        _grid.SelectedRows.Cast<DataGridViewRow>().Select(r => r.Tag).OfType<UrlFinding>();

    private void UpdateButtons()
    {
        var sel = Selected().ToList();
        _btnCopy.Enabled = sel.Any(f => f.SuggestedCommand != null);
        _btnAccept.Enabled = _acceptHost != null && sel.Count == 1 && sel[0].Host != null && sel[0].Kind == UrlFindingKind.NotCovered;
        _btnCopyAll.Enabled = _report?.Servers.SelectMany(s => s.Findings).Any(f => f.Blocking && f.SuggestedCommand != null) == true;
    }

    private void CopySelected()
    {
        var cmds = Selected().Select(f => f.SuggestedCommand).Where(c => c != null).ToList();
        if (cmds.Count == 0) return;
        Clipboard.SetText(string.Join(Environment.NewLine, cmds));
        Text = $"URL-Prüfung – {cmds.Count} Befehl(e) kopiert";
    }

    private void CopyAll()
    {
        if (_report == null) return;
        var sb = new StringBuilder();
        sb.AppendLine("# Vorschläge aus OpnSenseACME2Exchange – bitte prüfen und in der Exchange Management Shell selbst ausführen");
        foreach (var s in _report.Servers.Where(s => s.Findings.Any(f => f.Blocking && f.SuggestedCommand != null)))
        {
            sb.AppendLine($"# {s.Server}");
            foreach (var f in s.Findings.Where(f => f.Blocking && f.SuggestedCommand != null))
                sb.AppendLine(f.SuggestedCommand);
        }
        Clipboard.SetText(sb.ToString());
        Text = "URL-Prüfung – alle Befehle kopiert";
    }

    private async Task RecheckAsync()
    {
        if (_recheck == null) return;
        await Busy(async () => { var r = await _recheck(); if (r != null) ShowReport(r); });
    }

    private async Task AcceptAsync()
    {
        if (_acceptHost == null || Selected().FirstOrDefault() is not { Host: { } host }) return;
        var pattern = host;
        var dot = host.IndexOf('.');
        if (dot > 0)
        {
            var wildcard = "*" + host[dot..];
            var answer = MessageBox.Show(this,
                $"'{host}' bewusst als Ausnahme akzeptieren?\n\nJa = nur {host}\nNein = alle {wildcard}\nAbbrechen = nichts ändern\n\n" +
                "Akzeptierte Hosts gelten nicht mehr als Abweichung und blockieren den Tausch nicht.",
                "Host akzeptieren", MessageBoxButtons.YesNoCancel, MessageBoxIcon.Question);
            if (answer == DialogResult.Cancel) return;
            if (answer == DialogResult.No) pattern = wildcard;
        }
        await Busy(async () => { var r = await _acceptHost(pattern); if (r != null) ShowReport(r); });
    }

    private async Task Busy(Func<Task> work)
    {
        UseWaitCursor = true;
        foreach (var b in new[] { _btnRecheck, _btnAccept, _btnCopy, _btnCopyAll }) b.Enabled = false;
        try { await work(); }
        finally
        {
            UseWaitCursor = false;
            _btnRecheck.Enabled = _recheck != null;
            UpdateButtons();
        }
    }
}
