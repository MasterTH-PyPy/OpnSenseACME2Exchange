using OpnSenseACME2Exchange.Core.Config;
using OpnSenseACME2Exchange.Core.Engine;
using OpnSenseACME2Exchange.Core.Exchange;

namespace OpnSenseACME2Exchange.UI;

/// <summary>Serverliste und Ergebnisliste gruppiert nach DAG (Kopfzeile je Gruppe mit Haken für alle).</summary>
partial class MainForm
{
    private sealed class ServerGroupHeader(ServerGroup group)
    {
        public ServerGroup Group { get; } = group;
    }

    private static readonly Color HeaderBack = Color.FromArgb(225, 228, 233);
    private static readonly Color HeaderWarnBack = Color.FromArgb(255, 236, 200);
    private const int HeaderIndent = 18;

    private void WireServerGrid()
    {
        _gridServers.CellPainting += OnServerCellPainting;
        _gridServers.RowPostPaint += OnServerRowPostPaint;
        _gridServers.CellClick += OnServerCellClick;
        _gridServers.CurrentCellDirtyStateChanged += (_, _) =>
        {
            // Haken sofort übernehmen, damit die Kopfzeile mitzieht
            if (_gridServers.CurrentCell is DataGridViewCheckBoxCell && _gridServers.IsCurrentCellDirty)
                _gridServers.CommitEdit(DataGridViewDataErrorContexts.Commit);
        };
        _gridServers.CellValueChanged += (_, e) =>
        {
            if (_binding || e.RowIndex < 0 || _gridServers.Columns[e.ColumnIndex].Name != "Enabled") return;
            UpdateHeaderCheck(FindHeaderRow(e.RowIndex));
        };
        _gridServers.UserDeletingRow += (_, e) =>
        {
            if (e.Row?.Tag is ServerGroupHeader) e.Cancel = true; // Kopfzeilen nicht löschbar
        };
    }

    private void BindServersGrid()
    {
        _gridServers.Rows.Clear();
        foreach (var group in ServerGrouping.Group(_cfg.Exchange.Servers))
        {
            var h = _gridServers.Rows.Add(group.AllEnabled, group.Title, "", "", "", "", "", "", "", "");
            var hr = _gridServers.Rows[h];
            hr.Tag = new ServerGroupHeader(group);
            hr.ReadOnly = true;
            hr.Height = 26;
            hr.DefaultCellStyle.BackColor = hr.DefaultCellStyle.SelectionBackColor = HeaderColor(group);
            hr.DefaultCellStyle.SelectionForeColor = SystemColors.ControlText;

            foreach (var s in group.Servers)
            {
                var i = _gridServers.Rows.Add(s.Enabled, s.Name, s.Fqdn, s.Version ?? "", s.Dag ?? "", s.Site ?? "",
                    s.PowerShellUri ?? "", s.CurrentCertificate ?? "", s.UrlCheckSummary ?? "", s.LastStatus ?? "");
                var row = _gridServers.Rows[i];
                row.Tag = s;
                if (s.UrlCheckSummary != null && !s.UrlCheckSummary.StartsWith("OK", StringComparison.Ordinal))
                    row.Cells["Urls"].Style.BackColor = Color.FromArgb(255, 243, 205);
                row.Cells["Name"].Style.Padding = new Padding(HeaderIndent, 0, 0, 0);
                ColorStatusRow(row, s.LastStatus);
                if (s.MissingInAd) row.DefaultCellStyle.ForeColor = SystemColors.GrayText;
            }
        }
    }

    private static Color HeaderColor(ServerGroup g) =>
        g.Servers.Any(s => !string.IsNullOrEmpty(s.CurrentCertificate)) && !g.CertificatesConsistent ? HeaderWarnBack : HeaderBack;

    /// <summary>Kopfzeile: über alle Spalten (außer dem Haken) einheitlich hinterlegen, Text malt RowPostPaint.</summary>
    private void OnServerCellPainting(object? sender, DataGridViewCellPaintingEventArgs e)
    {
        if (e.RowIndex < 0 || e.ColumnIndex <= 0 || e.Graphics == null) return;
        if (_gridServers.Rows[e.RowIndex].Tag is not ServerGroupHeader h) return;
        using var b = new SolidBrush(HeaderColor(h.Group));
        e.Graphics.FillRectangle(b, e.CellBounds);
        using var p = new Pen(SystemColors.ControlDark);
        e.Graphics.DrawLine(p, e.CellBounds.Left, e.CellBounds.Bottom - 1, e.CellBounds.Right, e.CellBounds.Bottom - 1);
        e.Handled = true;
    }

    private void OnServerRowPostPaint(object? sender, DataGridViewRowPostPaintEventArgs e)
    {
        if (_gridServers.Rows[e.RowIndex].Tag is not ServerGroupHeader h) return;
        var left = e.RowBounds.Left + _gridServers.Columns[0].Width - _gridServers.HorizontalScrollingOffset + 4;
        var rect = new Rectangle(left, e.RowBounds.Top, Math.Max(0, e.RowBounds.Right - left - 4), e.RowBounds.Height);
        var titleSize = TextRenderer.MeasureText(e.Graphics, h.Group.Title, UiKit.BoldFont);
        TextRenderer.DrawText(e.Graphics, h.Group.Title, UiKit.BoldFont, rect, SystemColors.ControlText,
            TextFormatFlags.Left | TextFormatFlags.VerticalCenter | TextFormatFlags.SingleLine);
        var rest = new Rectangle(rect.Left + titleSize.Width + 6, rect.Top, Math.Max(0, rect.Width - titleSize.Width - 6), rect.Height);
        TextRenderer.DrawText(e.Graphics, "– " + LiveSummary(e.RowIndex, h.Group), _gridServers.Font, rest,
            h.Group.CertificatesConsistent ? SystemColors.ControlText : Color.FromArgb(150, 70, 0),
            TextFormatFlags.Left | TextFormatFlags.VerticalCenter | TextFormatFlags.SingleLine | TextFormatFlags.EndEllipsis);
    }

    /// <summary>Zusammenfassung mit den aktuell gesetzten Haken (noch nicht gespeichert).</summary>
    private string LiveSummary(int headerRow, ServerGroup g)
    {
        var members = MemberRows(headerRow).ToList();
        int on = members.Count(r => r.Cells["Enabled"].Value is true);
        var s = g.Summary;
        var idx = s.IndexOf(" aktiv", StringComparison.Ordinal);
        return idx > 0 ? $"{members.Count} Server, {on}{s[idx..]}" : s;
    }

    private void OnServerCellClick(object? sender, DataGridViewCellEventArgs e)
    {
        if (e.RowIndex < 0 || e.ColumnIndex < 0) return;
        if (_gridServers.Rows[e.RowIndex].Tag is not ServerGroupHeader) return;
        if (_gridServers.Columns[e.ColumnIndex].Name != "Enabled") return;

        var members = MemberRows(e.RowIndex).ToList();
        bool enable = !members.All(r => r.Cells["Enabled"].Value is true);
        _binding = true;
        try { foreach (var r in members) r.Cells["Enabled"].Value = enable; }
        finally { _binding = false; }
        UpdateHeaderCheck(e.RowIndex);
    }

    private void UpdateHeaderCheck(int headerRow)
    {
        if (headerRow < 0) return;
        var members = MemberRows(headerRow).ToList();
        _binding = true;
        try { _gridServers.Rows[headerRow].Cells["Enabled"].Value = members.Count > 0 && members.All(r => r.Cells["Enabled"].Value is true); }
        finally { _binding = false; }
        _gridServers.InvalidateRow(headerRow);
    }

    private int FindHeaderRow(int row)
    {
        for (int i = row; i >= 0; i--)
            if (_gridServers.Rows[i].Tag is ServerGroupHeader) return i;
        return -1;
    }

    private IEnumerable<DataGridViewRow> MemberRows(int headerRow)
    {
        for (int i = headerRow + 1; i < _gridServers.Rows.Count; i++)
        {
            var r = _gridServers.Rows[i];
            if (r.IsNewRow || r.Tag is ServerGroupHeader) yield break;
            yield return r;
        }
    }

    /// <summary>FQDNs der Auswahl – eine markierte Kopfzeile steht für alle Server ihrer Gruppe.</summary>
    private List<string> SelectedServerFqdns()
    {
        var set = new List<string>();
        foreach (DataGridViewRow r in _gridServers.SelectedRows)
        {
            if (r.IsNewRow) continue;
            var rows = r.Tag is ServerGroupHeader ? MemberRows(r.Index) : new[] { r };
            foreach (var m in rows)
            {
                var f = Cell(m, "Fqdn");
                if (f.Length > 0 && !set.Contains(f, StringComparer.OrdinalIgnoreCase)) set.Add(f);
            }
        }
        return set;
    }

    // ───────────────────────── Ergebnisliste ─────────────────────────

    private void ShowRunGrouped(RunResult r)
    {
        _gridResults.Rows.Clear();
        var known = _cfg.Exchange.Servers;
        ExchangeServerEntry? Entry(string server) =>
            known.FirstOrDefault(s => s.Name.Equals(server, StringComparison.OrdinalIgnoreCase) || s.Fqdn.Equals(server, StringComparison.OrdinalIgnoreCase));

        var order = ServerGrouping.Group(known).Select(g => g.Key).ToList();
        var groups = r.Servers
            .GroupBy(sr => Entry(sr.Server) is { } e ? ServerGrouping.KeyOf(e) : "~nodag")
            .OrderBy(g => order.IndexOf(g.Key) is var i && i >= 0 ? i : int.MaxValue)
            .ToList();

        foreach (var g in groups)
        {
            var sample = g.Select(sr => Entry(sr.Server)).FirstOrDefault(e => e != null);
            var title = g.Key == "~edge" ? "Edge-Transport" : g.Key == "~nodag" ? "Ohne DAG" : "DAG " + sample?.Dag;
            var counts = string.Join(", ", g.GroupBy(sr => sr.Outcome).OrderBy(x => x.Key)
                .Select(x => $"{x.Count()} {OutcomeText(x.Key)}"));
            var h = _gridResults.Rows.Add(title, "", "", $"{g.Count()} Server: {counts}");
            var hr = _gridResults.Rows[h];
            hr.DefaultCellStyle.BackColor = hr.DefaultCellStyle.SelectionBackColor = HeaderBack;
            hr.DefaultCellStyle.SelectionForeColor = SystemColors.ControlText;
            hr.DefaultCellStyle.Font = UiKit.BoldFont;

            foreach (var sr in g)
            {
                var i = _gridResults.Rows.Add(sr.Server, sr.Action, OutcomeText(sr.Outcome),
                    sr.Details + (sr.UrlFindings.Count > 0 ? "  [Doppelklick: URL-Befunde]" : ""));
                var row = _gridResults.Rows[i];
                row.Tag = sr;
                row.DefaultCellStyle.BackColor = UiKit.OutcomeColor(sr.Outcome);
                row.Cells["Server"].Style.Padding = new Padding(HeaderIndent, 0, 0, 0);
            }
        }
    }

    private static string OutcomeText(ServerOutcome o) => o switch
    {
        ServerOutcome.Ok => "OK",
        ServerOutcome.Skipped => "aktuell",
        ServerOutcome.DryRun => "simuliert",
        ServerOutcome.Warning => "WARNUNG",
        _ => "FEHLER"
    };
}
